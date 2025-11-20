#!/usr/bin/env python3
"""
Distributed password cracking server (per-length assignment).
Sends start_idx/end_idx offsets within a fixed password LENGTH.
Requires Python 3.8+.
"""
import argparse
import socket
import threading
import json
import time
import sys
import signal

# Config alphabet -- must match cracker.py CHAR
# (server doesn't need to import cracker; it only needs base size)
LEGAL = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#%^&*()_+-=.,:;?"
BASE = len(LEGAL)

ATOMIC_START = 0
atomic_lock = threading.Lock()
# atomic_counter is an offset within the current length's space
atomic_counter = ATOMIC_START

found_event = threading.Event()

def debug(msg):
    print(f"[SDEBUG] {msg}", flush=True)

class NodeConn:
    def __init__(self, conn, addr, node_id, server):
        self.conn = conn
        self.addr = addr
        self.id = node_id
        self.server = server
        self.alive = True
        self.last_seen = time.time()
        threading.Thread(target=self.reader, daemon=True).start()

    def send(self, msg: dict):
        try:
            data = json.dumps(msg).encode() + b"\n"
            self.conn.sendall(data)
        except Exception as e:
            debug(f"Node#{self.id} send err: {e}")
            self.alive = False

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass
        self.alive = False

    def reader(self):
        buf = b""
        while self.alive and not found_event.is_set():
            try:
                data = self.conn.recv(4096)
                if not data:
                    break
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if not line.strip():
                        continue
                    try:
                        msg = json.loads(line.decode())
                    except Exception as e:
                        debug(f"Node#{self.id} bad json: {e}")
                        continue
                    # update last seen
                    self.last_seen = time.time()
                    self.server.handle_msg(self, msg)
            except Exception as e:
                debug(f"Node#{self.id} reader err: {e}")
                break

        self.alive = False
        self.server.remove_node(self)

class Server:
    def __init__(self, users, args):
        self.users = users
        self.args = args
        self.hash = args.hash

        self.nodes = []
        # assigned: node_id -> dict with start,end,length,assigned_time
        self.assigned = {}

        self.lock = threading.Lock()
        self.node_counter = 0

        # per-length state
        self.length = 1
        self.base = BASE
        self.total_for_length = pow(self.base, self.length)
        self.atomic_counter = 0  # offset within current length

        # monitor thread
        self.monitor_thread = threading.Thread(target=self.monitor_nodes, daemon=True)
        self.monitor_thread.start()

    def _alloc_block(self, work_size):
        """Return (start, end, length) offsets within current length.
        Advance to next length when current space exhausted."""
        with self.lock:
            # if current counter already exhausted, move to next length
            while self.atomic_counter >= self.total_for_length:
                self.length += 1
                self.total_for_length = pow(self.base, self.length)
                debug(f"All blocks for length {self.length-1} exhausted. Advancing to length={self.length}")

            start = self.atomic_counter
            end = min(start + work_size - 1, self.total_for_length - 1)
            self.atomic_counter = end + 1

            # if we've exhausted the space exactly after this block, the next allocation
            # will bump length automatically in subsequent calls.
            return start, end, self.length

    def handle_msg(self, node, msg):
        t = msg.get("type")
        node.last_seen = time.time()

        if t == "register":
            debug(f"[+] Node#{node.id} registered (threads={msg.get('threads')})")
            return

        if t == "request_work":
            if found_event.is_set():
                node.send({"type": "stop"})
                return

            start, end, length = self._alloc_block(self.args.work_size)
            assigned_time = time.time()

            with self.lock:
                self.assigned[node.id] = {
                    "start": start,
                    "end": end,
                    "length": length,
                    "assigned_time": assigned_time,
                }

            node.send({
                "type": "work",
                "start_idx": start,
                "end_idx": end,
                "length": length,
                "hash": self.hash,
                "checkpoint": self.args.checkpoint,
                "timeout": self.args.timeout,
                "assigned_time": assigned_time,
                "username": self.users[0][0] if self.users else None
            })
            debug(f"[+] Assigned Node#{node.id} len={length} work {start}–{end}")
            return

        if t == "progress" or t == "heartbeat":
            # optional: log or update metrics
            if t == "progress":
                debug(f"[ ] Progress Node#{node.id}: {msg.get('current')}")
            return

        if t == "result":
            # remove assignment
            with self.lock:
                if node.id in self.assigned:
                    self.assigned.pop(node.id, None)

            if msg.get("found"):
                debug(f"\n[+] Node#{node.id} cracked it! Password = {msg.get('password')}\n")
                found_event.set()
                self.broadcast_stop()
            else:
                debug(f"[ ] Node#{node.id} reported not found for assigned block")
            return

        debug(f"[?] Node#{node.id} unknown msg: {t}")

    def broadcast_stop(self):
        with self.lock:
            for n in list(self.nodes):
                if n.alive:
                    try:
                        n.send({"type": "stop"})
                    except Exception:
                        pass

    def remove_node(self, node):
        with self.lock:
            debug(f"[-] Node#{node.id} disconnected")
            if node.id in self.assigned:
                debug(f"    Reclaiming block assigned to Node#{node.id} (dropping; counter advanced)")
                del self.assigned[node.id]
            self.nodes = [n for n in self.nodes if n is not node]
            try:
                node.close()
            except Exception:
                pass

    def monitor_nodes(self):
        while not found_event.is_set():
            now = time.time()
            to_remove = []
            with self.lock:
                for n in list(self.nodes):
                    if not n.alive:
                        to_remove.append(n)
                        continue
                    if self.args.timeout and (now - n.last_seen) > self.args.timeout:
                        debug(f"[!] Node#{n.id} timed out (last seen {now - n.last_seen:.1f}s ago)")
                        to_remove.append(n)
            for n in to_remove:
                try:
                    n.send({"type": "stop"})
                except Exception:
                    pass
                self.remove_node(n)
            time.sleep(1)

    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", self.args.port))
        sock.listen(50)

        debug(f"[*] Listening on port {self.args.port}")

        try:
            while not found_event.is_set():
                try:
                    conn, addr = sock.accept()
                    with self.lock:
                        n = NodeConn(conn, addr, self.node_counter, self)
                        self.nodes.append(n)
                        self.node_counter += 1
                    debug(f"[+] Connection from {addr[0]}:{addr[1]}")
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    debug(f"[!] accept error: {e}")
        finally:
            sock.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--hash", required=True, help="Password hash to crack")
    parser.add_argument("--work-size", type=int, default=1000, help="number of offsets per worker block")
    parser.add_argument("--checkpoint", type=int, default=500)
    parser.add_argument("--timeout", type=int, default=600)

    args = parser.parse_args()

    users = [("target", args.hash)]

    global server
    server = Server(users, args)
    server.start()


if __name__ == "__main__":
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
    main()

