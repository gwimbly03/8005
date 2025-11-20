import argparse
import socket
import threading
import json
import time
import sys
import signal

# === SHARED BRUTE-FORCE SPACE (MUST BE IDENTICAL IN NODE) ===
CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#%^&*()_+-=.,:;?"
BASE = len(CHARS)  # 77
# ===========================================================

atomic_lock = threading.Lock()
atomic_counter = 0
found_event = threading.Event()

class Node:
    def __init__(self, conn, addr, node_id, server):
        self.conn = conn
        self.addr = addr
        self.id = node_id
        self.server = server
        self.alive = True
        self.last_seen = time.time()
        self.has_work = False  # Fair distribution: only one block at a time

        threading.Thread(target=self.reader, daemon=True).start()
        threading.Thread(target=self.timeout_watcher, daemon=True).start()

    def send(self, msg: dict):
        try:
            data = json.dumps(msg).encode() + b"\n"
            self.conn.sendall(data)
        except:
            self.alive = False

    def update_activity(self):
        self.last_seen = time.time()

    def timeout_watcher(self):
        while self.alive and not found_event.is_set():
            if time.time() - self.last_seen > self.server.args.timeout:
                print(f"[-] Node#{self.id} ({self.addr[0]}) TIMED OUT (no checkpoint in {self.server.args.timeout}s)")
                self.alive = False
                self.server.remove_node(self)
                try: self.conn.close()
                except: pass
                break
            time.sleep(5)

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
                    msg = json.loads(line)
                    self.update_activity()
                    self.server.handle_msg(self, msg)
            except:
                break
        self.alive = False
        self.server.remove_node(self)


class Server:
    def __init__(self, args):
        self.args = args
        self.hash = args.hash
        self.nodes = []
        self.lock = threading.Lock()
        self.node_counter = 0

    def handle_msg(self, node, msg):
        t = msg.get("type")

        if t == "register":
            print(f"[+] Node#{node.id} connected from {node.addr[0]}:{node.addr[1]}")
            return

        if t == "request_work":
            node.update_activity()
            node.has_work = False  # Finished previous block

            if found_event.is_set():
                node.send({"type": "stop"})
                return

            start = self.next_index()
            end = start + self.args.work_size
            node.has_work = True

            node.send({
                "type": "work",
                "start_idx": start,
                "end_idx": end,
                "hash": self.hash,
                "checkpoint_every": self.args.checkpoint
            })
            print(f"[→] Node#{node.id} → {start:,}–{end-1:,} ({self.args.work_size:,} passwords)")
            return

        if t == "checkpoint":
            reached = msg.get("last_checked", "?")
            print(f"[✓] Node#{node.id} checkpoint @ {reached:,}")
            return

        if t == "result":
            node.has_work = False
            if msg.get("found"):
                pw = msg.get("password", "UNKNOWN")
                print(f"\n{'='*70}")
                print(f"[!!!] PASSWORD CRACKED BY Node#{node.id}!")
                print(f"[!!!] Password: {pw}")
                print(f"{'='*70}\n")
                found_event.set()
                self.broadcast_stop()
            return

    def next_index(self):
        global atomic_counter
        with atomic_lock:
            v = atomic_counter
            atomic_counter += self.args.work_size  # ← Correct chunking
            return v

    def broadcast_stop(self):
        for n in list(self.nodes):
            if n.alive:
                n.send({"type": "stop"})

    def remove_node(self, node):
        with self.lock:
            if node in self.nodes:
                self.nodes.remove(node)
            node.has_work = False
            print(f"[-] Node#{node.id} ({node.addr[0]}) disconnected")

    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", self.args.port))
        sock.listen(50)

        print(f"[*] Distributed cracker server STARTED")
        print(f" ├─ Port         : {self.args.port}")
        print(f" ├─ Target hash  : {self.args.hash[:60]}...")
        print(f" ├─ Work size    : {self.args.work_size:,}")
        print(f" ├─ Checkpoint   : every {self.args.checkpoint:,}")
        print(f" └─ Timeout      : {self.args.timeout}s")
        print("\n[?] Waiting for workers...\n")

        while not found_event.is_set():
            try:
                sock.settimeout(1.0)
                conn, addr = sock.accept()
                sock.settimeout(None)
                node = Node(conn, addr, self.node_counter, self)
                with self.lock:
                    self.nodes.append(node)
                    self.node_counter += 1
            except socket.timeout:
                continue
            except KeyboardInterrupt:
                print("\n[!] Shutting down...")
                break


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--hash", type=str, required=True)
    parser.add_argument("--work-size", type=int, default=1000)
    parser.add_argument("--checkpoint", type=int, default=500)
    parser.add_argument("--timeout", type=int, default=600)
    args = parser.parse_args()

    Server(args).start()


if __name__ == "__main__":
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
    main()
