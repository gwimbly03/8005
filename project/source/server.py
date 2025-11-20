#!/usr/bin/env python3
import argparse
import socket
import threading
import json
import time
import sys
import signal
from typing import Optional, Tuple

atomic_lock = threading.Lock()
atomic_counter = 0

found_event = threading.Event()


def atomic_reserve(count: int) -> int:
    global atomic_counter
    with atomic_lock:
        start = atomic_counter
        atomic_counter += count
        return start


class NodeConnection:
    def __init__(self, conn: socket.socket, addr: Tuple[str, int], node_id: int, server: "Server"):
        self.conn = conn
        self.addr = addr
        self.id = node_id
        self.server = server
        self.alive = True
        self.last_seen = time.time()

        self.current_work: Optional[dict] = None
        self.lock = threading.Lock()

        threading.Thread(target=self.reader, daemon=True).start()

    def send(self, msg: dict):
        try:
            self.conn.sendall(json.dumps(msg).encode() + b"\n")
        except Exception:
            self.alive = False

    def reader(self):
        buf = b""
        try:
            while self.alive and not found_event.is_set():
                data = self.conn.recv(4096)
                if not data:
                    break
                self.last_seen = time.time()
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if not line.strip():
                        continue
                    try:
                        msg = json.loads(line.decode())
                    except Exception:
                        print(f"[!] Invalid JSON from Node#{self.id}")
                        continue
                    self.server.handle_msg(self, msg)
        except Exception as e:
            print(f"[!] Node#{self.id} reader error: {e}")
        finally:
            self.alive = False
            self.server.node_lost(self)


class Server:
    def __init__(self, target_hash: str, args):
        self.hash = target_hash
        self.args = args

        self.nodes: list[NodeConnection] = []
        self.node_id_counter = 0

        self.pending: list[Tuple[int, int]] = []
        self.pending_lock = threading.Lock()

        self.lock = threading.Lock()

        threading.Thread(target=self.health_check_loop, daemon=True).start()

    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("0.0.0.0", self.args.port))
            sock.listen(50)
        except Exception as e:
            print(f"[!] Failed to bind/listen: {e}")
            sys.exit(1)

        print(f"[*] Listening on :{self.args.port}")
        print(f"[*] Hash = {self.hash}")
        print(f"[*] work-size={self.args.work_size} checkpoint={self.args.checkpoint} timeout={self.args.timeout}")

        while not found_event.is_set():
            try:
                conn, addr = sock.accept()
                with self.lock:
                    node = NodeConnection(conn, addr, self.node_id_counter, self)
                    self.node_id_counter += 1
                    self.nodes.append(node)
                print(f"[+] Node#{node.id} connected from {addr[0]}:{addr[1]}")
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[!] Accept error: {e}")

        try:
            sock.close()
        except Exception:
            pass

        self.broadcast_stop()

    # ──────────────────────────────────
    # Message Handling
    # ──────────────────────────────────
    def handle_msg(self, node: NodeConnection, msg: dict):
        t = msg.get("type")
        node.last_seen = time.time()

        if t == "register":
            print(f"[+] Node#{node.id} registered (threads={msg.get('threads')})")
            return

        if t == "request_work":
            if found_event.is_set():
                node.send({"type": "stop"})
                return

            if self.try_assign_from_pending(node):
                return

            start = atomic_reserve(self.args.work_size)
            end = start + self.args.work_size

            with node.lock:
                node.current_work = {"start": start, "end": end, "last_checkpoint": start}

            node.send({
                "type": "work",
                "start_idx": start,
                "end_idx": end,
                "hash": self.hash,
                "checkpoint": self.args.checkpoint,
                "timeout": self.args.timeout
            })
            print(f"[→] Node#{node.id} assigned [{start:,}..{end:,})")
            return

        if t == "checkpoint":
            idx = msg.get("idx")
            if idx is None:
                return
            with node.lock:
                if node.current_work:
                    node.current_work["last_checkpoint"] = int(idx)
            print(f"[*] Checkpoint Node#{node.id} idx={int(idx):,}")
            return

        if t == "result":
            # ───────────────────────────────
            # PASSWORD FOUND — ONLY PRINT IT
            # ───────────────────────────────
            if msg.get("found"):
                plaintext = msg.get("password", "<unknown>")
                print("\n" + "=" * 70)
                print(f"[+] Node#{node.id} cracked the password!")
                print(f"[+] Plaintext: {plaintext}")
                print("=" * 70 + "\n")
                found_event.set()
                self.broadcast_stop()
            return

    # ──────────────────────────────────
    # Pending Work
    # ──────────────────────────────────
    def requeue_range(self, start: int, end: int):
        with self.pending_lock:
            self.pending.append((start, end))
        print(f"[i] Requeued [{start:,}..{end:,})")

    def try_assign_from_pending(self, node: NodeConnection) -> bool:
        with self.pending_lock:
            if not self.pending:
                return False
            start, end = self.pending.pop(0)

        with node.lock:
            node.current_work = {"start": start, "end": end, "last_checkpoint": start}

        node.send({
            "type": "work",
            "start_idx": start,
            "end_idx": end,
            "hash": self.hash,
            "checkpoint": self.args.checkpoint,
            "timeout": self.args.timeout
        })
        print(f"[→] Node#{node.id} assigned REQUEUED [{start:,}..{end:,})")
        return True

    # ──────────────────────────────────
    # Node Disconnect/Timeout
    # ──────────────────────────────────
    def node_lost(self, node: NodeConnection):
        with self.lock:
            print(f"[-] Node#{node.id} disconnected")

            with node.lock:
                w = node.current_work
                if w:
                    remaining_start = int(w.get("last_checkpoint", w["start"]))
                    remaining_end = int(w["end"])
                    if remaining_start < remaining_end:
                        self.requeue_range(remaining_start, remaining_end)

            self.nodes = [n for n in self.nodes if n is not node]

    def health_check_loop(self):
        while not found_event.is_set():
            time.sleep(2)
            now = time.time()

            with self.lock:
                for node in list(self.nodes):
                    if not node.alive:
                        continue
                    if now - node.last_seen > self.args.timeout:
                        print(f"[!] Node#{node.id} TIMEOUT -> requeue remaining work")

                        with node.lock:
                            w = node.current_work
                            if w:
                                remaining_start = int(w.get("last_checkpoint", w["start"]))
                                remaining_end = int(w["end"])
                                if remaining_start < remaining_end:
                                    self.requeue_range(remaining_start, remaining_end)
                                node.current_work = None

                        try:
                            node.conn.close()
                        except:
                            pass
                        node.alive = False
                        self.nodes = [n for n in self.nodes if n is not node]

    # ──────────────────────────────────
    # STOP
    # ──────────────────────────────────
    def broadcast_stop(self):
        print("[*] Broadcasting STOP to all nodes...")
        with self.lock:
            for n in self.nodes:
                try:
                    n.send({"type": "stop"})
                except:
                    pass


def main():
    parser = argparse.ArgumentParser(description="Distributed Password Cracker - Server")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--hash", required=True)
    parser.add_argument("--work-size", type=int, default=1000)
    parser.add_argument("--checkpoint", type=int, default=500)
    parser.add_argument("--timeout", type=int, default=60)
    args = parser.parse_args()

    srv = Server(args.hash, args)

    def sigint(x, y):
        print("[!] CTRL+C — shutting down")
        found_event.set()
        srv.broadcast_stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, sigint)
    srv.start()


if __name__ == "__main__":
    main()

