import argparse
import socket
import threading
import json
import time
import sys
import signal
import os
from typing import List, Tuple, Dict, Optional

LEGAL = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#%^&*()_+-=.,:;?"
BASE = len(LEGAL)

found_event = threading.Event()

class WorkUnit:
    def __init__(self, username, hash_field, length, start_idx, end_idx):
        self.username = username
        self.hash_field = hash_field
        self.length = length
        self.start = start_idx
        self.end = end_idx
        self.last_checkpoint = start_idx

class Node:
    def __init__(self, conn, addr, node_id):
        self.conn = conn
        self.addr = addr
        self.id = node_id
        self.current_work: Optional[WorkUnit] = None
        self.alive = True
        self.last_seen = time.time()

        self.thread = threading.Thread(target=self.reader, daemon=True)
        self.thread.start()

    def send(self, msg: dict):
        try:
            data = json.dumps(msg).encode() + b"\n"
            self.conn.sendall(data)
        except:
            self.alive = False

    def reader(self):
        buf = b""
        while self.alive:
            try:
                data = self.conn.recv(4096)
                if not data:
                    print(f"[-] Node#{self.id} disconnected (no data)")
                    break
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if line.strip():
                        try:
                            msg = json.loads(line)
                            print(f"[DEBUG] Node#{self.id} sent: {msg}")
                            server.handle_msg(self, msg)
                        except Exception as e:
                            print(f"[!] Failed to decode JSON from Node#{self.id}: {e}")
            except Exception as e:
                print(f"[!] Reader exception Node#{self.id}: {e}")
                break
        self.alive = False
        server.node_lost(self)
        print(f"[-] Node#{self.id} reader thread exiting")


class Server:
    def __init__(self, users, args):
        self.users = users
        self.args = args

        self.nodes: List[Node] = []
        self.pending: List[WorkUnit] = []
        self.assigned: Dict[Node, WorkUnit] = {}

        self.lock = threading.Lock()
        self.node_counter = 0

    def load(self):
        print(f"[*] Loaded {len(self.users)} user(s)")
        for u, h in self.users:
            print(f"  → {u}: {h[:35]}...")

    def generate_user(self, username, hash_field, length):
        total = BASE ** length
        chunk = self.args.work_size

        for s in range(0, total, chunk):
            e = min(s + chunk, total)
            self.pending.append(WorkUnit(username, hash_field, length, s, e))

        print(f"[+] Prepared length={length} for {username} ({total:,} guesses)")

    def length_worker(self):
        """Generate all lengths for each user."""
        user_i = 0
        length = 1

        while not found_event.is_set() and user_i < len(self.users):
            username, h = self.users[user_i]

            self.generate_user(username, h, length)

            # wait for this length to finish
            while not found_event.is_set():
                with self.lock:
                    remaining = [w for w in self.pending if w.username == username and w.length == length]
                    assigned = [w for w in self.assigned.values() if w.username == username and w.length == length]
                if not remaining and not assigned:
                    break
                time.sleep(0.5)

            length += 1
            if length > 12:
                user_i += 1
                length = 1

        if not found_event.is_set():
            print("[!] No passwords found for any user")

    def assigner(self):
        """Assign idle nodes work."""
        while not found_event.is_set():
            time.sleep(0.1)

            with self.lock:
                if not self.pending:
                    continue

                idle = [n for n in self.nodes if n.alive and n.current_work is None]
                if not idle:
                    continue

                node = idle[0]
                work = self.pending.pop(0)

                self.assigned[node] = work
                node.current_work = work

            msg = {
                "type": "work",
                "username": work.username,
                "hash": work.hash_field,
                "length": work.length,
                "start_idx": work.start,
                "end_idx": work.end,
                "checkpoint": self.args.checkpoint
            }

            print(f"[→] Node#{node.id} assigned {work.username} L={work.length} [{work.start:,}..{work.end:,})")
            node.send(msg)

    def handle_msg(self, node, msg):
        tp = msg["type"]

        if tp == "register":
            print(f"[+] Node#{node.id} registered")
            node.last_seen = time.time()
            return

        if tp == "checkpoint":
            node.last_seen = time.time()
            if node.current_work:
                node.current_work.last_checkpoint = msg["idx"]
            print(f"[*] Node#{node.id} checkpoint idx={msg['idx']:,}")
            return

        if tp == "found":
            print("\n" + "=" * 70)
            print(f"PASSWORD FOUND by Node#{node.id}")
            print(f"User: {msg['username']}")
            print(f"Pass: {msg['password']}")
            print("=" * 70)
            found_event.set()
            self.broadcast_stop()

    def broadcast_stop(self):
        for n in self.nodes:
            if n.alive:
                n.send({"type": "stop"})

    def node_lost(self, node):
        with self.lock:
            if node in self.assigned:
                work = self.assigned.pop(node)
                if work.last_checkpoint < work.end:
                    print(f"[!] Node#{node.id} lost — requeueing [{work.last_checkpoint}..{work.end})")
                    self.pending.append(
                        WorkUnit(work.username, work.hash_field, work.length,
                                 work.last_checkpoint, work.end)
                    )

            self.nodes = [n for n in self.nodes if n.alive]

    def health_check(self):
        """Disconnect nodes that haven't checked in within timeout."""
        while not found_event.is_set():
            time.sleep(5)
            now = time.time()
            with self.lock:
                for node in list(self.nodes):
                    if node.alive and now - node.last_seen > self.args.timeout:
                        print(f"[!] Node#{node.id} timed out (> {self.args.timeout}s)")
                        node.conn.close()  # triggers node_lost

    def start(self):
        self.load()

        # start worker threads
        threading.Thread(target=self.length_worker, daemon=True).start()
        threading.Thread(target=self.assigner, daemon=True).start()
        threading.Thread(target=self.health_check, daemon=True).start()
        try:
            sock.bind(("0.0.0.0", self.args.port))
            sock.listen(50)
            print(f"[*] Listening on 0.0.0.0:{self.args.port}")
        except Exception as e:
            print(f"[!] Failed to bind/listen: {e}")
            sys.exit(1)

        while not found_event.is_set():
            try:
                conn, addr = sock.accept()
                print(f"[+] Incoming connection from {addr[0]}:{addr[1]}")
                n = Node(conn, addr, self.node_counter)
                with self.lock:
                    self.nodes.append(n)
                    self.node_counter += 1
            except KeyboardInterrupt:
                print("[!] KeyboardInterrupt detected, exiting...")
                break
            except Exception as e:
                print(f"[!] Accept failed: {e}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--hash", required=True)
    parser.add_argument("--work-size", type=int, default=500)
    parser.add_argument("--checkpoint", type=int, default=5000)
    parser.add_argument("--timeout", type=int, default=60, help="Node timeout in seconds")

    args = parser.parse_args()

    users = []
    with open(args.hash) as f:
        for line in f:
            parts = line.strip().split(":")
            if len(parts) >= 2 and parts[1].startswith("$"):
                users.append((parts[0], parts[1]))

    global server
    server = Server(users, args)
    server.start()


if __name__ == "__main__":
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
    main()

