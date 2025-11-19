#!/usr/bin/env python3
import argparse
import socket
import threading
import json
import time
import sys
import signal
import os
from typing import List, Tuple, Dict, Optional

# Server only needs this to compute search space size
LEGALCHAR = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#%^&*()_+-=.,:;?"
BASE = len(LEGALCHAR)

found_event = threading.Event()

class WorkUnit:
    def __init__(self, username: str, hash_field: str, length: int, start_idx: int, end_idx: int):
        self.username = username
        self.hash_field = hash_field
        self.length = length
        self.start_idx = start_idx
        self.end_idx = end_idx
        self.last_checkpoint = start_idx  # where node last reported

class Node:
    def __init__(self, conn: socket.socket, addr: tuple, node_id: int):
        self.conn = conn
        self.addr = addr
        self.id = node_id
        self.current_work: Optional[WorkUnit] = None
        self.alive = True
        self.last_seen = time.time()
        self.thread = threading.Thread(target=self.handle_connection, daemon=True)
        self.thread.start()

    def send(self, msg: dict):
        try:
            data = json.dumps(msg).encode("utf-8") + b"\n"
            self.conn.sendall(data)
        except:
            self.alive = False

    def handle_connection(self):
        buffer = b""
        while self.alive:
            try:
                data = self.conn.recv(4096)
                if not data:
                    break
                buffer += data
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    if line.strip():
                        msg = json.loads(line)
                        server.handle_message(self, msg)
            except:
                break
        self.alive = False
        server.node_disconnected(self)

class Server:
    def __init__(self, users: List[Tuple[str, str]], args):
        self.users = users[:]  # copy list of (username, hash)
        self.args = args
        self.nodes: List[Node] = []
        self.node_id_counter = 0
        self.pending_work: List[WorkUnit] = []
        self.assigned_work: Dict[Node, WorkUnit] = {}
        self.lock = threading.Lock()

    def load_all_users(self):
        print(f"[*] Loaded {len(self.users)} crackable account(s):")
        for username, h in self.users:
            alg = h.split("$")[1] if "$" in h else "unknown"
            print(f"    → {username:15} {h[:40]}... ({alg})")

    def generate_work_for_user(self, username: str, hash_field: str, length: int):
        total = BASE ** length
        chunk = self.args.work_size
        for start in range(0, total, chunk):
            end = min(start + chunk, total)
            self.pending_work.append(WorkUnit(username, hash_field, length, start, end))

    def generate_next_length(self):
        current_length = 1
        user_index = 0

        while not found_event.is_set() and user_index < len(self.users):
            username, hash_field = self.users[user_index]

            # Generate all chunks for this length for this user
            self.generate_work_for_user(username, hash_field, current_length)
            print(f"[+] Prepared length {current_length} for {username} → {BASE**current_length:,} passwords")

            # Wait until all chunks of this length for this user are done or password found
            while not found_event.is_set():
                with self.lock:
                    remaining = [w for w in self.pending_work if w.username == username and w.length == current_length]
                    assigned_here = [w for w in self.assigned_work.values() if w.username == username and w.length == current_length]
                if not remaining and not assigned_here:
                    break
                time.sleep(1)

            current_length += 1
            if current_length > 12:
                print(f"[!] {username} reached max length, moving to next user")
                user_index += 1
                current_length = 1

        if not found_event.is_set():
            print("[!] All users exhausted — no password found")

    def assign_work(self):
        while not found_event.is_set():
            time.sleep(0.2)
            with self.lock:
                idle_nodes = [n for n in self.nodes if n.alive and n.current_work is None]
                if not idle_nodes or not self.pending_work:
                    continue
                node = idle_nodes[0]
                work = self.pending_work.pop(0)
                node.current_work = work
                self.assigned_work[node] = work

            msg = {
                "type": "work",
                "username": work.username,
                "hash": work.hash_field,
                "length": work.length,
                "start_idx": work.start_idx,
                "end_idx": work.end_idx,
                "checkpoint_interval": self.args.checkpoint
            }
            print(f"--> Node #{node.id} → {work.username} len={work.length} [{work.start_idx:,}..{work.end_idx:,})")
            node.send(msg)

    def handle_message(self, node: Node, msg: dict):
        global found_event
        t = msg["type"]

        if t == "register":
            print(f"[+] Node #{node.id} registered from {node.addr[0]}:{node.addr[1]}")
            node.last_seen = time.time()

        elif t == "checkpoint":
            idx = msg["idx"]
            node.last_seen = time.time()
            if node.current_work:
                node.current_work.last_checkpoint = idx
            print(f"[*] Checkpoint Node #{node.id} → {msg['username']} len={msg['length']} idx={idx:,}")

        elif t == "found":
            print("\n" + "="*80)
            print(f"PASSWORD FOUND BY NODE #{node.id}!")
            print(f"Username : {msg['username']}")
            print(f"Password : {msg['password']}")
            print("="*80)
            found_event.set()
            self.broadcast_stop()

    def node_disconnected(self, node: Node):
        with self.lock:
            if not node.alive:
                return
            node.alive = False
            print(f"[-] Node #{node.id} disconnected")
            if node in self.assigned_work:
                work = self.assigned_work.pop(node)
                if work.last_checkpoint < work.end_idx:
                    remaining = WorkUnit(
                        work.username, work.hash_field, work.length,
                        work.last_checkpoint, work.end_idx
                    )
                    self.pending_work.append(remaining)
                    print(f"[i] Re-queued partial work for {work.username} [{work.last_checkpoint:,}..{work.end_idx:,})")
            self.nodes = [n for n in self.nodes if n.alive]

    def health_check(self):
        while not found_event.is_set():
            time.sleep(5)
            now = time.time()
            with self.lock:
                for node in list(self.nodes):
                    if node.alive and now - node.last_seen > self.args.timeout:
                        print(f"[!] Node #{node.id} timeout ({self.args.timeout}s no checkpoint)")
                        node.conn.close()

    def broadcast_stop(self):
        msg = {"type": "stop"}
        for node in self.nodes:
            if node.alive:
                node.send(msg)

    def start(self):
        self.load_all_users()
        print(f"[*] Listening on 0.0.0.0:{self.args.port}")
        print(f"    Work size: {self.args.work_size} | Checkpoint: {self.args.checkpoint} | Timeout: {self.args.timeout}s\n")

        threading.Thread(target=self.generate_next_length, daemon=True).start()
        threading.Thread(target=self.assign_work, daemon=True).start()
        threading.Thread(target=self.health_check, daemon=True).start()

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", self.args.port))
        sock.listen(50)

        while not found_event.is_set():
            try:
                conn, addr = sock.accept()
                with self.lock:
                    node = Node(conn, addr, self.node_id_counter)
                    self.nodes.append(node)
                    self.node_id_counter += 1
            except OSError:
                break

# ==================== MAIN ====================
def main():
    parser = argparse.ArgumentParser(description="Distributed Password Cracker - Server")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--hash", required=True, help="Path to shadow file")
    parser.add_argument("--work-size", type=int, default=100000, help="Guesses per work unit")
    parser.add_argument("--checkpoint", type=int, default=5000, help="Checkpoint every N guesses")
    parser.add_argument("--timeout", type=int, default=60, help="Node timeout in seconds")
    args = parser.parse_args()

    if not os.path.isfile(args.hash):
        print(f"[!] Shadow file not found: {args.hash}")
        sys.exit(1)

    users = []
    with open(args.hash, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":", 2)
            if len(parts) >= 2:
                username, h = parts[0], parts[1]
                if h.startswith("$") and not h.startswith("!"):
                    users.append((username, h))

    if not users:
        print("[!] No crackable hashes found")
        sys.exit(1)

    global server
    server = Server(users, args)
    server.start()

if __name__ == "__main__":
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
    main()
