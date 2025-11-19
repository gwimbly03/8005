#!/usr/bin/env python3
import argparse
import socket
import threading
import json
import time
import sys
import signal
from typing import Dict, Optional, List

import crypt_r
from passlib.context import CryptContext

# ====================== UNCHANGED CRACKING LOGIC ======================
LEGALCHAR = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#%^&*()_+-=.,:;?"
BASE = len(LEGALCHAR)

ctx = CryptContext(
    schemes=["bcrypt", "sha512_crypt", "sha256_crypt", "md5_crypt"],
    deprecated="auto",
)

def idx_to_guess(i: int, length: int) -> str:
    chars = []
    for _ in range(length):
        chars.append(LEGALCHAR[i % BASE])
        i //= BASE
    return "".join(reversed(chars))

def verify_hash(hash_field: str, password_guess: str) -> bool:
    if hash_field.startswith("$y$"):  # yescrypt
        try:
            out = crypt_r.crypt(password_guess, hash_field)
            return out == hash_field
        except Exception:
            return False
    else:
        try:
            return ctx.verify(password_guess, hash_field)
        except Exception:
            return False
# =====================================================================

def find_hash_in_shadow(shadow_path: str, username: str) -> str:
    with open(shadow_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if not line.strip() or line.startswith("#"):
                continue
            parts = line.rstrip("\n").split(":")
            if len(parts) >= 2 and parts[0] == username:
                return parts[1]
    raise ValueError(f"User '{username}' not found in shadow file")

class WorkUnit:
    def __init__(self, length: int, start_idx: int, end_idx: int):
        self.length = length
        self.start_idx = start_idx
        self.end_idx = end_idx
        self.last_reported = start_idx  # last checkpoint received

class Node:
    def __init__(self, conn: socket.socket, addr, node_id: int):
        self.conn = conn
        self.addr = addr
        self.id = node_id
        self.work: Optional[WorkUnit] = None
        self.alive = True
        self.last_seen = time.time()
        self.thread = threading.Thread(target=self.handle, daemon=True)
        self.thread.start()

    def send(self, msg: dict):
        try:
            data = json.dumps(msg).encode("utf-8") + b"\n"
            self.conn.sendall(data)
        except Exception:
            self.alive = False

    def handle(self):
        buf = b""
        while self.alive:
            try:
                data = self.conn.recv(4096)
                if not data:
                    break
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if line:
                        msg = json.loads(line.decode("utf-8"))
                        self.process_message(msg)
            except Exception:
                break
        self.alive = False
        server.on_node_disconnect(self)

    def process_message(self, msg: dict):
        global found_password, found_event

        if msg["type"] == "register":
            print(f"[+] Node #{self.id} registered from {self.addr[0]}:{self.addr[1]}")
            self.send({"type": "hash", "hash": target_hash})

        elif msg["type"] == "checkpoint":
            idx = msg["idx"]
            self.work.last_reported = idx
            self.last_seen = time.time()
            print(f"[*] Node #{self.id} checkpoint: length={self.work.length} idx={idx:,}")

        elif msg["type"] == "found":
            pw = msg["password"]
            print("\n" + "="*70)
            print(f"PASSWORD CRACKED BY NODE #{self.id}: {pw}")
            print("="*70)
            found_password = pw
            found_event.set()
            server.broadcast_stop()

class Server:
    def __init__(self, args):
        self.args = args
        self.nodes: List[Node] = []
        self.node_counter = 0
        self.lock = threading.Lock()
        self.current_length = 1
        self.pending_work: List[WorkUnit] = []
        self.assigned: Dict[Node, WorkUnit] = {}

    def broadcast_stop(self):
        msg = {"type": "stop"}
        for node in list(self.nodes):
            if node.alive:
                node.send(msg)

    def on_node_disconnect(self, node: Node):
        with self.lock:
            if not node.alive:
                return
            node.alive = False
            print(f"[-] Node #{node.id} disconnected ({node.addr})")
            if node in self.assigned:
                work = self.assigned.pop(node)
                remaining_start = work.last_reported
                if remaining_start < work.end_idx:
                    new_unit = WorkUnit(work.length, remaining_start, work.end_idx)
                    self.pending_work.append(new_unit)
                    print(f"[i] Requeued unfinished work: len={work.length} [{remaining_start:,}..{work.end_idx:,})")
            self.nodes = [n for n in self.nodes if n.alive]

    def health_check(self):
        while True:
            time.sleep(5)
            now = time.time()
            with self.lock:
                for node in list(self.nodes):
                    if node.alive and now - node.last_seen > self.args.timeout:
                        print(f"[!] Node #{node.id} timed out (no checkpoint for {self.args.timeout}s)")
                        node.conn.close()  # trigger disconnect handling

    def assign_work(self):
        while not found_event.is_set():
            with self.lock:
                idle_nodes = [n for n in self.nodes if n.alive and n.work is None]
                if not idle_nodes or not self.pending_work:
                    time.sleep(0.1)
                    continue
                node = idle_nodes[0]
                work = self.pending_work.pop(0)
            node.work = work
            self.assigned[node] = work

            msg = {
                "type": "work",
                "length": work.length,
                "start_idx": work.start_idx,
                "end_idx": work.end_idx,
                "checkpoint_interval": self.args.checkpoint
            }
            print(f"--> Node #{node.id}: len={work.length} [{work.start_idx:,}..{work.end_idx:,})")
            node.send(msg)

    def generate_work_for_length(self, length: int):
        total = BASE ** length
        start = 0
        while start < total:
            end = min(start + self.args.work_size, total)
            self.pending_work.append(WorkUnit(length, start, end))
            start = end
        print(f"[+] Prepared length {length}: {total:,} passwords → {len(self.pending_work)} chunks")

    def work_generator(self):
        while not found_event.is_set():
            self.generate_work_for_length(self.current_length)
            # wait until this length is done
            while self.pending_work or any(n.work and n.work.length == self.current_length for n in self.nodes):
                if found_event.is_set():
                    return
                time.sleep(1)
            self.current_length += 1
            if self.current_length > 12:
                print("[!] Max length reached")
                break

    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", self.args.port))
        sock.listen(50)
        print(f"[*] Server listening on port {self.args.port}")
        print(f"    Work size: {self.args.work_size:,} | Checkpoint: {self.args.checkpoint} | Timeout: {self.args.timeout}s")

        threading.Thread(target=self.assign_work, daemon=True).start()
        threading.Thread(target=self.work_generator, daemon=True).start()
        threading.Thread(target=self.health_check, daemon=True).start()

        while not found_event.is_set():
            try:
                conn, addr = sock.accept()
                with self.lock:
                    node = Node(conn, addr, self.node_counter)
                    self.nodes.append(node)
                    self.node_counter += 1
            except OSError:
                break

# ========================== GLOBALS ==========================
found_password: Optional[str] = None
found_event = threading.Event()
target_hash: str = ""
server: Server

def sigint_handler(sig, frame):
    print("\n[!] Shutting down...")
    found_event.set()
    if 'server' in globals():
        server.broadcast_stop()
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, sigint_handler)

    parser = argparse.ArgumentParser(description="Distributed Password Cracker - Server")
    parser.add_argument("--port", type=int, default=5000, help="Port the server listens on")
    parser.add_argument("--hash", required=True, help="Path to shadow file and username, e.g., '/etc/shadow alice'")
    parser.add_argument("--work-size", type=int, default=100_000, help="Passwords per work unit")
    parser.add_argument("--checkpoint", type=int, default=5000, help="Node sends checkpoint after N guesses")
    parser.add_argument("--timeout", type=int, default=60, help="Seconds to wait for checkpoint before considering node dead")
    args = parser.parse_args()

    # Parse --hash "shadow_path username"
    try:
        shadow_path, username = args.hash.rsplit(maxsplit=1)
    except ValueError:
        print("Error: --hash must be 'shadow_file_path username'")
        sys.exit(1)

    try:
        target_hash = find_hash_in_shadow(shadow_path, username)
        print(f"[*] Target user: {username}")
        print(f"[*] Hash: {target_hash}")
    except Exception as e:
        print(e)
        sys.exit(1)

    server = Server(args)
    server.start()
