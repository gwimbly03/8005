#!/usr/bin/env python3
import argparse
import socket
import json
import threading
import time
import signal
import sys

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
    if hash_field.startswith("$y$"):
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

class WorkerNode:
    def __init__(self, server_ip: str, port: int, threads: int):
        self.server_ip = server_ip
        self.port = port
        self.threads = threads
        self.hash = None
        self.stop_event = threading.Event()
        self.current_jobs = []  # list of active cracking jobs

    def connect(self):
        while not self.stop_event.is_set():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((self.server_ip, self.port))
                self.sock = sock
                self.send({"type": "register"})
                print(f"[+] Connected to server {self.server_ip}:{self.port}")
                self.receive_loop()
                return
            except Exception as e:
                print(f"[-] Connection failed ({e}), retrying in 5s...")
                time.sleep(5)

    def send(self, msg: dict):
        try:
            data = json.dumps(msg).encode("utf-8") + b"\n"
            self.sock.sendall(data)
        except:
            pass

    def receive_loop(self):
        buf = b""
        while not self.stop_event.is_set():
            try:
                data = self.sock.recv(4096)
                if not data:
                    break
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if line:
                        msg = json.loads(line.decode("utf-8"))
                        self.handle(msg)
            except:
                break
        print("[-] Disconnected from server")

    def handle(self, msg: dict):
        tp = msg["type"]

        if tp == "hash":
            self.hash = msg["hash"]
            print(f"[i] Received target hash")

        elif tp == "work":
            if not self.hash:
                return
            job = {
                "length": msg["length"],
                "start": msg["start_idx"],
                "end": msg["end_idx"],
                "interval": msg["checkpoint_interval"],
            }
            for _ in range(self.threads):
                t = threading.Thread(target=self.crack_thread, args=(job,), daemon=True)
                t.start()
                self.current_jobs.append(t)

        elif tp == "stop":
            print("[i] Stop signal received")
            self.stop_event.set()

    def crack_thread(self, job: dict):
        i = job["start"]
        end = job["end"]
        length = job["length"]
        interval = job["interval"]
        next_cp = i + interval

        while i < end and not self.stop_event.is_set():
            guess = idx_to_guess(i, length)
            if verify_hash(self.hash, guess):
                print(f"\n*** FOUND: {guess} ***")
                self.send({"type": "found", "password": guess})
                self.stop_event.set()
                return

            if i >= next_cp:
                self.send({"type": "checkpoint", "idx": i})
                next_cp += interval
            i += 1

        # finished without finding
        self.send({"type": "checkpoint", "idx": end})

    def run(self):
        while not self.stop_event.is_set():
            self.connect()
            time.sleep(5)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Distributed Password Cracker - Worker Node")
    parser.add_argument("--server", required=True, help="Server IP address")
    parser.add_argument("--port", type=int, default=5000, help="Server port")
    parser.add_argument("--threads", type=int, default=4, help="Number of cracking threads")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))

    node = WorkerNode(args.server, args.port, args.threads)
    node.run()
