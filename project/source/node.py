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

# ====================== CRACKING LOGIC (ONLY ON NODE) ======================
LEGALCHAR = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#%^&*()_+-=.,:;?"
BASE = len(LEGALCHAR)

ctx = CryptContext(
    schemes=["bcrypt", "sha512_crypt", "sha256_crypt", "md5_crypt"],
    deprecated="auto",
)

def idx_to_guess(i: int, length: int) -> str:
    chars = []
    idx = i
    for _ in range(length):
        chars.append(LEGALCHAR[idx % BASE])
        idx //= BASE
    return "".join(reversed(chars))

def verify_hash(hash_field: str, password_guess: str) -> bool:
    if hash_field.startswith("$y$"):  # yescrypt
        try:
            out = crypt_r.crypt(password_guess, hash_field)
            return out == hash_field
        except:
            return False
    else:
        try:
            return ctx.verify(password_guess, hash_field)
        except:
            return False
# ==========================================================================

class WorkerNode:
    def __init__(self, server_ip: str, port: int, threads: int):
        self.server_ip = server_ip
        self.port = port
        self.threads = threads
        self.current_target = None
        self.stop_event = threading.Event()

    def connect(self):
        while not self.stop_event.is_set():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((self.server_ip, self.port))
                self.sock = sock
                self.send({"type": "register"})
                print(f"[+] Connected to {self.server_ip}:{self.port}")
                self.receive_loop()
                return
            except Exception as e:
                print(f"[-] Connection failed: {e} – retrying in 5s")
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
        if tp == "new_target":
            self.current_target = {
                "username": msg["username"],
                "hash": msg["hash"],
                "interval": msg["checkpoint_interval"]
            }
            print(f"[+] Cracking user: {msg['username']}")
            for _ in range(self.threads):
                t = threading.Thread(target=self.crack_target, daemon=True)
                t.start()

        elif tp == "stop":
            print("[i] Stop signal received")
            self.stop_event.set()

    def crack_target(self):
        target = self.current_target
        if not target:
            return

        username = target["username"]
        h = target["hash"]
        interval = target["interval"]

        length = 1
        while not self.stop_event.is_set():
            total = BASE ** length
            i = 0
            next_cp = interval

            while i < total and not self.stop_event.is_set():
                guess = idx_to_guess(i, length)
                if verify_hash(h, guess):
                    print(f"\n*** PASSWORD FOUND for {username}: {guess} ***")
                    self.send({"type": "found", "username": username, "password": guess})
                    self.stop_event.set()
                    return

                if i >= next_cp:
                    self.send({"type": "checkpoint", "username": username, "length": length, "idx": i})
                    next_cp += interval
                i += 1

            print(f"[i] Finished length {length} for {username}")
            length += 1
            if length > 12:
                break

        self.send({"type": "checkpoint", "username": username, "length": length, "idx": 0})

    def run(self):
        while not self.stop_event.is_set():
            self.connect()
            time.sleep(5)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Distributed Password Cracker – Node")
    parser.add_argument("--server", required=True)
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--threads", type=int, default=4)
    args = parser.parse_args()

    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
    node = WorkerNode(args.server, args.port, args.threads)
    node.run()
