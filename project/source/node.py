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

LEGAL = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#%^&*()_+-=.,:;?"
BASE = len(LEGAL)

ctx = CryptContext(
    schemes=["bcrypt", "sha512_crypt", "sha256_crypt", "md5_crypt"],
    deprecated="auto",
)

def idx_to_guess(n, length):
    out = []
    for _ in range(length):
        out.append(LEGAL[n % BASE])
        n //= BASE
    return "".join(reversed(out))

def verify(hash_field, guess):
    if hash_field.startswith("$y$"):  # yescrypt
        try:
            return crypt_r.crypt(guess, hash_field) == hash_field
        except:
            return False
    try:
        return ctx.verify(guess, hash_field)
    except:
        return False

class NodeClient:
    def __init__(self, server, port, threads):
        self.server = server
        self.port = port
        self.threads = threads
        self.stop = threading.Event()

    def send(self, msg):
        try:
            self.sock.sendall(json.dumps(msg).encode() + b"\n")
        except:
            pass

    def connect_loop(self):
        while not self.stop.is_set():
            try:
                print(f"[DEBUG] Attempting to connect to {self.server}:{self.port}")
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.connect((self.server, self.port))
                print("[DEBUG] Connected!")
                self.send({"type": "register"})
                self.reader()
            except Exception as e:
                print(f"[!] Connection failed: {e}")
                time.sleep(2)


    def reader(self):
        buf = b""
        while not self.stop.is_set():
            try:
                data = self.sock.recv(4096)
                if not data:
                    break
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if line.strip():
                        msg = json.loads(line)
                        self.handle(msg)
            except:
                break
        print("[-] Disconnected")

    def handle(self, msg):
        tp = msg["type"]

        if tp == "work":
            print(f"[+] Received work L={msg['length']} [{msg['start_idx']}..{msg['end_idx']})")

            for _ in range(self.threads):
                threading.Thread(target=self.worker, args=(msg,), daemon=True).start()

        elif tp == "stop":
            print("[!] STOP received")
            self.stop.set()

    def worker(self, w):
        length = w["length"]
        start = w["start_idx"]
        end = w["end_idx"]
        h = w["hash"]
        checkpoint = w["checkpoint"]

        next_cp = start + checkpoint

        for i in range(start, end):
            if self.stop.is_set():
                return

            guess = idx_to_guess(i, length)
            if verify(h, guess):
                print(f"PASSWORD FOUND: {guess}")
                self.send({"type": "found", "username": w["username"], "password": guess})
                self.stop.set()
                return

            if i >= next_cp:
                self.send({"type": "checkpoint", "username": w["username"], "idx": i})
                next_cp += checkpoint

    def run(self):
        self.connect_loop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--threads", type=int, default=4)
    args = parser.parse_args()

    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
    n = NodeClient(args.server, args.port, args.threads)
    n.run()

