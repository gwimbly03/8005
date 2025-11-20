#!/usr/bin/env python3
import argparse
import socket
import threading
import json
import time
import hashlib
import string
import sys

CHARS = string.ascii_lowercase + string.ascii_uppercase + string.digits
BASE = len(CHARS)


def idx_to_guess(idx, length):
    """Convert an atomic index → password string for a given length."""
    out = []
    for _ in range(length):
        out.append(CHARS[idx % BASE])
        idx //= BASE
    return ''.join(reversed(out))


def verify(h, guess):
    return hashlib.md5(guess.encode()).hexdigest() == h


class Node:
    def __init__(self, host, port, threads):
        self.host = host
        self.port = port
        self.threads = threads
        self.stop = threading.Event()
        self.sock = None
        self.send_lock = threading.Lock()

    # ---------------------------------------------
    # Connection + message handling
    # ---------------------------------------------
    def connect_loop(self):
        while not self.stop.is_set():
            try:
                print(f"[+] Connecting to server {self.host}:{self.port} ...")
                self.sock = socket.create_connection((self.host, self.port))
                print("[+] Connected")

                self.send({"type": "register", "threads": self.threads})
                self.send({"type": "request_work"})

                self.reader()
            except Exception as e:
                print(f"[!] Connection error: {e}")
                time.sleep(2)

    def reader(self):
        buf = b""
        while not self.stop.is_set():
            try:
                chunk = self.sock.recv(4096)
                if not chunk:
                    print("[!] Server disconnected")
                    break
                buf += chunk

                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if line.strip():
                        msg = json.loads(line)
                        self.handle(msg)

            except Exception as e:
                print(f"[!] Reader error: {e}")
                break

        if not self.stop.is_set():
            print("[!] Attempting reconnect...")
            self.connect_loop()

    def send(self, obj):
        try:
            data = (json.dumps(obj) + "\n").encode()
            with self.send_lock:
                self.sock.sendall(data)
        except Exception as e:
            print(f"[!] Send error: {e}")

    # ---------------------------------------------
    # Message handling
    # ---------------------------------------------
    def handle(self, msg):
        tp = msg.get("type")

        if tp == "work":
            # Message example:
            # {"type":"work","start_idx":1234,"end_idx":2234,"length":4,"hash":"..."}
            print(f"[+] Got work: {msg}")
            for _ in range(self.threads):
                threading.Thread(target=self.worker, args=(msg,), daemon=True).start()

        elif tp == "stop":
            print("[!] Stop signal from server")
            self.stop.set()

        else:
            print(f"[!] Unknown message: {msg}")

    # ---------------------------------------------
    # Worker logic (atomic index → password)
    # ---------------------------------------------
    def worker(self, work):
        start = work["start_idx"]
        end = work["end_idx"]
        length = work["length"]
        h = work["hash"]

        for idx in range(start, end):
            if self.stop.is_set():
                return

            guess = idx_to_guess(idx, length)

            if verify(h, guess):
                print(f"[!!!] PASSWORD FOUND: {guess}")
                self.send({"type": "result", "found": True, "password": guess})
                self.stop.set()
                return

        # request more work when done
        self.send({"type": "request_work"})


# ---------------------------------------------
# Main
# ---------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--threads", required=True, type=int)
    args = parser.parse_args()

    node = Node(args.host, args.port, args.threads)
    node.connect_loop()

