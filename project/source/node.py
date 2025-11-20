#!/usr/bin/env python3
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
    """convert integer → password string of a given length"""
    out = []
    for _ in range(length):
        out.append(CHARS[idx % BASE])
        idx //= BASE
    return ''.join(reversed(out))

def verify(h, guess):
    return hashlib.md5(guess.encode()).hexdigest() == h


class Node:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.stop = threading.Event()
        self.sock = None

    def connect_loop(self):
        while not self.stop.is_set():
            try:
                print(f"[+] Connecting to server {self.host}:{self.port} ...")
                self.sock = socket.create_connection((self.host, self.port))
                print("[+] Connected")

                # register and request first work unit
                self.send({"type": "register"})
                self.send({"type": "request_work"})

                self.reader()
            except Exception as e:
                print(f"[!] Connection error: {e}")
                time.sleep(2)

    def reader(self):
        buf = b""
        while not self.stop.is_set():
            chunk = self.sock.recv(4096)
            if not chunk:
                print("[!] Server disconnected")
                break
            buf += chunk

            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if line.strip():
                    self.handle(json.loads(line))

        # if disconnected, stop or reconnect
        if not self.stop.is_set():
            print("[!] Attempting reconnect...")
            self.connect_loop()

    def send(self, obj):
        try:
            data = (json.dumps(obj) + "\n").encode()
            self.sock.sendall(data)
        except Exception as e:
            print(f"[!] Send error: {e}")

    def handle(self, msg):
        tp = msg.get("type")
        if tp == "work":
            # server sent: {"type":"work","index":N,"hash":"..."}
            threading.Thread(target=self.worker, args=(msg,), daemon=True).start()

        elif tp == "stop":
            print("[!] Stop signal from server")
            self.stop.set()

        elif tp == "result":
            # ignore, server shouldn't send this
            pass

        else:
            print(f"[!] Unknown message: {msg}")

    def worker(self, w):
        idx = w["index"]
        h = w["hash"]

        # Try all lengths: 1 → 32
        for length in range(1, 33):
            guess = idx_to_guess(idx, length)

            if verify(h, guess):
                print(f"[!!!] PASSWORD FOUND: {guess}")
                self.send({
                    "type": "result",
                    "found": True,
                    "password": guess
                })
                self.stop.set()
                return

        # Not found → request new index immediately
        self.send({"type": "request_work"})


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: node.py <host> <port>")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])

    n = Node(host, port)
    n.connect_loop()

