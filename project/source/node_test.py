#!/usr/bin/env python3
import socket
import json
import threading
import argparse
import time
import sys

class WorkerNode:
    def __init__(self, server: str, port: int, threads: int):
        self.server = server
        self.port = port
        self.threads = threads
        self.sock = None
        self.stop_event = threading.Event()

    def connect_loop(self):
        while not self.stop_event.is_set():
            try:
                print(f"[DEBUG] Attempting to connect to {self.server}:{self.port}")
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.settimeout(5)  # short timeout for connect
                self.sock.connect((self.server, self.port))
                print(f"[DEBUG] Connected to {self.server}:{self.port}")
                self.send({"type": "register"})
                self.sock.settimeout(None)  # remove timeout after connect
                self.receive_loop()
                return
            except socket.timeout:
                print("[!] Connection timed out, retrying in 3s")
                time.sleep(3)
            except ConnectionRefusedError:
                print("[!] Connection refused, is the server running? Retrying in 3s")
                time.sleep(3)
            except Exception as e:
                print(f"[!] Unexpected connection error: {e}, retrying in 3s")
                time.sleep(3)

    def send(self, msg: dict):
        try:
            data = json.dumps(msg).encode() + b"\n"
            self.sock.sendall(data)
            print(f"[DEBUG] Sent message: {msg['type']}")
        except Exception as e:
            print(f"[!] Send failed: {e}")

    def receive_loop(self):
        buf = b""
        while not self.stop_event.is_set():
            try:
                data = self.sock.recv(4096)
                if not data:
                    print("[!] Server disconnected")
                    break
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if line:
                        try:
                            msg = json.loads(line)
                            print(f"[DEBUG] Received: {msg}")
                        except Exception as e:
                            print(f"[!] JSON decode error: {e}")
            except Exception as e:
                print(f"[!] Receive error: {e}")
                break

    def run(self):
        self.connect_loop()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--threads", type=int, default=4)
    args = parser.parse_args()

    node = WorkerNode(args.server, args.port, args.threads)
    node.run()

