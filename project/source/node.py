#!/usr/bin/env python3
"""
Distributed node client that expects server to send:
{ type: "work", start_idx: int, end_idx: int, length: int, hash: str, checkpoint: int, timeout: int, assigned_time: float }
It uses cracker.idx_to_guess(i, length) and cracker.verify_hash(...) from /mnt/data/cracker.py
"""

import argparse
import socket
import threading
import json
import time
import sys
import os

CHAR = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#%^&*()_+-=.,:;?"
BASE = len(CHAR)

from passlib.context import CryptContext
try:
    import crypt_r
except Exception:
    crypt_r = None

CTX = CryptContext(
    schemes=["bcrypt", "sha512_crypt", "sha256_crypt", "md5_crypt"],
    deprecated="auto",
)

def idx_to_guess(i, length):
    base = len(CHAR)
    chars = []
    for _ in range(length):
        chars.append(CHAR[i % base])
        i //= base
    return "".join(reversed(chars))

def verify_hash(hash_field: str, guess: str) -> bool:
    """Verify guess against hash_field. Supports yescrypt ($y$) via crypt_r."""
    if not hash_field:
        return False

    # yescrypt via crypt_r
    if hash_field.startswith("$y$"):
        if crypt_r is None:
            return False
        try:
            out = crypt_r.crypt(guess, hash_field)
            return out == hash_field
        except Exception:
            return False

    # otherwise use passlib
    try:
        return CTX.verify(guess, hash_field)
    except Exception:
        return False

class Node:
    def __init__(self, host: str, port: int, threads: int):
        self.host = host
        self.port = port
        self.threads = threads

        # network
        self.sock = None
        self.sock_lock = threading.Lock()       # protect sends

        # work coordination
        self.current_work = None                # dict or None
        self.work_lock = threading.Lock()       # protect current_work fields
        self.work_available = threading.Event() # signals workers a block is present

        # control flags
        self.stop_event = threading.Event()

        # start worker threads
        self.workers = []
        for i in range(self.threads):
            t = threading.Thread(target=self.worker_loop, name=f"worker-{i}", daemon=True)
            t.start()
            self.workers.append(t)

    # -----------------------
    # Networking utilities
    # -----------------------
    def connect(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(10)
        s.connect((self.host, self.port))
        s.settimeout(None)  # blocking
        return s

    def safe_send(self, obj: dict):
        """Thread-safe send JSON + newline. Returns False on failure."""
        data = (json.dumps(obj) + "\n").encode()
        with self.sock_lock:
            try:
                if self.sock is None:
                    return False
                self.sock.sendall(data)
                return True
            except Exception as e:
                debug(f"[!] Send error: {e}")
                return False

    # -----------------------
    # Main connect / reader
    # -----------------------
    def run(self):
        while not self.stop_event.is_set():
            try:
                debug(f"[+] Connecting to server {self.host}:{self.port} ...")
                self.sock = self.connect()
                debug("[+] Connected")
                # register
                self.safe_send({"type": "register", "threads": self.threads})
                # request initial work
                self.safe_send({"type": "request_work"})
                # message loop
                self.reader_loop()
            except Exception as e:
                debug(f"[!] Connection error: {e}")
                # clear state so workers don't spin on stale work
                with self.work_lock:
                    self.current_work = None
                    self.work_available.clear()
                time.sleep(2)
            finally:
                # ensure socket is closed on error/exit
                with self.sock_lock:
                    try:
                        if self.sock:
                            self.sock.close()
                    except Exception:
                        pass
                    self.sock = None

    def reader_loop(self):
        buf = b""
        while not self.stop_event.is_set():
            try:
                data = self.sock.recv(4096)
                if not data:
                    debug("[!] Server closed connection")
                    break
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if not line:
                        continue
                    try:
                        msg = json.loads(line.decode())
                    except Exception as e:
                        debug(f"[!] JSON decode error: {e} line={line!r}")
                        continue
                    self.handle_message(msg)
            except Exception as e:
                debug(f"[!] Reader error: {e}")
                break

    # -----------------------
    # Message handling
    # -----------------------
    def handle_message(self, msg: dict):
        tp = msg.get("type")
        if tp == "work":
            try:
                start = int(msg.get("start_idx", 0))
                end = int(msg.get("end_idx", -1))
                length = int(msg.get("length", 1))
            except Exception:
                debug("[!] Invalid work indices from server")
                self.safe_send({"type": "request_work"})
                return

            target_hash = msg.get("hash", "")
            checkpoint = int(msg.get("checkpoint", 0)) if msg.get("checkpoint") is not None else 0
            timeout = int(msg.get("timeout", 0)) if msg.get("timeout") is not None else 0
            assigned_time = float(msg.get("assigned_time", time.time()))
            username = msg.get("username")

            if end < start:
                self.safe_send({"type": "request_work"})
                return

            with self.work_lock:
                self.current_work = {
                    "start_idx": start,
                    "end_idx": end,               # inclusive offset within this length
                    "length": length,
                    "hash": target_hash,
                    "checkpoint": checkpoint,
                    "timeout": timeout,
                    "username": username,
                    "assigned_time": assigned_time,
                    "next_idx": start,
                    "last_progress_sent": start
                }
                self.work_available.set()

            debug(f"[+] New work assigned: length={length} [{start:,} .. {end:,}] checkpoint={checkpoint}")

        elif tp == "stop":
            debug("[!] Stop received from server")
            self.stop_event.set()
            with self.work_lock:
                self.current_work = None
                self.work_available.clear()

        elif tp == "ack":
            pass

        else:
            debug(f"[!] Unknown message: {msg}")

    # -----------------------
    # Worker loop (each thread)
    # -----------------------
    def worker_loop(self):
        while not self.stop_event.is_set():
            # wait for work assignment
            if not self.work_available.wait(timeout=1.0):
                continue

            with self.work_lock:
                work = self.current_work
                if work is None:
                    self.work_available.clear()
                    continue

            length = work["length"]
            checkpoint_interval = int(work.get("checkpoint", 0))
            timeout = int(work.get("timeout", 0))
            username = work.get("username")
            assigned_time = float(work.get("assigned_time", time.time()))

            while True:
                if self.stop_event.is_set():
                    return

                with self.work_lock:
                    if self.current_work is not work:
                        break

                    next_idx = work["next_idx"]
                    if next_idx > work["end_idx"]:
                        debug(f"[{threading.current_thread().name}] block finished at idx={next_idx}")
                        self.current_work = None
                        self.work_available.clear()
                        break

                    if timeout > 0 and (time.time() - assigned_time) >= timeout:
                        debug(f"[!] Block timeout reached (assigned {time.time() - assigned_time:.1f}s ago)")
                        self.current_work = None
                        self.work_available.clear()
                        break

                    # allocate current index to this thread
                    work["next_idx"] += 1
                    cur_idx = next_idx

                # use cracker's idx_to_guess(i, length) - i is an offset within this length
                try:
                    guess = idx_to_guess(cur_idx, length)
                except Exception as e:
                    debug(f"[!] idx_to_guess error for idx={cur_idx}, length={length}: {e}")
                    self.stop_event.set()
                    return

                # debug only for length >= 3
                if len(guess) >= 3:
                    debug(f"[{threading.current_thread().name}] Trying idx={cur_idx} -> '{guess}'")

                if verify_hash(work["hash"], guess):
                    debug(f"[!!!] PASSWORD FOUND: {guess}")
                    res = {"type": "result", "found": True, "password": guess}
                    if username is not None:
                        res["username"] = username
                    self.safe_send(res)
                    self.stop_event.set()
                    with self.work_lock:
                        self.current_work = None
                        self.work_available.clear()
                    return

                # checkpoint / progress messages
                sent_progress = False
                if checkpoint_interval > 0:
                    with self.work_lock:
                        last_sent = work.get("last_progress_sent", work["start_idx"])
                        if (cur_idx - last_sent) >= checkpoint_interval:
                            work["last_progress_sent"] = cur_idx
                            sent_progress = True

                    if sent_progress:
                        msg = {"type": "progress", "current": cur_idx}
                        if username is not None:
                            msg["username"] = username
                        self.safe_send(msg)

            # finished block without finding password → request more work
            if not self.stop_event.is_set():
                time.sleep(0.01)
                self.safe_send({"type": "request_work"})

# -----------------------
# CLI / main
# -----------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--threads", required=True, type=int)
    args = parser.parse_args()

    node = Node(args.host, args.port, args.threads)
    try:
        node.run()
    except KeyboardInterrupt:
        debug("[!] KeyboardInterrupt, shutting down")
        node.stop_event.set()
        with node.sock_lock:
            try:
                if node.sock:
                    node.sock.close()
            except Exception:
                pass
        time.sleep(0.2)

if __name__ == "__main__":
    main()

