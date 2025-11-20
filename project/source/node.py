#!/usr/bin/env python3
"""
Robust worker node for the distributed password cracker.

Usage:
    python node.py --host 192.168.50.101 --port 5000 --threads 5

Behavior:
- Creates N worker threads once.
- Server sends work blocks:
  {"type":"work","start_idx":..., "end_idx":..., "hash":"...","checkpoint":N, "username": "..." }
- Workers atomically grab indices in the assigned block and test candidates.
- Workers send checkpoint updates every "checkpoint" attempts (sent by server).
- On success node sends {"type":"result","found":true,"password":"PLAINTEXT"}.
- Node requests more work when finished with a block.
"""

import argparse
import socket
import threading
import json
import time
import sys

# hashing libs
try:
    import crypt_r
except Exception:
    crypt_r = None

from passlib.context import CryptContext

# charset (your legal set)
CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#%^&*()_+-=.,:;?"
BASE = len(CHARS)

# passlib context used for non-yescrypt hashes
CTX = CryptContext(
    schemes=["bcrypt", "sha512_crypt", "sha256_crypt", "md5_crypt"],
    deprecated="auto",
)


def idx_to_guess(idx: int) -> str:
    """Convert integer index -> password string (variable length)."""
    if idx == 0:
        return CHARS[0]
    out = []
    while idx > 0:
        out.append(CHARS[idx % BASE])
        idx //= BASE
    return "".join(reversed(out))


def verify_hash(hash_field: str, guess: str) -> bool:
    """Verify guess against hash_field. Supports yescrypt ($y$) via crypt_r."""
    if not hash_field:
        return False

    if hash_field.startswith("$y$"):
        # yescrypt / similar requiring crypt_r
        if crypt_r is None:
            # Can't verify yescrypt without crypt_r
            return False
        try:
            out = crypt_r.crypt(guess, hash_field)
            return out == hash_field
        except Exception:
            return False

    # other schemes: use passlib
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
        self.recv_lock = threading.Lock()

        # work coordination
        self.current_work = None                # dict or None
        self.work_lock = threading.Lock()       # protect current_work fields
        self.work_available = threading.Event() # signals workers a block is present

        # per-work atomic next index (stored inside current_work as 'next_idx')
        # control flags
        self.stop_event = threading.Event()
        self.shutdown_lock = threading.Lock()

        # start worker threads once
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
                # socket likely dead
                # print minimal debug
                print(f"[!] Send error: {e}")
                return False

    # -----------------------
    # Main connect / reader
    # -----------------------
    def run(self):
        while not self.stop_event.is_set():
            try:
                print(f"[+] Connecting to server {self.host}:{self.port} ...")
                self.sock = self.connect()
                print("[+] Connected")
                # register
                self.safe_send({"type": "register", "threads": self.threads})
                # request initial work
                self.safe_send({"type": "request_work"})
                # message loop
                self.reader_loop()
            except Exception as e:
                print(f"[!] Connection error: {e}")
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
                    # remote closed
                    print("[!] Server closed connection")
                    break
                buf += data
                # process full newline-terminated messages
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if not line:
                        continue
                    try:
                        msg = json.loads(line.decode())
                    except Exception as e:
                        print(f"[!] JSON decode error: {e} line={line!r}")
                        continue
                    self.handle_message(msg)
            except Exception as e:
                print(f"[!] Reader error: {e}")
                break

    # -----------------------
    # Message handling
    # -----------------------
    def handle_message(self, msg: dict):
        tp = msg.get("type")
        if tp == "work":
            # expected keys: start_idx, end_idx, hash, checkpoint (optional), username (optional)
            start = int(msg.get("start_idx", 0))
            end = int(msg.get("end_idx", 0))
            h = msg.get("hash", "")
            checkpoint = int(msg.get("checkpoint", 0)) if msg.get("checkpoint") is not None else 0
            username = msg.get("username")

            if end <= start:
                # nothing to do: request more
                self.safe_send({"type": "request_work"})
                return

            with self.work_lock:
                # set the current work, including atomic next index
                self.current_work = {
                    "start_idx": start,
                    "end_idx": end,
                    "hash": h,
                    "checkpoint": checkpoint,
                    "username": username,
                    "next_idx": start,
                }
                # wake workers
                self.work_available.set()

            print(f"[+] New work assigned: [{start:,}..{end:,}) checkpoint={checkpoint} username={username}")

        elif tp == "stop":
            print("[!] Stop received from server")
            self.stop_event.set()
            # let workers finish current iteration if desired
            # clear work to avoid new attempts
            with self.work_lock:
                self.current_work = None
                self.work_available.clear()

        elif tp == "ack":
            # optional, ignore
            pass

        else:
            print(f"[!] Unknown message: {msg}")

    # -----------------------
    # Worker loop (each thread)
    # -----------------------
    def worker_loop(self):
        # local counters for checkpointing (track last checkpoint sent)
        last_checkpoint_sent = 0

        while not self.stop_event.is_set():
            # wait for work
            if not self.work_available.wait(timeout=1.0):
                continue

            # quick copy of the work reference to avoid holding lock long
            with self.work_lock:
                work = self.current_work
                if work is None:
                    self.work_available.clear()
                    continue

            start = work["start_idx"]
            end = work["end_idx"]
            target_hash = work["hash"]
            checkpoint_interval = int(work.get("checkpoint", 0)) or 0
            username = work.get("username")

            # grab indices atomically from work['next_idx']
            while True:
                if self.stop_event.is_set():
                    return

                with self.work_lock:
                    # ensure current_work didn't change
                    if self.current_work is not work:
                        # new work assigned - break and outer loop will reload it
                        break
                    next_idx = work["next_idx"]
                    if next_idx >= work["end_idx"]:
                        # finished this block
                        # clear current_work so we don't re-process it
                        self.current_work = None
                        self.work_available.clear()
                        break
                    # assign this index to this thread and bump
                    work["next_idx"] += 1

                # process the assigned index
                guess = idx_to_guess(next_idx)
                try:
                    ok = verify_hash(target_hash, guess)
                except Exception:
                    ok = False

                # checkpoint handling
                if checkpoint_interval:
                    # send checkpoint every checkpoint_interval attempts (approx)
                    # use next_idx as progress marker
                    if next_idx - last_checkpoint_sent >= checkpoint_interval:
                        cp_msg = {"type": "checkpoint", "idx": next_idx}
                        if username is not None:
                            cp_msg["username"] = username
                        self.safe_send(cp_msg)
                        last_checkpoint_sent = next_idx

                if ok:
                    print(f"[!!!] PASSWORD FOUND locally: {guess}")
                    # send plaintext to server
                    res = {"type": "result", "found": True, "password": guess}
                    if username is not None:
                        res["username"] = username
                    # attempt to send result (server should broadcast stop)
                    self.safe_send(res)
                    # mark stop and clear current work
                    self.stop_event.set()
                    with self.work_lock:
                        self.current_work = None
                        self.work_available.clear()
                    return

            # finished block without finding password: request next block
            if not self.stop_event.is_set():
                self.safe_send({"type": "request_work"})

        # exit worker when stop_event set
        return

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
        print("[!] KeyboardInterrupt, shutting down")
        node.stop_event.set()
        # close socket
        with node.sock_lock:
            try:
                if node.sock:
                    node.sock.close()
            except Exception:
                pass
        # give threads a moment
        time.sleep(0.2)


if __name__ == "__main__":
    main()

