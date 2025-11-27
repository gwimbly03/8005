#!/usr/bin/env python3
"""
Debug-enabled Node client for distributed brute-force.
Includes:
 - --selftest to print first N idx->password mappings
 - --find <password> to search for index of password in first N
 - --debug to print progress while running against a server
This preserves your original worker logic for use with the server.
"""
import argparse
import socket
import threading
import json
import time
import sys

try:
    import crypt_r
except Exception:
    crypt_r = None

from passlib.context import CryptContext

CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#%^&*()_+-=.,:;?"
BASE = len(CHARS)

CTX = CryptContext(
    schemes=["bcrypt", "sha512_crypt", "sha256_crypt", "md5_crypt"],
    deprecated="auto",
)


def idx_to_guess(idx: int) -> str:
    """Convert integer index -> password string (variable length)."""
    if idx < 0:
        raise ValueError("Index must be non-negative")
    if idx == 0:
        return CHARS[0]
    chars = []
    while idx > 0:
        chars.append(CHARS[idx % BASE])
        idx //= BASE
    return "".join(reversed(chars))


def verify_hash(hash_field: str, guess: str) -> bool:
    """Verify guess against hash_field. Supports yescrypt ($y$) via crypt_r."""
    if not hash_field:
        return False

    if hash_field.startswith("$y$"):
        if crypt_r is None:
            return False
        try:
            out = crypt_r.crypt(guess, hash_field)
            return out == hash_field
        except Exception:
            return False

    try:
        return CTX.verify(guess, hash_field)
    except Exception:
        return False


# ----------------------------
# Debug / test helpers
# ----------------------------
def selftest_print(count: int):
    """Print first `count` mappings and show where lengths grow."""
    last_len = 0
    for i in range(count):
        s = idx_to_guess(i)
        if len(s) != last_len:
            print(f"--- index {i} => length increased to {len(s)} (example: {s}) ---")
            last_len = len(s)
        if i < 200 or (i % 1000 == 0):
            print(f"{i:8d} -> {s}")
        # avoid extremely slow stdout for huge counts; print markers instead
    print("selftest done.")


def find_index_for_password(target: str, max_idx: int):
    """Brute-force search for a password among first max_idx indices (for debugging)."""
    for i in range(max_idx + 1):
        if idx_to_guess(i) == target:
            return i
    return None


# -----------------------
# Main Node implementation
# -----------------------
class Node:
    def __init__(self, host: str, port: int, threads: int, debug=False, dbg_interval=10000):
        self.host = host
        self.port = port
        self.threads = threads
        self.debug = debug
        self.dbg_interval = dbg_interval

        # network
        self.sock = None
        self.sock_lock = threading.Lock()       # protect sends

        # work coordination
        self.current_work = None                # dict or None
        self.work_lock = threading.Lock()       # protect current_work fields
        self.work_available = threading.Event() # signals workers a block is present

        # control flags
        self.stop_event = threading.Event()

        # worker threads
        self.workers = []
        for i in range(self.threads):
            t = threading.Thread(target=self.worker_loop, name=f"worker-{i}", daemon=True)
            t.start()
            self.workers.append(t)

        # heartbeat thread (keeps server's last_seen fresh)
        self.hb_thread = threading.Thread(target=self.heartbeat_loop, daemon=True)
        self.hb_thread.start()

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
                if self.debug:
                    print(f"[!] Send error: {e}")
                return False

    # -----------------------
    # Heartbeat to keep server last_seen fresh
    # -----------------------
    def heartbeat_loop(self):
        while not self.stop_event.is_set():
            try:
                with self.sock_lock:
                    sock_present = self.sock is not None
                if sock_present:
                    self.safe_send({"type": "heartbeat"})
                time.sleep(10)
            except Exception:
                time.sleep(1)

    # -----------------------
    # Main connect / reader
    # -----------------------
    def run(self):
        while not self.stop_event.is_set():
            try:
                if self.debug:
                    print(f"[+] Connecting to server {self.host}:{self.port} ...")
                self.sock = self.connect()
                if self.debug:
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
                    print("[!] Server closed connection")
                    break
                buf += data
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
            # expected keys: start_idx, end_idx (inclusive), hash, checkpoint (optional), timeout (optional), assigned_time (optional), username (optional)
            try:
                start = int(msg.get("start_idx", 0))
                end = int(msg.get("end_idx", -1))
            except Exception:
                print("[!] Invalid work indices from server")
                self.safe_send({"type": "request_work"})
                return

            target_hash = msg.get("hash", "")
            checkpoint = int(msg.get("checkpoint", 0)) if msg.get("checkpoint") is not None else 0
            timeout = int(msg.get("timeout", 0)) if msg.get("timeout") is not None else 0
            assigned_time = float(msg.get("assigned_time", time.time()))
            username = msg.get("username")

            if end < start:
                # nothing to do: request more
                self.safe_send({"type": "request_work"})
                return

            with self.work_lock:
                # set the current work, including atomic next index and bookkeeping
                self.current_work = {
                    "start_idx": start,
                    "end_idx": end,               # inclusive
                    "hash": target_hash,
                    "checkpoint": checkpoint,
                    "timeout": timeout,
                    "username": username,
                    "assigned_time": assigned_time,
                    "next_idx": start,
                    # per-block progress tracking
                    "last_progress_sent": start,
                    # debug counters
                    "checked_since_dbg": 0
                }
                # wake workers
                self.work_available.set()

            print(f"[+] New work assigned: [{start:,} .. {end:,}] checkpoint={checkpoint} timeout={timeout} username={username}")

        elif tp == "stop":
            print("[!] Stop received from server")
            self.stop_event.set()
            with self.work_lock:
                self.current_work = None
                self.work_available.clear()

        elif tp == "ack":
            pass

        else:
            print(f"[!] Unknown message: {msg}")

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

            # extract parameters (cached for this thread)
            checkpoint_interval = int(work.get("checkpoint", 0))
            timeout = int(work.get("timeout", 0))
            username = work.get("username")
            assigned_time = float(work.get("assigned_time", time.time()))

            while True:
                if self.stop_event.is_set():
                    return

                with self.work_lock:
                    # ensure current_work hasn't changed
                    if self.current_work is not work:
                        break

                    next_idx = work["next_idx"]
                    # if next_idx is past inclusive end, block is done
                    if next_idx > work["end_idx"]:
                        self.current_work = None
                        self.work_available.clear()
                        break

                    # check server-supplied timeout (compare to assigned_time)
                    if timeout > 0 and (time.time() - assigned_time) >= timeout:
                        print(f"[!] Block timeout reached (assigned {time.time() - assigned_time:.1f}s ago) — requesting new block")
                        self.current_work = None
                        self.work_available.clear()
                        break

                    # allocate current index to this thread
                    work["next_idx"] += 1
                    # debug counter
                    work["checked_since_dbg"] = work.get("checked_since_dbg", 0) + 1
                    checked_since_dbg = work["checked_since_dbg"]

                # perform guess and verification outside lock
                guess = idx_to_guess(next_idx)
                if verify_hash(work["hash"], guess):
                    print(f"[!!!] PASSWORD FOUND: idx={next_idx} guess={guess}")
                    res = {"type": "result", "found": True, "password": guess}
                    if username is not None:
                        res["username"] = username
                    self.safe_send(res)
                    # stop all threads
                    self.stop_event.set()
                    with self.work_lock:
                        self.current_work = None
                        self.work_available.clear()
                    return

                # debug printing: show occasional index->guess so we can see progress / repetition
                if self.debug and checked_since_dbg % self.dbg_interval == 0:
                    print(f"[debug] tested idx={next_idx} -> {guess} (thread {threading.current_thread().name})")

                # checkpoint / progress messages
                sent_progress = False
                if checkpoint_interval > 0:
                    # send progress if we've advanced at least checkpoint_interval since last_progress_sent
                    with self.work_lock:
                        last_sent = work.get("last_progress_sent", work["start_idx"])
                        if (next_idx - last_sent) >= checkpoint_interval:
                            # update shared last_progress_sent
                            work["last_progress_sent"] = next_idx
                            sent_progress = True

                    if sent_progress:
                        msg = {"type": "progress", "current": next_idx}
                        if username is not None:
                            msg["username"] = username
                        self.safe_send(msg)
                # loop continues until block exhausted or server stops us

            # finished block without finding password → request more work
            if not self.stop_event.is_set():
                time.sleep(0.01)  # tiny backoff to avoid tight loop
                self.safe_send({"type": "request_work"})

# -----------------------
# CLI / main
# -----------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host")
    parser.add_argument("--port", type=int)
    parser.add_argument("--threads", type=int, default=1)
    parser.add_argument("--debug", action="store_true", help="print debug progress during cracking")
    parser.add_argument("--dbg-interval", type=int, default=10000, help="debug print every N checks per block")
    parser.add_argument("--selftest", action="store_true", help="run local mapping test and exit")
    parser.add_argument("--count", type=int, default=7000, help="count for --selftest or --find")
    parser.add_argument("--find", type=str, help="find the index of this password within first --count indices")
    args = parser.parse_args()

    if args.selftest:
        selftest_print(args.count)
        return

    if args.find:
        idx = find_index_for_password(args.find, args.count)
        if idx is None:
            print(f"Password '{args.find}' not found in first {args.count} indices")
        else:
            print(f"Password '{args.find}' found at index {idx}")
        return

    # normal networked run:
    if not args.host or not args.port:
        print("For networked run you must provide --host and --port")
        return

    node = Node(args.host, args.port, args.threads, debug=args.debug, dbg_interval=args.dbg_interval)
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
        time.sleep(0.2)


if __name__ == "__main__":
    main()

