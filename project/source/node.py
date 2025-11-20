import argparse
import socket
import threading
import json
import time
import sys
import threading

# Atomic brute-force index
global_counter = 0
counter_lock = threading.Lock()

# Character set
CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:',.<>?/`~"
BASE = len(CHARS)

try:
    import crypt_r
except Exception:
    crypt_r = None

from passlib.context import CryptContext


CTX = CryptContext(
    schemes=["bcrypt", "sha512_crypt", "sha256_crypt", "md5_crypt"],
    deprecated="auto",
)

def idx_to_password(idx: int) -> str:
    """
    Converts a monotonic index (0,1,2,3...) into a brute-force password.
    This method produces:
    a, b, c, ..., ?, aa, ab, ac, ..., aaa, aab, ...
    with NO max length.
    """
    length = 1
    count = BASE  # number of passwords of length 1

    # Determine which password length this index falls into
    while idx >= count:
        idx -= count
        length += 1
        count *= BASE  # BASE^length

    # Now idx is within this length; decode in base-N with fixed digits
    out = []
    for _ in range(length):
        out.append(CHARS[idx % BASE])
        idx //= BASE

    return "".join(reversed(out))

def get_next_password() -> tuple[int, str]:
    global global_counter

    with counter_lock:
        idx = global_counter
        global_counter += 1

    return idx, idx_to_password(idx)

def verify_hash(hash_field: str, guess: str) -> bool:
    if not hash_field:
        return False
    if hash_field.startswith("$y$"):
        if crypt_r is None:
            return False
        try:
            return crypt_r.crypt(guess, hash_field) == hash_field
        except Exception:
            return False
    try:
        return CTX.verify(guess, hash_field)
    except Exception:
        return False

class Node:
    def __init__(self, server_ip: str, port: int, threads: int):
        self.server_ip = server_ip
        self.port = port
        self.threads = threads

        self.sock = None
        self.sock_lock = threading.Lock()

        self.current_work = None
        self.work_lock = threading.Lock()
        self.work_event = threading.Event()

        self.stop_event = threading.Event()

        # Start worker threads
        self.workers = []
        for i in range(threads):
            t = threading.Thread(target=self.worker, daemon=True)
            t.start()
            self.workers.append(t)

    def connect(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.connect((self.server_ip, self.port))
        return s

    def send(self, msg: dict):
        data = json.dumps(msg).encode() + b"\n"
        with self.sock_lock:
            try:
                if self.sock:
                    self.sock.sendall(data)
                    return True
            except:
                pass
        return False

    def run(self):
        while not self.stop_event.is_set():
            try:
                print(f"[*] Connecting to {self.server_ip}:{self.port}...")
                self.sock = self.connect()
                print("[+] Connected!")

                self.send({"type": "register"})
                self.send({"type": "request_work"})

                threading.Thread(target=self.reader, daemon=True).start()

                while not self.stop_event.is_set() and self.sock:
                    time.sleep(0.5)

            except Exception as e:
                print(f"[!] Connection error: {e}")
                with self.sock_lock:
                    if self.sock:
                        self.sock.close()
                        self.sock = None
                time.sleep(3)


    def reader(self):
        buf = b""
        while not self.stop_event.is_set():
            try:
                data = self.sock.recv(4096)
                if not data:
                    break
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if not line.strip():
                        continue
                    try:
                        msg = json.loads(line)
                        self.handle_server_msg(msg)
                    except json.JSONDecodeError:
                        continue
            except:
                break
        print("[!] Server disconnected")
        self.stop_event.set()

    def handle_server_msg(self, msg: dict):
        typ = msg.get("type")

        if typ == "work":
            start = msg["start_idx"]
            end = msg["end_idx"]
            h = msg["hash"]
            checkpoint_every = msg.get("checkpoint_every", 0)

            with self.work_lock:
                self.current_work = {
                    "start": int(start),
                    "end": int(end),
                    "hash": h,
                    "checkpoint_every": int(checkpoint_every),
                    "next_idx": int(start),
                    "last_checkpoint_idx": int(start) - 1
                }
                self.work_event.set()

            print(f"[+] Work received: {start:,} → {end:,}")
        
        elif typ == "stop":
            print("[!] STOP signal received")
            self.stop_event.set()
            with self.work_lock:
                self.current_work = None
                self.work_event.clear()


    def worker(self):
        while not self.stop_event.is_set():

            # Wait for work
            self.work_event.wait(timeout=1)
            if self.stop_event.is_set():
                break

            work = None
            with self.work_lock:
                if self.current_work:
                    work = self.current_work.copy()

            if not work:
                continue

            # ---- Crack the chunk ----
            while not self.stop_event.is_set():
                with self.work_lock:
                    if self.current_work != work or self.current_work is None:
                        break

                    idx = self.current_work["next_idx"]
                    if idx >= work["end"]:
                        # Done this block
                        self.current_work = None
                        self.work_event.clear()
                        break

                    self.current_work["next_idx"] += 1

                guess = idx_to_guess(idx)

                if verify_hash(work["hash"], guess):
                    print(f"\n[!!!] PASSWORD FOUND: {guess}\n")
                    self.send({"type": "result", "found": True, "password": guess})
                    self.stop_event.set()
                    return

                # Send checkpoint if needed
                if work["checkpoint_every"] > 0:
                    if (idx - work["last_checkpoint_idx"]) >= work["checkpoint_every"]:
                        self.send({"type": "checkpoint", "last_checked": idx})
                        with self.work_lock:
                            if self.current_work:
                                self.current_work["last_checkpoint_idx"] = idx
                        print(f"[✓] Checkpoint @ {idx:,}")

            # ---- Finished → ask server for more work ----
            if not self.stop_event.is_set():
                self.send({"type": "request_work"})

def main():
    parser = argparse.ArgumentParser(description="Distributed Cracker - Worker Node")
    parser.add_argument("--server", type=str, required=True, help="Server IP address")
    parser.add_argument("--port", type=int, default=5000, help="Server port")
    parser.add_argument("--threads", type=int, default=4, help="Number of cracking threads")
    args = parser.parse_args()

    print(f"[*] Starting worker → {args.server}:{args.port} | threads: {args.threads}")

    node = Node(args.server, args.port, args.threads)
    try:
        node.run()
    except KeyboardInterrupt:
        print("\n[!] Shutting down...")
        node.stop_event.set()

if __name__ == "__main__":
    main()
