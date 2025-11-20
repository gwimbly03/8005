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
    if idx == 0:
        return CHARS[0]
    out = []
    while idx > 0:
        out.append(CHARS[idx % BASE])
        idx //= BASE
    return "".join(reversed(out))

def verify_hash(hash_field: str, guess: str) -> bool:
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


class Node:
    def __init__(self, host: str, port: int, threads: int):
        self.host = host
        self.port = port
        self.threads = threads

        self.sock = None
        self.sock_lock = threading.Lock()

        self.current_work = None
        self.work_lock = threading.Lock()
        self.work_available = threading.Event()

        self.stop_event = threading.Event()

        self.workers = []
        for i in range(self.threads):
            t = threading.Thread(target=self.worker_loop, daemon=True)
            t.start()
            self.workers.append(t)

    def connect(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(10)
        s.connect((self.host, self.port))
        s.settimeout(None)
        return s

    def safe_send(self, obj: dict):
        data = (json.dumps(obj) + "\n").encode()
        with self.sock_lock:
            try:
                if self.sock is None:
                    return False
                self.sock.sendall(data)
                return True
            except Exception as e:
                print(f"Send error: {e}")
                return False

    def run(self):
        while not self.stop_event.is_set():
            try:
                print(f"Connecting to server {self.host}:{self.port} ...")
                self.sock = self.connect()
                print("Connected")

                self.safe_send({"type": "register", "threads": self.threads})
                self.safe_send({"type": "request_work"})

                self.reader_loop()

            except Exception as e:
                print(f"Connection error: {e}")
                with self.work_lock:
                    self.current_work = None
                    self.work_available.clear()
                time.sleep(2)

            finally:
                with self.sock_lock:
                    if self.sock:
                        try:
                            self.sock.close()
                        except:
                            pass
                    self.sock = None

    def reader_loop(self):
        buf = b""
        while not self.stop_event.is_set():
            try:
                data = self.sock.recv(4096)
                if not data:
                    print("Server closed connection")
                    break
                buf += data

                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if not line:
                        continue
                    try:
                        msg = json.loads(line.decode())
                    except Exception:
                        continue
                    self.handle_message(msg)

            except Exception as e:
                print(f"Reader error: {e}")
                break

    def handle_message(self, msg: dict):
        tp = msg.get("type")

        if tp == "work":
            start = int(msg["start_idx"])
            end = int(msg["end_idx"])
            h = msg.get("hash", "")

            timeout = msg.get("timeout", 600)
            checkpoint = msg.get("checkpoint", 0)

            if end <= start:
                self.safe_send({"type": "request_work"})
                return

            with self.work_lock:
                self.current_work = {
                    "start_idx": start,
                    "end_idx": end,
                    "hash": h,
                    "next_idx": start,
                    "assigned_time": time.time(),
                    "timeout": timeout,
                    "checkpoint": checkpoint,
                }
                self.work_available.set()

            print(f"New work assigned: [{start:,}..{end:,}) timeout={timeout}s checkpoint={checkpoint}")

        elif tp == "stop":
            print("[!] Stop received from server")
            self.stop_event.set()
            with self.work_lock:
                self.current_work = None
                self.work_available.clear()

        elif tp == "result_ack":
            pass

        else:
            print(f"Unknown message: {msg}")

    def worker_loop(self):
        while not self.stop_event.is_set():
            if not self.work_available.wait(timeout=1.0):
                continue

            with self.work_lock:
                work = self.current_work
                if work is None:
                    continue

            while True:
                if self.stop_event.is_set():
                    return

                with self.work_lock:
                    if self.current_work is not work:
                        break

                    # TIMEOUT LOGIC
                    if time.time() - work["assigned_time"] >= work["timeout"]:
                        print("[!] Work timeout reached — requesting new work")
                        self.current_work = None
                        self.work_available.clear()
                        break

                    next_idx = work["next_idx"]
                    if next_idx >= work["end_idx"]:
                        self.current_work = None
                        self.work_available.clear()
                        break

                    work["next_idx"] += 1

                guess = idx_to_guess(next_idx)
                ok = verify_hash(work["hash"], guess)

                # CHECKPOINT LOGIC
                if work["checkpoint"] > 0:
                    if (next_idx - work["start_idx"]) % work["checkpoint"] == 0:
                        print(f"[Checkpoint] Worker reached index {next_idx:,}")
                        self.safe_send({"type": "checkpoint", "idx": next_idx})

                if ok:
                    print(f"Password found: {guess}")
                    self.safe_send({"type": "result", "found": True, "password": guess})
                    self.stop_event.set()
                    return

            if not self.stop_event.is_set():
                self.safe_send({"type": "request_work"})


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
        print("KeyboardInterrupt — shutting down")
        node.stop_event.set()


if __name__ == "__main__":
    main()

