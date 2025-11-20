import argparse
import socket
import threading
import json
import time
import sys

try:
    import crypt_r
except ImportError:
    crypt_r = None

from passlib.context import CryptContext

# === EXACT SAME CHARSET AND FUNCTION AS SERVER ===
CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#%^&*()_+-=.,:;?"
BASE = len(CHARS)

CTX = CryptContext(schemes=["bcrypt", "sha512_crypt", "sha256_crypt", "md5_crypt"], deprecated="auto")

def idx_to_password(idx: int) -> str:
    if idx == 0:
        return CHARS[0]
    pw = []
    while idx > 0:
        pw.append(CHARS[idx % BASE])
        idx //= BASE
    return "".join(reversed(pw))
# ================================================

def verify_hash(target: str, guess: str) -> bool:
    if target.startswith("$y$") and crypt_r:
        try:
            return crypt_r.crypt(guess, target) == target
        except:
            return False
    try:
        return CTX.verify(guess, target)
    except:
        return False


class Node:
    def __init__(self, server_ip: str, port: int, threads: int):
        self.server_ip = server_ip
        self.port = port
        self.threads = threads
        self.sock = None
        self.sock_lock = threading.Lock()
        self.work = None
        self.work_lock = threading.Lock()
        self.work_event = threading.Event()
        self.stop_event = threading.Event()

        for _ in range(threads):
            threading.Thread(target=self.worker, daemon=True).start()

    def connect(self):
        s = socket.socket()
        s.connect((self.server_ip, self.port))
        return s

    def send(self, msg: dict):
        data = json.dumps(msg).encode() + b"\n"
        with self.sock_lock:
            try:
                if self.sock:
                    self.sock.sendall(data)
            except:
                pass

    def run(self):
        while not self.stop_event.is_set():
            try:
                print(f"[*] Connecting to {self.server_ip}:{self.port}...")
                self.sock = self.connect()
                print("[+] Connected")
                self.send({"type": "register"})
                self.send({"type": "request_work"})
                threading.Thread(target=self.reader, daemon=True).start()
                while not self.stop_event.is_set():
                    time.sleep(1)
            except Exception as e:
                print(f"[!] Error: {e}")
                with self.sock_lock:
                    if self.sock: self.sock.close(); self.sock = None
                time.sleep(3)

    def reader(self):
        buf = b""
        while not self.stop_event.is_set():
            try:
                data = self.sock.recv(4096)
                if not data: break
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if not line.strip(): continue
                    msg = json.loads(line)
                    self.handle(msg)
            except: break
        self.stop_event.set()

    def handle(self, msg: dict):
        typ = msg.get("type")
        if typ == "work":
            with self.work_lock:
                self.work = {
                    "start": msg["start_idx"],
                    "end": msg["end_idx"],
                    "hash": msg["hash"],
                    "cp_every": msg.get("checkpoint_every", 0),
                    "next": msg["start_idx"],
                    "last_cp": msg["start_idx"] - 1
                }
                self.work_event.set()
            print(f"[+] Work: {msg['start_idx']:,} → {msg['end_idx']:,}")
        elif typ == "stop":
            print("[!] Password found elsewhere — stopping")
            self.stop_event.set()

    def worker(self):
        while not self.stop_event.is_set():
            self.work_event.wait(1)
            if self.stop_event.is_set(): break

            work = None
            with self.work_lock:
                if self.work:
                    work = self.work.copy()

            if not work: continue

            while work["next"] < work["end"]:
                if self.stop_event.is_set(): return
                idx = work["next"]
                with self.work_lock:
                    if not self.work or self.work["next"] != idx + 1:
                        break
                    self.work["next"] += 1

                guess = idx_to_password(idx)
                if verify_hash(work["hash"], guess):
                    print(f"\n[!!!] CRACKED: {guess}\n")
                    self.send({"type": "result", "found": True, "password": guess})
                    self.stop_event.set()
                    return

                if work["cp_every"] and (idx - work["last_cp"]) >= work["cp_every"]:
                    with self.work_lock:
                        if self.work: self.work["last_cp"] = idx
                    self.send({"type": "checkpoint", "last_checked": idx})

            # Block done → request more
            if not self.stop_event.is_set():
                self.send({"type": "request_work"})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--threads", type=int, default=4)
    args = parser.parse_args()

    Node(args.server, args.port, args.threads).run()


if __name__ == "__main__":
    main()
