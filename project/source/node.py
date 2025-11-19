#!/usr/bin/env python3
import argparse
import socket
import json
import multiprocessing as mp
import threading
import time
import sys
import crypt_r
from passlib.context import CryptContext

LEGALCHAR = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#%^&*()_+-=.,:;?"
ctx = CryptContext(schemes=["bcrypt", "sha512_crypt", "sha256_crypt", "md5_crypt"], deprecated="auto")
_lock = mp.Lock()

def idx_to_guess(n):
    s = ""
    while n > 0 or not s:
        s = LEGALCHAR[n % 95] + s
        n //= 95
    return (s + LEGALCHAR[0]*5)[:5]

def check(guess, hashes):
    for h in hashes:
        if h.startswith("$y$"):
            with _lock:
                if crypt_r.crypt(guess, h) == h:
                    return True
        elif ctx.verify(guess, h):
            return True
    return False

def worker(start, end, hashes, checkpoint, found, q):
    attempts = 0
    for i in range(start, end):
        if found.value:
            return
        guess = idx_to_guess(i)
        if check(guess, hashes):
            found.value = 1
            q.put({"type": "found", "password": guess})
            return
        attempts += 1
        if attempts % checkpoint == 0:
            q.put({"type": "checkpoint", "attempts": attempts, "last_index": i})

def sender(sock, q):
    while True:
        try:
            msg = q.get(timeout=1)
            sock.sendall(json.dumps(msg).encode() + b"\n")
            if msg["type"] == "found":
                return
        except:
            return

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--server", required=True)
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--threads", type=int, default=mp.cpu_count())
    args = p.parse_args()

    while True:
        try:
            s = socket.socket()
            s.connect((args.server, args.port))
            print(f"[NODE] Connected to {args.server}:{args.port}")
            break
        except:
            time.sleep(3)

    while True:
        try:
            buf = s.recv(4096).decode()
            if not buf:
                raise Exception("empty")
            msg = json.loads(buf.strip().split("\n")[0])
        except:
            print("[NODE] Disconnected – reconnecting...")
            s.close()
            time.sleep(3)
            return main()

        if msg["type"] == "cancel":
            print("[NODE] Password found elsewhere – goodbye!")
            return

        start, end = msg["start"], msg["end"]
        hashes = msg["hash"] if isinstance(msg["hash"], list) else [msg["hash"]]
        chk = msg["checkpoint"]
        print(f"[NODE] → {start:,} .. {end-1:,}")

        found = mp.Value('i', 0)
        q = mp.Queue()
        procs = []
        step = (end - start) // args.threads
        for i in range(args.threads):
            lo = start + i * step
            hi = end if i == args.threads - 1 else start + (i + 1) * step
            p = mp.Process(target=worker, args=(lo, hi, hashes, chk, found, q))
            procs.append(p)
            p.start()

        threading.Thread(target=sender, args=(s, q), daemon=True).start()

        for p in procs:
            p.join()

        if found.value:
            time.sleep(2)  # let "found" message go out
            return

if __name__ == "__main__":
    main()
