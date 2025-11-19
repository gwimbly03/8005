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
CALLBACK_PORT = 6000

ctx = CryptContext(schemes=["bcrypt", "sha512_crypt", "sha256_crypt", "md5_crypt"], deprecated="auto")
_crypt_lock = mp.Lock()

def idx_to_guess(idx):
    s = ""
    i = idx
    while i > 0 or not s:            # ensure we generate at least one char
        s = LEGALCHAR[i % len(LEGALCHAR)] + s
        i //= len(LEGALCHAR)
    return s[:5].rjust(5, LEGALCHAR[0])   # exactly length ≤5

def verify_hash(h, guess):
    if h.startswith("$y$"):  # yescrypt
        with _crypt_lock:
            return crypt_r.crypt(guess, h) == h
    try:
        return ctx.verify(guess, h)
    except:
        return False

def worker(start, end, hashes, checkpoint, stop_flag, found_flag, progress, q):
    for i in range(start, end):
        if stop_flag.value or found_flag.value:
            return
        guess = idx_to_guess(i)
        for h in hashes:
            if verify_hash(h, guess):
                found_flag.value = 1
                q.put({"type": "found", "password": guess})
                return
        progress.value += 1
        if progress.value % checkpoint == 0:
            q.put({"type": "checkpoint", "attempts": progress.value, "last_index": i})

def sender(sock, q, stop_flag):
    while not stop_flag.value:
        try:
            msg = q.get(timeout=0.5)
            sock.sendall((json.dumps(msg) + "\n").encode())
        except:
            pass

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--threads", type=int, default=mp.cpu_count())
    args = parser.parse_args()

    # Listen for callback
    listener = socket.socket()
    listener.bind(("0.0.0.0", CALLBACK_PORT))
    listener.listen(1)
    print(f"[NODE] Waiting for callback on port {CALLBACK_PORT}")

    # Register
    reg = socket.socket()
    reg.connect((args.server, args.port))
    reg.sendall(json.dumps({"type": "register", "callback_port": CALLBACK_PORT}).encode() + b"\n")
    reg.close()

    cb_sock, _ = listener.accept()
    print("[NODE] Server connected back")
    listener.close()

    while True:
        cb_sock.sendall(json.dumps({"type": "work_request"}).encode() + b"\n")

        buffer = ""
        while "\n" not in buffer:
            data = cb_sock.recv(4096)
            if not data:
                print("[NODE] Server gone")
                return
            buffer += data.decode()
        line, buffer = buffer.split("\n", 1)
        msg = json.loads(line)

        if msg["type"] == "no_work":
            time.sleep(2)
            continue
        if msg["type"] == "cancel":
            print("[NODE] Password already found – stopping")
            return
        if msg["type"] == "work":
            start, end = msg["start"], msg["end"]
            hashes = msg["hash"] if isinstance(msg["hash"], list) else [msg["hash"]]
            checkpoint = msg["checkpoint"]
            print(f"[NODE] Cracking {start:,} → {end:,}")

            stop_flag = mp.Value('i', 0)
            found_flag = mp.Value('i', 0)
            progress = mp.Value('i', 0)
            q = mp.Queue()

            procs = []
            chunk_size = (end - start) // args.threads
            for i in range(args.threads):
                s = start + i * chunk_size
                e = end if i == args.threads - 1 else start + (i + 1) * chunk_size
                p = mp.Process(target=worker, args=(s, e, hashes, checkpoint, stop_flag, found_flag, progress, q))
                procs.append(p)
                p.start()

            threading.Thread(target=sender, args=(cb_sock, q, stop_flag), daemon=True).start()

            for p in procs:
                p.join()

            if found_flag.value:
                time.sleep(2)  # let final messages go out

if __name__ == "__main__":
    main()
