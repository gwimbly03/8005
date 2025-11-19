#!/usr/bin/env python3
import argparse
import socket
import json
import multiprocessing as mp
import threading
import time
import sys

LEGALCHAR = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#%^&*()_+-=.,:;?"
CALLBACK_PORT = 6000

from passlib.context import CryptContext
import crypt_r  # assuming you have this

ctx = CryptContext(schemes=["bcrypt", "sha512_crypt", "sha256_crypt", "md5_crypt", "yescrypt"], deprecated="auto")
_crypt_lock = mp.Lock()

def idx_to_guess(i):
    """ Convert integer to password using LEGALCHAR as base """
    s = ""
    while i > 0 or not s:  # ensure at least one char
        s = LEGALCHAR[i % len(LEGALCHAR)] + s
        i //= len(LEGALCHAR)
    return s.rjust(5, LEGALCHAR[0])[:5]  # pad/truncate to length 5

def verify_hash(h, guess):
    if h.startswith("$y$"):
        with _crypt_lock:
            return crypt_r.crypt(guess, h) == h
    try:
        return ctx.verify(guess, h)
    except:
        return False

def worker(start, end, hashes, checkpoint, stop_flag, found_flag, progress, report_q):
    for idx in range(start, end):
        if stop_flag.value or found_flag.value:
            return
        guess = idx_to_guess(idx)
        for h in hashes:
            if verify_hash(h, guess):
                found_flag.value = 1
                report_q.put({"type": "found", "password": guess})
                return
        progress.value += 1
        if progress.value % checkpoint == 0:
            report_q.put({"type": "checkpoint", "attempts": progress.value, "last_index": idx})

def sender(sock, report_q, stop_flag):
    while not stop_flag.value:
        try:
            msg = report_q.get(timeout=0.5)
            sock.sendall((json.dumps(msg) + "\n").encode())
        except:
            break

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--threads", type=int, default=4)
    args = parser.parse_args()

    # 1. Start callback listener
    listener = socket.socket()
    listener.bind(("0.0.0.0", CALLBACK_PORT))
    listener.listen(1)
    print(f"[NODE] Listening for callback on :{CALLBACK_PORT}")

    # 2. Register
    reg_sock = socket.socket()
    reg_sock.connect((args.server, args.port))
    reg_sock.sendall(json.dumps({"type": "register", "callback_port": CALLBACK_PORT}).encode() + b"\n")
    reg_sock.close()

    # 3. Accept callback
    cb_sock, _ = listener.accept()
    print("[NODE] Server connected back")
    listener.close()

    while True:
        cb_sock.sendall(json.dumps({"type": "work_request"}).encode() + b"\n")

        buffer = ""
        msg = None
        while True:
            data = cb_sock.recv(4096)
            if not data:
                print("[NODE] Server died")
                return
            buffer += data.decode()
            if "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                msg = json.loads(line)
                break

        typ = msg["type"]
        if typ == "no_work":
            time.sleep(2)
            continue
        if typ == "cancel":
            print("[NODE] Password found elsewhere — stopping")
            return
        if typ == "work":
            start = msg["start"]
            end = msg["end"]
            hashes = msg["hash"] if isinstance(msg["hash"], list) else [msg["hash"]]
            checkpoint = msg["checkpoint"]
            print(f"[NODE] Working on {start:,} → {end:,}")

            stop_flag = mp.Value('i', 0)
            found_flag = mp.Value('i', 0)
            progress = mp.Value('i', 0)
            report_q = mp.Queue()

            procs = []
            chunk = (end - start) // args.threads
            for i in range(args.threads):
                s = start + i * chunk
                e = end if i == args.threads - 1 else start + (i + 1) * chunk
                p = mp.Process(target=worker, args=(s, e, hashes, checkpoint, stop_flag, found_flag, progress, report_q))
                procs.append(p)
                p.start()

            sender_thread = threading.Thread(target=sender, args=(cb_sock, report_q, stop_flag))
            sender_thread.start()

            # Wait
            for p in procs:
                p.join()

            if found_flag.value:
                print("[NODE] We found it! Waiting for ack...")
                time.sleep(2)  # give time to send 'found'
            # Work done → loop and ask for more

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
