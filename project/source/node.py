#!/usr/bin/env python3
import argparse
import socket
import json
import multiprocessing as mp
import time
import threading
import sys
import crypt_r
from passlib.context import CryptContext

# -------------------------
# CONSTANTS
# -------------------------
LEGALCHAR = (
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#%^&*()_+-=.,:;?"
)

ctx = CryptContext(
    schemes=["bcrypt", "sha512_crypt", "sha256_crypt", "md5_crypt"],
    deprecated="auto",
)
_crypt_lock = mp.Lock()


# -------------------------
# HASH + BRUTE FORCE LOGIC
# -------------------------
def idx_to_guess(i, length):
    base = len(LEGALCHAR)
    chars = []
    for _ in range(length):
        chars.append(LEGALCHAR[i % base])
        i //= base
    return "".join(reversed(chars))


def verify_hash(hash_field, password_guess):
    if hash_field.startswith("$y$"):  # yescrypt
        try:
            with _crypt_lock:
                out = crypt_r.crypt(password_guess, hash_field)
        except Exception:
            return False
        if not out:
            return False
        return out == hash_field

    try:
        return ctx.verify(password_guess, hash_field)
    except Exception:
        return False


# -------------------------
# WORKER PROCESS
# -------------------------
def worker_process(start, end, length, hash_field, checkpoint_interval,
                   stop_flag, found_password, progress_counter, report_queue):
    """
    Each process brute-forces its assigned chunk.
    Sends checkpoint updates every N attempts.
    """

    for i in range(start, end):
        # Check global stop flag
        if stop_flag.value == 1:
            return

        password_guess = idx_to_guess(i, length)

        if verify_hash(hash_field, password_guess):
            with found_password.get_lock():
                found_password.value = 1
            report_queue.put({
                "type": "FOUND",
                "password": password_guess
            })
            return

        # checkpoint update
        with progress_counter.get_lock():
            progress_counter.value += 1
            if progress_counter.value % checkpoint_interval == 0:
                report_queue.put({
                    "type": "CHECKPOINT",
                    "attempts": progress_counter.value,
                    "last_index": i
                })


# -------------------------
# NETWORK THREAD
# -------------------------
def network_thread(sock, report_queue, stop_flag):
    """
    Continuously sends updates (CHECKPOINT, FOUND) to server.
    Receives STOP or NEW WORK from server.
    """

    while True:
        if stop_flag.value == 1:
            return

        try:
            msg = report_queue.get(timeout=0.1)
        except:
            continue

        try:
            sock.sendall((json.dumps(msg) + "\n").encode())
        except:
            stop_flag.value = 1
            return


# -------------------------
# MAIN CLIENT LOGIC
# -------------------------
def main():
    parser = argparse.ArgumentParser(description="Distributed Worker Node")
    parser.add_argument("--server", required=True, help="Server IP")
    parser.add_argument("--port", required=True, type=int, help="Server port")
    parser.add_argument("--threads", required=True, type=int, help="Worker processes")

    args = parser.parse_args()

    # Connect to server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((args.server, args.port))

    # Register
    sock.sendall(json.dumps({"type": "REGISTER"}) .encode() + b"\n")

    # Main loop waiting for assignments
    buffer = ""

    while True:
        data = sock.recv(4096)
        if not data:
            print("Disconnected from server.")
            return

        buffer += data.decode()
        while "\n" in buffer:
            line, buffer = buffer.split("\n", 1)

            if not line.strip():
                continue

            msg = json.loads(line)

            if msg["type"] == "ASSIGN_WORK":
                # Extract work
                start = msg["start"]
                end = msg["end"]
                length = msg["length"]
                checkpoint = msg["checkpoint"]
                hash_field = msg["hash"]

                # Shared state
                stop_flag = mp.Value('i', 0)
                found_password = mp.Value('i', 0)
                progress_counter = mp.Value('i', 0)

                report_queue = mp.Queue()

                # Launch worker processes
                procs = []
                chunk_size = (end - start) // args.threads
                for t in range(args.threads):
                    s = start + t * chunk_size
                    e = start + (t + 1) * chunk_size if t < args.threads - 1 else end

                    p = mp.Process(
                        target=worker_process,
                        args=(s, e, length, hash_field, checkpoint,
                              stop_flag, found_password, progress_counter, report_queue)
                    )
                    procs.append(p)
                    p.start()

                # Start network thread
                nt = threading.Thread(target=network_thread,
                                      args=(sock, report_queue, stop_flag),
                                      daemon=True)
                nt.start()

                # Wait for processes
                for p in procs:
                    p.join()

                # If we found the password, wait for server to confirm STOP
                if found_password.value == 1:
                    continue

                # Otherwise, notify server finished work
                sock.sendall(json.dumps({"type": "DONE"}).encode() + b"\n")

            elif msg["type"] == "STOP":
                print("Received STOP from server.")
                return


if __name__ == "__main__":
    main()

