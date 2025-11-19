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

# -------------------------
# CONSTANTS
# -------------------------
LEGALCHAR = (
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#%^&*()_+-=.,:;?"
)

CALLBACK_PORT = 6000   # <----- HARD‑CODED CALLBACK PORT

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
def worker_process(start, end, length, hash_list, checkpoint_interval,
                   stop_flag, found_password, progress_counter, report_queue):

    for i in range(start, end):
        if stop_flag.value == 1:
            return

        password_guess = idx_to_guess(i, length)

        for h in hash_list:
            if verify_hash(h, password_guess):
                with found_password.get_lock():
                    found_password.value = 1
                report_queue.put({"type": "found", "password": password_guess})
                return

        # checkpoint
        with progress_counter.get_lock():
            progress_counter.value += 1
            if progress_counter.value % checkpoint_interval == 0:
                report_queue.put({
                    "type": "checkpoint",
                    "attempts": progress_counter.value,
                    "last_index": i
                })


# -------------------------
# NETWORK SENDER THREAD
# -------------------------
def send_updates(sock, report_queue, stop_flag):
    """ Sends checkpoint/found messages back to the server. """
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
# MAIN NODE FUNCTION
# -------------------------
def main():
    parser = argparse.ArgumentParser(description="Distributed Worker Node")
    parser.add_argument("--server", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--threads", required=True, type=int)
    args = parser.parse_args()

    # -----------------------------------------
    # 1. Listen for callback from server
    # -----------------------------------------
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("0.0.0.0", CALLBACK_PORT))
    listener.listen(1)

    print(f"[NODE] Listening for server callback on port {CALLBACK_PORT}")

    # -----------------------------------------
    # 2. Connect to server and register
    # -----------------------------------------
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.connect((args.server, args.port))

    reg_msg = {
        "type": "register",
        "callback_port": CALLBACK_PORT
    }
    server_sock.sendall((json.dumps(reg_msg) + "\n").encode())

    print("[NODE] Registered with server, waiting for callback connection...")

    # -----------------------------------------
    # 3. Wait for server to connect back
    # -----------------------------------------
    callback_conn, callback_addr = listener.accept()
    print(f"[NODE] Server callback connection established from {callback_addr}")

    buffer = ""

    while True:
        # Ask for work
        callback_conn.sendall(json.dumps({"type": "work_request"}).encode() + b"\n")

        data = callback_conn.recv(4096)
        if not data:
            print("[NODE] Server disconnected.")
            return

        buffer += data.decode()

        # process all messages
        while "\n" in buffer:
            line, buffer = buffer.split("\n", 1)
            if not line.strip():
                continue

            msg = json.loads(line)
            mtype = msg.get("type")

            if mtype == "no_work":
                print("[NODE] No work available. Will ask again.")
                time.sleep(1)
                continue

            if mtype == "cancel":
                print("[NODE] Cancel received. Stopping.")
                return

            if mtype == "work":
                start = msg["start"]
                end = msg["end"]
                hash_list = msg["hash"]      # list from the server
                checkpoint = msg["checkpoint"]

                print(f"[NODE] Received work: {start} → {end}")

                # multiprocess states
                stop_flag = mp.Value('i', 0)
                found_password = mp.Value('i', 0)
                progress_counter = mp.Value('i', 0)
                report_queue = mp.Queue()

                # Launch workers
                procs = []
                chunk = (end - start) // args.threads
                for t in range(args.threads):
                    s = start + t * chunk
                    e = start + (t + 1) * chunk if t < args.threads - 1 else end

                    p = mp.Process(
                        target=worker_process,
                        args=(s, e, 5, hash_list, checkpoint,
                              stop_flag, found_password, progress_counter, report_queue)
                    )
                    procs.append(p)
                    p.start()

                # network sender
                net_thread = threading.Thread(target=send_updates,
                                              args=(callback_conn, report_queue, stop_flag),
                                              daemon=True)
                net_thread.start()

                # wait for workers
                for p in procs:
                    p.join()

                if found_password.value == 1:
                    # send FOUND confirmation ends loop; server stops everyone
                    continue

                # Work completed, request more
                continue


if __name__ == "__main__":
    main()

