import argparse
import json
import socket
import threading
import time
import os

work_lock = threading.Lock()

work_queue = []          # (start, end)
active_nodes = {}        # node_id -> timestamp of last checkpoint
node_work = {}           # node_id -> (start, end)
password_found = False


# -----------------------------------------------------------
# JSON Communication
# -----------------------------------------------------------
def send_json(conn, data):
    conn.sendall((json.dumps(data) + "\n").encode())


def receive_json(conn):
    line = conn.recv(4096).decode().strip()
    if not line:
        return None
    return json.loads(line)


# -----------------------------------------------------------
# HASH / SHADOW FILE HANDLING
# -----------------------------------------------------------
def load_hash_or_shadow(arg):
    """
    If --hash argument is a file, treat it as a shadow file.
    Otherwise, treat it as a single hash string.
    Returns a list of hashes.
    """
    if os.path.isfile(arg):
        print(f"[*] Detected shadow file: {arg}")
        hashes = []
        with open(arg, "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 2:
                    h = parts[1]
                    if h not in ("", "*", "!"):
                        hashes.append(h)
        print(f"[*] Loaded {len(hashes)} hashes from shadow file")
        return hashes

    # Otherwise treat arg as a plain hash string
    print("[*] Using single hash mode")
    return [arg]


# -----------------------------------------------------------
# NODE HANDLER THREAD
# -----------------------------------------------------------
def handle_node(conn, addr, args, hashes):
    global password_found

    node_id = f"{addr[0]}:{addr[1]}"
    print(f"[+] Node connected: {node_id}")

    try:
        # Register node
        with work_lock:
            active_nodes[node_id] = time.time()

        # Main loop
        while True:
            msg = receive_json(conn)
            if msg is None:
                print(f"[!] Node disconnected: {node_id}")
                break

            mtype = msg["type"]

            # Worker requests work
            if mtype == "work_request":
                with work_lock:
                    if password_found:
                        send_json(conn, {"type": "cancel"})
                        continue

                    if len(work_queue) == 0:
                        send_json(conn, {"type": "no_work"})
                        continue

                    start, end = work_queue.pop(0)
                    node_work[node_id] = (start, end)

                # Send work + ALL hashes (even if only one)
                send_json(conn, {
                    "type": "work",
                    "start": start,
                    "end": end,
                    "hash": hashes,          # NOW A LIST
                    "checkpoint": args.checkpoint
                })

            # Worker heartbeat / checkpoint
            elif mtype == "checkpoint":
                with work_lock:
                    active_nodes[node_id] = time.time()
                # No reply needed

            # Worker found the password
            elif mtype == "found":
                print(f"[!!!] PASSWORD FOUND by {node_id}: {msg['password']}")
                with work_lock:
                    password_found = True

                send_json(conn, {"type": "ack"})
                break

    except Exception as e:
        print(f"[ERROR] Node {node_id} crashed: {e}")

    finally:
        # Cleanup and return unfinished work
        with work_lock:
            if node_id in node_work:
                print(f"[!] Reclaiming unfinished work from {node_id}")
                work_queue.append(node_work[node_id])
                del node_work[node_id]
            if node_id in active_nodes:
                del active_nodes[node_id]

        conn.close()
        print(f"[X] Node connection closed: {node_id}")


# -----------------------------------------------------------
# TIMEOUT MONITOR THREAD
# -----------------------------------------------------------
def timeout_monitor(args):
    global password_found

    while not password_found:
        time.sleep(2)
        now = time.time()

        with work_lock:
            dead_nodes = []
            for node_id, last in active_nodes.items():
                if now - last > args.timeout:
                    print(f"[TIMEOUT] Node died: {node_id}")
                    dead_nodes.append(node_id)

            for node_id in dead_nodes:
                if node_id in node_work:
                    print(f"[!] Returning unfinished work from {node_id}")
                    work_queue.append(node_work[node_id])
                    del node_work[node_id]
                del active_nodes[node_id]


# -----------------------------------------------------------
# MAIN
# -----------------------------------------------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--hash", required=True)  # unchanged, now supports file OR hash
    parser.add_argument("--work-size", type=int, required=True)
    parser.add_argument("--checkpoint", type=int, required=True)
    parser.add_argument("--timeout", type=int, required=True)
    args = parser.parse_args()

    # Load either single hash OR entire shadow file
    hashes = load_hash_or_shadow(args.hash)

    # Initialize brute-force search space
    print("[*] Generating work segments...")
    MAX = 26 ** 5
    for i in range(0, MAX, args.work_size):
        work_queue.append((i, min(i + args.work_size, MAX)))

    print(f"[*] Total work segments: {len(work_queue)}")

    # Start timeout monitor
    threading.Thread(target=timeout_monitor, args=(args,), daemon=True).start()

    # Start server
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", args.port))
    server.listen()

    print(f"Running on port {args.port}")

    while True:
        conn, addr = server.accept()
        threading.Thread(
            target=handle_node,
            args=(conn, addr, args, hashes),
            daemon=True
        ).start()


if __name__ == "__main__":
    main()

