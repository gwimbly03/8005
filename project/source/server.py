#!/usr/bin/env python3
import argparse
import json
import socket
import threading
import time

work_lock = threading.Lock()

work_queue = []          # (start, end)
active_nodes = {}        # node_id -> timestamp of last checkpoint
node_work = {}           # node_id -> (start, end)
password_found = False


def send_json(conn, data):
    conn.sendall((json.dumps(data) + "\n").encode())


def receive_json(conn):
    line = conn.recv(4096).decode().strip()
    if not line:
        return None
    return json.loads(line)


def handle_node(conn, addr, args):
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

                send_json(conn, {
                    "type": "work",
                    "start": start,
                    "end": end,
                    "hash": args.hash,
                    "checkpoint": args.checkpoint
                })

            elif mtype == "checkpoint":
                with work_lock:
                    active_nodes[node_id] = time.time()
                # No response needed

            elif mtype == "found":
                print(f"[!!!] PASSWORD FOUND by {node_id}: {msg['password']}")
                with work_lock:
                    password_found = True

                # Tell ALL nodes to stop
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--hash", required=True)
    parser.add_argument("--work-size", type=int, required=True)
    parser.add_argument("--checkpoint", type=int, required=True)
    parser.add_argument("--timeout", type=int, required=True)
    args = parser.parse_args()

    # Initialize brute-force search space: range 0 -> 26^5 or however large
    print("[*] Generating work segments...")
    MAX = 26 ** 5  # You can change this
    for i in range(0, MAX, args.work_size):
        work_queue.append((i, min(i + args.work_size, MAX)))

    print(f"[*] Total work segments: {len(work_queue)}")

    # Start timeout monitor
    threading.Thread(target=timeout_monitor, args=(args,), daemon=True).start()

    # Start server
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", args.port))
    server.listen()

    print(f"[SERVER] Running on port {args.port}")

    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_node, args=(conn, addr, args), daemon=True).start()


if __name__ == "__main__":
    main()

