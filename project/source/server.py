#!/usr/bin/env python3
import argparse
import json
import socket
import threading
import time

work_lock = threading.Lock()
active_nodes = {}          # node_id → last checkpoint time
node_work = {}             # node_id → (start, end)
callback_sockets = {}      # node_id → socket
password_found = False
found_password = None

# Lazy counter — replaces the giant pre-filled list
next_index = 0

def get_next_work_unit(work_size):
    global next_index
    with work_lock:
        start = next_index
        end = start + work_size
        next_index = end
        return start, end

def send_json(conn, data):
    try:
        conn.sendall((json.dumps(data) + "\n").encode())
    except:
        pass

def receive_json(conn):
    try:
        line = conn.recv(4096).decode().strip()
        if not line:
            return None
        return json.loads(line)
    except:
        return None

def handle_node(register_conn, addr, args):
    global password_found, found_password
    node_id = f"{addr[0]}:{addr[1]}"
    print(f"[+] Node registered: {node_id}")

    msg = receive_json(register_conn)
    if not msg or msg.get("type") != "register":
        register_conn.close()
        return

    callback_port = msg["callback_port"]
    register_conn.close()

    # Callback to the node
    cb_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        cb_sock.connect((addr[0], callback_port))
        print(f"[+] Callback connected to {node_id}")
    except Exception as e:
        print(f"[!] Callback failed for {node_id}: {e}")
        return

    with work_lock:
        active_nodes[node_id] = time.time()
        callback_sockets[node_id] = cb_sock

    try:
        while not password_found:
            msg = receive_json(cb_sock)
            if msg is None:
                break

            with work_lock:
                active_nodes[node_id] = time.time()

            if msg["type"] == "work_request":
                if password_found:
                    send_json(cb_sock, {"type": "cancel"})
                    continue

                start, end = get_next_work_unit(args.work_size)
                node_work[node_id] = (start, end)
                print(f"[WORK] Assigned {start:,} → {end:,} to {node_id}")

                send_json(cb_sock, {
                    "type": "work",
                    "start": start,
                    "end": end,
                    "hash": args.hash,            # list of hashes
                    "checkpoint": args.checkpoint
                })

            elif msg["type"] == "checkpoint":
                print(f"[CHECKPOINT] {node_id} → index {msg.get('last_index', '?'):,} "
                      f"({msg.get('attempts', 0):,} attempts)")

            elif msg["type"] == "found":
                pw = msg["password"]
                print(f"\n[!!!] PASSWORD FOUND by {node_id}: {pw}\n")
                found_password = pw
                password_found = True
                send_json(cb_sock, {"type": "ack"})

                # Tell everyone else to stop
                with work_lock:
                    for nid, sock in callback_sockets.items():
                        if nid != node_id:
                            send_json(sock, {"type": "cancel"})

    except Exception as e:
        print(f"[ERROR] Node {node_id}: {e}")
    finally:
        cleanup_node(node_id)

def cleanup_node(node_id):
    with work_lock:
        if node_id in node_work and not password_found:
            start, end = node_work.pop(node_id)
            print(f"[RECLAIM] Returned {start:,} → {end:,} from {node_id}")
        active_nodes.pop(node_id, None)
        if node_id in callback_sockets:
            try:
                callback_sockets[node_id].close()
            except:
                pass
            del callback_sockets[node_id]
        print(f"[X] Node disconnected: {node_id}")

def timeout_monitor(args):
    while not password_found:
        time.sleep(5)
        now = time.time()
        with work_lock:
            dead = [nid for nid, t in active_nodes.items() if now - t > args.timeout]
            for nid in dead:
                print(f"[TIMEOUT] No checkpoint from {nid} for {args.timeout}s → dead")
                cleanup_node(nid)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--hash", required=True)                   # e.g. "$y$j9T..." or "$2b$..." multiple with comma
    parser.add_argument("--work-size", type=int, required=True)
    parser.add_argument("--checkpoint", type=int, required=True)
    parser.add_argument("--timeout", type=int, required=True)
    args = parser.parse_args()

    args.hash = [h.strip() for h in args.hash.split(",") if h.strip()]

    print("[*] Server ready – lazy work generation (up to ≈7.8 billion passwords)")

    threading.Thread(target=timeout_monitor, args=(args,), daemon=True).start()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", args.port))
    server.listen()
    print(f"[SERVER] Listening on port {args.port}")

    try:
        while not password_found:
            conn, addr = server.accept()
            threading.Thread(target=handle_node, args=(conn, addr, args), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        if found_password:
            print(f"\n=== PASSWORD CRACKED: {found_password} ===\n")

if __name__ == "__main__":
    main()
