#!/usr/bin/env python3
import argparse
import json
import socket
import threading
import time

# Global state – one lock, super fast
lock = threading.Lock()
next_id = 0
nodes = {}                      # node_id → {'sock': sock, 'last_seen': time, 'work': (start,end)}
password_found = False
cracked_pw = None

def get_next_chunk(size):
    global next_id
    with lock:
        start = next_id
        end = start + size
        next_id = end
        return start, end

def broadcast_cancel():
    with lock:
        for info in nodes.values():
            try:
                info['sock'].sendall(b'{"type":"cancel"}\n')
            except:
                pass

def handle_client(sock, addr, args):
    global password_found, cracked_pw
    node_id = f"{addr[0]}:{addr[1]}"
    print(f"[+] Node connected: {node_id}")

    with lock:
        nodes[node_id] = {'sock': sock, 'last_seen': time.time(), 'work': None}

    try:
        while not password_found:
            start, end = get_next_chunk(args.work_size)
            with lock:
                nodes[node_id]['work'] = (start, end)
                nodes[node_id]['last_seen'] = time.time()

            print(f"[WORK] {node_id} ← {start:,} to {end:,}")

            sock.sendall(json.dumps({
                "type": "work",
                "start": start,
                "end": end,
                "hash": args.hash,
                "checkpoint": args.checkpoint
            }).encode() + b"\n")

            # Wait for messages with timeout
            sock.settimeout(args.timeout + 10)
            data = sock.recv(4096)
            if not data:
                break

            for line in data.decode().strip().split("\n"):
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except:
                    continue

                with lock:
                    nodes[node_id]['last_seen'] = time.time()

                if msg["type"] == "checkpoint":
                    print(f"[CHECK] {node_id} @ {msg.get('last_index', '?'):,} "
                          f"({msg.get('attempts', 0):,} attempts)")

                elif msg["type"] == "found":
                    pw = msg["password"]
                    print(f"\n[!!!] PASSWORD CRACKED BY {node_id}: {pw}\n")
                    cracked_pw = pw
                    password_found = True
                    broadcast_cancel()
                    return

    except Exception:
        if not password_found:
            print(f"[!] Node {node_id} disconnected")
    finally:
        with lock:
            work = nodes[node_id].get('work')
            if work and not password_found:
                print(f"[RECLAIM] Reclaiming {work[0]:,} → {work[1]:,} from {node_id}")
            nodes.pop(node_id, None)
        sock.close()

def heartbeat_monitor(args):
    while not password_found:
        time.sleep(5)
        now = time.time()
        with lock:
            dead = [nid for nid, info in nodes.items() if now - info['last_seen'] > args.timeout]
            for nid in dead:
                print(f"[TIMEOUT] {nid} dead – reclaiming work")
                work = nodes[nid].get('work')
                if work and not password_found:
                    print(f"[RECLAIM] {work[0]:,} → {work[1]:,} from timeout")
                try:
                    nodes[nid]['sock'].close()
                except:
                    pass
                del nodes[nid]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--hash", required=True)
    parser.add_argument("--work-size", type=int, required=True)
    parser.add_argument("--checkpoint", type=int, required=True)
    parser.add_argument("--timeout", type=int, required=True)
    args = parser.parse_args()

    # Support file or direct hash
    if args.hash.startswith("../") or args.hash.startswith("/"):
        with open(args.hash) as f:
            args.hash = [line.split(":")[1] for line in f if ":" in line]
    else:
        args.hash = [h.strip() for h in args.hash.split(",") if h.strip()]

    threading.Thread(target=heartbeat_monitor, args=(args,), daemon=True).start()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)   # ← FIXED LINE
    server.bind(("0.0.0.0", args.port))
    server.listen(128)
    print(f"[SERVER] Listening on port {args.port}")

    try:
        while not password_found:
            try:
                server.settimeout(1.0)
                sock, addr = server.accept()
                threading.Thread(target=handle_client, args=(sock, addr, args), daemon=True).start()
            except socket.timeout:
                continue
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        if cracked_pw:
            print(f"\nPASSWORD CRACKED: {cracked_pw}\n")

if __name__ == "__main__":
    main()
