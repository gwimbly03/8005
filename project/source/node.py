#!/usr/bin/env python3
import socket
import json
import threading
import time
import bcrypt

SERVER_IP = "192.168.50.101"
SERVER_PORT = 5000
NODE_ID = None

running = True


def brute_force_chunk(start_idx, end_idx, target_hash, checkpoint, node_sock):
    global running

    for idx in range(start_idx, end_idx):
        if not running:
            return

        candidate = f"pass{idx}"  # Your real generation algorithm goes here

        if bcrypt.checkpw(candidate.encode(), target_hash.encode()):
            print(f"[*] PASSWORD FOUND: {candidate}")

            msg = json.dumps({
                "type": "found",
                "node_id": NODE_ID,
                "password": candidate
            })
            node_sock.sendall(msg.encode() + b"\n")
            return

        # checkpoint output
        if (idx - start_idx) % checkpoint == 0:
            print(f"[{NODE_ID}] Progress: {idx}/{end_idx}")


def handle_server(sock):
    global running, NODE_ID

    buf = ""
    while running:
        try:
            data = sock.recv(4096)
            if not data:
                break

            buf += data.decode()
            while "\n" in buf:
                line, buf = buf.split("\n", 1)
                if not line.strip():
                    continue

                msg = json.loads(line)

                if msg["type"] == "work":
                    NODE_ID = msg["node_id"]
                    print(f"[+] Got work: [{msg['start_idx']}..{msg['end_idx']})")

                    t = threading.Thread(
                        target=brute_force_chunk,
                        args=(
                            msg["start_idx"],
                            msg["end_idx"],
                            msg["hash"],
                            msg["checkpoint"],
                            sock
                        ),
                        daemon=True
                    )
                    t.start()

                elif msg["type"] == "stop":
                    print(f"[!] STOP received from server: {msg['reason']}")
                    running = False
                    return

        except Exception as e:
            print(f"[!] Reader error: {e}")
            running = False
            break


def connect():
    global running
    running = True

    while True:
        try:
            print(f"[+] Connecting to server {SERVER_IP}:{SERVER_PORT} ...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((SERVER_IP, SERVER_PORT))
            print("[+] Connected")
            return sock
        except:
            print("[!] Connection failed, retrying...")
            time.sleep(2)


if __name__ == "__main__":
    sock = connect()

    threading.Thread(target=handle_server, args=(sock,), daemon=True).start()

    # Let server know we are ready for more work
    while running:
        time.sleep(3)
        try:
            sock.sendall(json.dumps({"type": "ready"}).encode() + b"\n")
        except:
            break

