#!/usr/bin/env python3
import argparse
import socket
import threading
import json
import time

class Server:
    def __init__(self, port, target_hash, work_size, checkpoint, timeout):
        self.port = port
        self.target_hash = target_hash
        self.work_size = work_size
        self.checkpoint = checkpoint
        self.timeout = timeout

        self.nodes = {}
        self.next_node_id = 1
        self.lock = threading.Lock()

        self.current_idx = 0
        self.password_found = False
        self.found_by = None
        self.found_password = None

    def start(self):
        print(f"[+] Server listening on port {self.port}")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("0.0.0.0", self.port))
        s.listen(20)

        while True:
            client_sock, addr = s.accept()
            node_id = f"node-{self.next_node_id}"
            self.next_node_id += 1

            with self.lock:
                self.nodes[node_id] = {
                    "sock": client_sock,
                    "addr": addr,
                    "last_seen": time.time()
                }

            print(f"[+] Node connected: {node_id} from {addr}")
            threading.Thread(target=self.handle_client, args=(client_sock, node_id), daemon=True).start()

    def assign_work(self, node_id):
        if self.password_found:
            return None

        start = self.current_idx
        end = start + self.work_size
        self.current_idx = end

        return {
            "type": "work",
            "start_idx": start,
            "end_idx": end,
            "hash": self.target_hash,
            "checkpoint": self.checkpoint,
            "node_id": node_id
        }

    def handle_client(self, sock, node_id):
        buf = ""

        # Send initial work immediately
        work = self.assign_work(node_id)
        if work:
            sock.sendall(json.dumps(work).encode() + b"\n")
            print(f"[+] New work assigned -> {node_id}: [{work['start_idx']}..{work['end_idx']})")

        while True:
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

                    # Node heartbeat / ack work
                    if msg["type"] == "ready" and not self.password_found:
                        work = self.assign_work(node_id)
                        if work:
                            sock.sendall(json.dumps(work).encode() + b"\n")
                            print(f"[+] New work assigned -> {node_id}: [{work['start_idx']}..{work['end_idx']})")

                    # PASSWORD FOUND
                    elif msg["type"] == "found":
                        plaintext = msg["password"]

                        if not self.password_found:
                            self.password_found = True
                            self.found_by = node_id
                            self.found_password = plaintext

                            print("\n" + "=" * 60)
                            print(f"[!!!] PASSWORD FOUND by {node_id}: {plaintext}")
                            print("=" * 60 + "\n")

                            # Tell all nodes to stop
                            self.broadcast_stop()

            except Exception as e:
                print(f"[!] Error with {node_id}: {e}")
                break

        print(f"[!] Node disconnected: {node_id}")
        with self.lock:
            if node_id in self.nodes:
                del self.nodes[node_id]

    def broadcast_stop(self):
        msg = json.dumps({"type": "stop", "reason": "password_found"})
        for n_id, node in list(self.nodes.items()):
            try:
                node["sock"].sendall(msg.encode() + b"\n")
            except:
                pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--hash", type=str, required=True)
    parser.add_argument("--work-size", type=int, default=1000)
    parser.add_argument("--checkpoint", type=int, default=500)
    parser.add_argument("--timeout", type=int, default=600)

    args = parser.parse_args()

    srv = Server(
        args.port,
        args.hash,
        args.work_size,
        args.checkpoint,
        args.timeout
    )
    srv.start()

