import argparse
import socket
import threading
import json
import time
import sys
import signal

LEGAL = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#%^&*()_+-=.,:;?"
BASE = len(LEGAL)

ATOMIC_START = 0
atomic_lock = threading.Lock()
atomic_counter = ATOMIC_START

found_event = threading.Event()


def atomic_next(work_size):
    global atomic_counter
    with atomic_lock:
        start = atomic_counter
        atomic_counter += work_size
        return start


class Node:
    def __init__(self, conn, addr, node_id, server):
        self.conn = conn
        self.addr = addr
        self.id = node_id
        self.server = server
        self.alive = True
        self.last_seen = time.time()

        threading.Thread(target=self.reader, daemon=True).start()

    def send(self, msg: dict):
        try:
            data = json.dumps(msg).encode() + b"\n"
            self.conn.sendall(data)
        except:
            self.alive = False

    def reader(self):
        buf = b""
        while self.alive and not found_event.is_set():
            try:
                data = self.conn.recv(4096)
                if not data:
                    break

                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if not line.strip():
                        continue

                    msg = json.loads(line)
                    self.server.handle_msg(self, msg)

                    # update health
                    self.last_seen = time.time()

            except Exception as e:
                print(f"[!] Node#{self.id} reader err: {e}")
                break

        self.alive = False
        self.server.remove_node(self)


class Server:
    def __init__(self, users, args):
        self.users = users
        self.args = args
        self.hash = args.hash

        self.nodes = []
        self.assigned = {}
        self.lock = threading.Lock()
        self.node_counter = 0

        threading.Thread(target=self.monitor_nodes, daemon=True).start()

    def handle_msg(self, node, msg):
        t = msg["type"]

        if t == "register":
            print(f"[+] Node#{node.id} registered")
            return

        if t == "request_work":
            if found_event.is_set():
                node.send({"type": "stop"})
                return

            start = atomic_next(self.args.work_size)
            end = start + self.args.work_size - 1

            assigned_time = time.time()

            with self.lock:
                self.assigned[node.id] = {
                    "start": start,
                    "end": end,
                    "assigned_time": assigned_time
                }

            node.send({
                "type": "work",
                "start_idx": start,
                "end_idx": end,
                "hash": self.hash,
                "checkpoint": self.args.checkpoint,
                "timeout": self.args.timeout,
                "assigned_time": assigned_time,
                "username": self.users[0][0] if self.users else None
            })
            return

        if t == "result":
            if msg["found"]:
                print(f"\n[+] Node#{node.id} cracked it! Password = {msg['password']}\n")
                found_event.set()
                self.broadcast_stop()
            return

    def broadcast_stop(self):
        for n in self.nodes:
            if n.alive:
                n.send({"type": "stop"})

    def remove_node(self, node):
        with self.lock:
            print(f"[-] Node#{node.id} disconnected")

            # reclaim work if assigned
            if node.id in self.assigned:
                print(f"    Reclaiming block assigned to Node#{node.id}")
                del self.assigned[node.id]

            self.nodes = [n for n in self.nodes if n is not node]

    def monitor_nodes(self):
        while not found_event.is_set():
            time.sleep(2)

            now = time.time()
            with self.lock:
                for n in list(self.nodes):
                    if now - n.last_seen > self.args.timeout:
                        print(f"[!] Node#{n.id} timed out, removing...")
                        self.remove_node(n)

    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", self.args.port))
        sock.listen(50)

        print(f"[*] Listening on port {self.args.port}")

        while not found_event.is_set():
            try:
                conn, addr = sock.accept()
                with self.lock:
                    n = Node(conn, addr, self.node_counter, self)
                    self.nodes.append(n)
                    self.node_counter += 1
                print(f"[+] Connection from {addr[0]}:{addr[1]}")
            except KeyboardInterrupt:
                break


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--hash", required=True)
    parser.add_argument("--work-size", type=int, default=1000)
    parser.add_argument("--checkpoint", type=int, default=500)
    parser.add_argument("--timeout", type=int, default=600)

    args = parser.parse_args()

    users = [("target", args.hash)]

    global server
    server = Server(users, args)
    server.start()


if __name__ == "__main__":
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
    main()

