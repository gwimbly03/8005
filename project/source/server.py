import argparse
import socket
import threading
import time
import json
import logging
import queue
from typing import Dict, List, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("server")

class WorkUnit:
    def __init__(self, start: int, end: int):
        self.start = start
        self.end = end
        self.last_checkpoint = start
        self.assigned_to = None
        self.completed = False


class Node:
    def __init__(self, node_id: str, conn: socket.socket, addr):
        self.id = node_id
        self.conn = conn
        self.addr = addr
        self.work: List[WorkUnit] = []
        self.last_heartbeat = time.time()
        self.connected = True

def recv_lines(sock, buffer):
    try:
        data = sock.recv(4096).decode("utf-8")
    except socket.timeout:
        return [], buffer
    except Exception:
        raise

    if not data:
        raise ConnectionResetError("client disconnected")

    buffer += data
    msgs = []

    while "\n" in buffer:
        line, buffer = buffer.split("\n", 1)
        if line.strip():
            msgs.append(line)

    return msgs, buffer


def send_json(sock, obj):
    try:
        sock.send((json.dumps(obj) + "\n").encode("utf-8"))
    except Exception:
        pass

class PasswordCrackingServer:
    def __init__(self, port, target_hash, work_size, checkpoint_interval, timeout):
        self.port = port
        self.target_instance = target_hash
        self.target_hash = target_hash
        self.work_size = work_size
        self.checkpoint_interval = checkpoint_interval
        self.timeout = timeout

        self.legal_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#%^&*()_+-=.,:;?"
        self.base = len(self.legal_chars)
        self.current_length = 1

        self.nodes: Dict[str, Node] = {}
        self.work_queue = queue.Queue()
        self.lock = threading.Lock()

        self.found_password = None
        self.stop_event = threading.Event()

        self._generate_work_units()

    def _generate_work_units(self):
        total = self.base ** self.current_length
        for start in range(0, total, self.work_size):
            end = min(start + self.work_size, total)
            self.work_queue.put(WorkUnit(start, end))

        logger.info(f"Generated work for length={self.current_length} total={total}")

    def _handle_node(self, node: Node):
        buffer = ""
        conn = node.conn
        conn.settimeout(1.0)

        while not self.stop_event.is_set() and node.connected:
            try:
                msgs, buffer = recv_lines(conn, buffer)
            except Exception:
                logger.warning(f"Node {node.id} disconnected.")
                break

            for raw in msgs:
                try:
                    msg = json.loads(raw)
                except json.JSONDecodeError:
                    continue

                self._process_message(node, msg)

        self._handle_disconnection(node.id)

    def _process_message(self, node: Node, msg: dict):
        t = msg.get("type")

        if t == "heartbeat":
            node.last_heartbeat = time.time()

        elif t == "checkpoint":
            wid = msg["work_id"]
            chk = msg["checkpoint"]

            with self.lock:
                for w in node.work:
                    if w.start == wid:
                        w.last_checkpoint = chk
                        break

        elif t == "work_request":
            self._assign_work(node)

        elif t == "password_found":
            pw = msg["password"]
            wid = msg["work_id"]

            with self.lock:
                self.found_password = pw
                self.stop_event.set()
                logger.info(f"!!! PASSWORD FOUND by {node.id}: {pw}")

            self._broadcast({"type": "stop"})

        elif t == "work_completed":
            wid = msg["work_id"]

            with self.lock:
                for w in node.work:
                    if w.start == wid:
                        w.completed = True
                        node.work.remove(w)
                        break

    def _assign_work(self, node: Node):
        if self.stop_event.is_set():
            send_json(node.conn, {"type": "stop"})
            return

        work = None

        with self.lock:
            try:
                work = self.work_queue.get_nowait()
            except queue.Empty:
                if self.work_queue.empty():
                    self.current_length += 1
                    if self.current_length <= 8:
                        logger.info(f"Moving to length {self.current_length}")
                        self._generate_work_units()
                        try:
                            work = self.work_queue.get_nowait()
                        except queue.Empty:
                            pass

        if work:
            work.assigned_to = node.id
            node.work.append(work)

            msg = {
                "type": "work_assignment",
                "work_id": work.start,
                "start": work.last_checkpoint,
                "end": work.end,
                "length": self.current_length,
            }
            send_json(node.conn, msg)

        else:
            send_json(node.conn, {"type": "no_work"})

    def _handle_disconnection(self, node_id: str):
        with self.lock:
            if node_id not in self.nodes:
                return

            node = self.nodes[node_id]
            node.connected = False

            logger.warning(f"Node {node_id} cleanup starting...")

            for w in node.work:
                if not w.completed:
                    self.work_queue.put(
                        WorkUnit(w.last_checkpoint, w.end)
                    )
                    logger.info(
                        f"Requeued {w.last_checkpoint}-{w.end} from {node_id}"
                    )

            del self.nodes[node_id]

    def _broadcast(self, msg):
        with self.lock:
            for node in self.nodes.values():
                send_json(node.conn, msg)

    def _monitor(self):
        while not self.stop_event.is_set():
            now = time.time()

            dead = []
            with self.lock:
                for nid, node in self.nodes.items():
                    if now - node.last_heartbeat > self.timeout:
                        dead.append(nid)

            for nid in dead:
                logger.warning(f"Heartbeat timeout: {nid}")
                self._handle_disconnection(nid)

            time.sleep(2)

    def start(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", self.port))
        s.listen(100)

        s.settimeout(1.0)

        logger.info(f"Server listening on port {self.port}")

        threading.Thread(target=self._monitor, daemon=True).start()

        while not self.stop_event.is_set():
            try:
                conn, addr = s.accept()
            except socket.timeout:
                if self.stop_event.is_set():
                    break
                continue
            except KeyboardInterrupt:
                logger.info("CTRL+C received — stopping server...")
                self.stop_event.set()
                break

            buffer = ""
            msgs, buffer = recv_lines(conn, buffer)

            if not msgs:
                conn.close()
                continue

            try:
                reg = json.loads(msgs[0])
            except:
                conn.close()
                continue

            if reg.get("type") != "register":
                conn.close()
                continue

            node_id = reg["node_id"]

            node = Node(node_id, conn, addr)
            with self.lock:
                self.nodes[node_id] = node

            logger.info(f"Node registered: {node_id} from {addr}")

            send_json(conn, {
                "type": "config",
                "target_hash": self.target_hash,
                "checkpoint_interval": self.checkpoint_interval
            })

            threading.Thread(
                target=self._handle_node, args=(node,), daemon=True
            ).start()

        s.close()

        if self.found_password:
            print("\n" + "#" * 60)
            print("PASSWORD FOUND:", self.found_password)
            print("#" * 60)
        else:
            print("No password found.")

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--hash", type=str, required=True)
    p.add_argument("--work-size", type=int, default=2000)
    p.add_argument("--checkpoint", type=int, default=600)
    p.add_argument("--timeout", type=int, default=600)

    a = p.parse_args()

    srv = PasswordCrackingServer(
        port=a.port,
        target_hash=a.hash,
        work_size=a.work_size,
        checkpoint_interval=a.checkpoint,
        timeout=a.timeout,
    )

    try:
        srv.start()
    except KeyboardInterrupt:
        logger.info("CTRL+C received — shutting down...")
        srv.stop_event.set()


if __name__ == "__main__":
    main()

