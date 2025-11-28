import argparse
import socket
import threading
import time
import json
import logging
import queue
import heapq
from typing import Dict, List


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

    def __repr__(self):
        return f"WorkUnit({self.start}-{self.end}, chk={self.last_checkpoint}, assigned={self.assigned_to}, done={self.completed})"


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
        # connection closed
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
        payload = (json.dumps(obj) + "\n").encode("utf-8")
        sock.sendall(payload)
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
        self.lock = threading.Lock()

        self.work_queue = queue.Queue()
        self.pq_counter = 0
        self.requeue_pq = []  

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

        try:
            while not self.stop_event.is_set() and node.connected:
                try:
                    msgs, buffer = recv_lines(conn, buffer)
                except ConnectionResetError:
                    logger.warning(f"Node {node.id} disconnected (connection reset).")
                    break
                except Exception as e:
                    logger.warning(f"Receive error from {node.id}: {e}")
                    break

                for raw in msgs:
                    try:
                        msg = json.loads(raw)
                    except json.JSONDecodeError:
                        logger.debug("JSON decode error, skipping")
                        continue

                    self._process_message(node, msg)

        finally:
            self._handle_disconnection(node.id)

    def _process_message(self, node: Node, msg: dict):
        t = msg.get("type")

        if t == "heartbeat":
            node.last_heartbeat = time.time()

        elif t == "checkpoint":
            wid = msg.get("work_id")
            chk = int(msg.get("checkpoint", 0))

            with self.lock:
                for w in node.work:
                    if w.start == wid:
                        if chk > w.last_checkpoint:
                            w.last_checkpoint = chk
                        break

        elif t == "work_request":
            self._assign_work(node)

        elif t == "password_found":
            pw = msg.get("password")
            wid = msg.get("work_id")

            with self.lock:
                self.found_password = pw
                self.stop_event.set()
                logger.info(f"PASSWORD FOUND by {node.id}: {pw}")

            self._broadcast({"type": "stop"})

        elif t == "work_completed":
            wid = msg.get("work_id")

            with self.lock:
                for w in list(node.work):
                    if w.start == wid:
                        w.completed = True
                        try:
                            node.work.remove(w)
                        except ValueError:
                            pass
                        break

        else:
            logger.debug(f"Unknown message type from {node.id}: {t}")


    def _assign_work(self, node: Node):
        if self.stop_event.is_set():
            send_json(node.conn, {"type": "stop"})
            return

        with self.lock:
            if self.requeue_pq:
                prio, _, work = heapq.heappop(self.requeue_pq)
                work.assigned_to = node.id
                node.work.append(work)

                msg = {
                    "type": "work_assignment",
                    "work_id": work.start,
                    "start": work.last_checkpoint,
                    "end": work.end,
                    "length": self.current_length
                }
                send_json(node.conn, msg)
                logger.info(f"Reassigned REQUEUED work {work.start}-{work.end} (chk={work.last_checkpoint}) to {node.id}")
                return

        work = None
        try:
            work = self.work_queue.get_nowait()
        except queue.Empty:
            with self.lock:
                self.current_length += 1
                if self.current_length <= 8:
                    logger.info(f"Moving to length {self.current_length}")
                    self._generate_work_units()
                try:
                    work = self.work_queue.get_nowait()
                except queue.Empty:
                    work = None

        if work:
            work.assigned_to = node.id
            node.work.append(work)

            msg = {
                "type": "work_assignment",
                "work_id": work.start,
                "start": work.last_checkpoint,
                "end": work.end,
                "length": self.current_length
            }
            send_json(node.conn, msg)
            logger.info(f"Assigned work {work.start}-{work.end} (chk={work.last_checkpoint}) to {node.id}")
        else:
            send_json(node.conn, {"type": "no_work"})
            logger.debug(f"No work available for {node.id}; sent no_work")


    def _handle_disconnection(self, node_id: str):
        with self.lock:
            if node_id not in self.nodes:
                return

            node = self.nodes[node_id]
            node.connected = False

            logger.warning(f"Node {node_id} cleanup starting...")

            for w in list(node.work):
                if not w.completed:
                    logger.info(f"Requeuing unfinished work {w.last_checkpoint}-{w.end} from {node_id}")
                    w.assigned_to = None
                    self.pq_counter += 1
                    heapq.heappush(self.requeue_pq, (w.last_checkpoint, self.pq_counter, WorkUnit(w.last_checkpoint, w.end)))
            node.work.clear()

            try:
                del self.nodes[node_id]
            except KeyError:
                pass


    def _broadcast(self, msg):
        """Send msg to all connected nodes (best effort)."""
        with self.lock:
            for node in list(self.nodes.values()):
                try:
                    send_json(node.conn, msg)
                except Exception:
                    logger.debug(f"Failed to send to {node.id}")


    def _monitor(self):
        """Background thread that checks heartbeats and reclaims dead nodes."""
        while not self.stop_event.is_set():
            now = time.time()
            dead = []

            with self.lock:
                for nid, node in list(self.nodes.items()):
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
            try:
                msgs, buffer = recv_lines(conn, buffer)
            except Exception:
                conn.close()
                continue

            if not msgs:
                conn.close()
                continue

            try:
                reg = json.loads(msgs[0])
            except Exception:
                conn.close()
                continue

            if reg.get("type") != "register":
                conn.close()
                continue

            node_id = reg.get("node_id")
            if not node_id:
                conn.close()
                continue

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
