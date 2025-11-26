import argparse
import socket
import threading
import time
import json
import logging
import sys
import signal
import random
from typing import Optional

import crypt_r
from passlib.context import CryptContext

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

_crypt_lock = threading.Lock()

try:
    ctx = CryptContext(
        schemes=["bcrypt", "sha512_crypt", "sha256_crypt", "md5_crypt"],
        deprecated="auto",
    )
except Exception as e:
    logger.error(f"Error initializing CryptContext: {e}")
    sys.exit(1)

LEGALCHAR = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#%^&*()_+-=.,:;?"

class PasswordCrackingWorker:
    def __init__(self, server_ip: str, server_port: int, num_threads: int):
        self.server_ip = server_ip
        self.server_port = server_port
        self.num_threads = max(1, num_threads)

        self.socket: Optional[socket.socket] = None
        self.connected = False
        self.node_id = f"worker-{socket.gethostname()}-{int(time.time())}"

        self.target_hash: Optional[str] = None
        self.current_work = None 
        self.stop_event = threading.Event()

        self.attempts_since_checkpoint = 0
        self.checkpoint_interval = 500 

        self.lock = threading.Lock()            
        self.send_lock = threading.Lock()      
        self.recv_buffer = ""                  

        self.reconnect_delay = 1
        self.reconnect_delay_max = 30

        self.no_work_delay = 1
        self.no_work_delay_max = 10

        self.heartbeat_interval = 10 

        self.total_attempts = 0
        self.attempts_lock = threading.Lock()
        self.attempts_window_start = time.time()

    def send_json(self, obj: dict):
        payload = (json.dumps(obj) + "\n").encode("utf-8")
        if not self.socket:
            return False
        with self.send_lock:
            try:
                self.socket.sendall(payload)
                return True
            except Exception as e:
                logger.debug(f"send_json failed: {e}")
                return False

    def _recv_lines(self) -> list:
        if not self.socket:
            return []
        try:
            data = self.socket.recv(4096).decode("utf-8")
        except socket.timeout:
            return []
        except Exception as e:
            logger.debug(f"_recv_lines socket error: {e}")
            raise
        if not data:
            raise ConnectionResetError("remote closed")
        self.recv_buffer += data
        lines = []
        while "\n" in self.recv_buffer:
            line, self.recv_buffer = self.recv_buffer.split("\n", 1)
            if line.strip():
                lines.append(line)
        return lines

    def _idx_to_guess(self, idx: int, length: int) -> str:
        base = len(LEGALCHAR)
        chars = []
        temp_idx = idx
        for _ in range(length):
            chars.append(LEGALCHAR[temp_idx % base])
            temp_idx //= base
        return ''.join(reversed(chars))

    def _verify_hash(self, hash_field: str, password_guess: str) -> bool:
        if hash_field.startswith("$y$"): 
            try:
                with _crypt_lock:
                    out = crypt_r.crypt(password_guess, hash_field)
            except Exception:
                return False
            if not out:
                return False
            return out == hash_field
        else:
            try:
                return ctx.verify(password_guess, hash_field)
            except Exception:
                return False

    def _crack_worker(self, target_hash: str, work_id: int, start: int, end: int, length: int):
        current = start
        last_report_time = time.time()

        while current < end and not self.stop_event.is_set():
            password_guess = self._idx_to_guess(current, length)

            if self._verify_hash(target_hash, password_guess):
                found_msg = {'type': 'password_found', 'password': password_guess, 'work_id': work_id}
                self.send_json(found_msg)
                logger.info(f"Password found: {password_guess} (work {work_id})")
                return

            current += 1

            with self.lock:
                self.attempts_since_checkpoint += 1
                with self.attempts_lock:
                    self.total_attempts += 1

                if self.attempts_since_checkpoint >= self.checkpoint_interval:
                    checkpoint_msg = {'type': 'checkpoint', 'work_id': work_id, 'checkpoint': current}
                    if not self.send_json(checkpoint_msg):
                        logger.debug("Failed to send checkpoint (socket issue)")
                    self.attempts_since_checkpoint = 0

            if time.time() - last_report_time >= 5:
                last_report_time = time.time()
                with self.attempts_lock:
                    window_elapsed = last_report_time - self.attempts_window_start
                    if window_elapsed > 0:
                        attempts_per_sec = self.total_attempts / window_elapsed
                        logger.debug(f"Throughput {attempts_per_sec:.1f} attempts/sec")
        if not self.stop_event.is_set():
            completed_msg = {'type': 'work_completed', 'work_id': work_id}
            self.send_json(completed_msg)

    def _send_heartbeat(self):
        while not self.stop_event.is_set() and self.connected:
            try:
                hb = {'type': 'heartbeat'}
                self.send_json(hb)
            except Exception:
                logger.debug("Heartbeat send failed")
                self.connected = False
                break
            time.sleep(self.heartbeat_interval + random.random()*2)

    def _process_server_message(self, message: dict):
        msg_type = message.get('type')
        if msg_type == 'config':
            self.checkpoint_interval = message.get('checkpoint_interval', self.checkpoint_interval)
            self.target_hash = message.get('target_hash', self.target_hash)
            logger.info(f"Received config: checkpoint={self.checkpoint_interval}")
            self.no_work_delay = 1  # reset
            self.send_json({'type': 'work_request'})

        elif msg_type == 'work_assignment':
            self.no_work_delay = 1

            work_id = message['work_id']
            start = int(message['start'])
            end = int(message['end'])
            length = int(message['length'])
            logger.info(f"Received work {work_id}: {start}-{end} (len {length})")

            with self.lock:
                self.attempts_since_checkpoint = 0

            threads = []
            total = end - start
            base_chunk = total // self.num_threads if self.num_threads > 0 else total
            if base_chunk == 0:
                base_chunk = total
            for i in range(self.num_threads):
                t_start = start + i * base_chunk
                t_end = t_start + base_chunk if i < self.num_threads - 1 else end
                if t_start >= t_end:
                    continue
                t = threading.Thread(
                    target=self._crack_worker,
                    args=(self.target_hash, work_id, t_start, t_end, length),
                    daemon=True
                )
                threads.append(t)
                t.start()

            for t in threads:
                t.join()

            if not self.stop_event.is_set() and self.connected:
                self.send_json({'type': 'work_request'})

        elif msg_type == 'no_work':
            logger.info(f"No work available; backing off for {self.no_work_delay}s")
            time.sleep(self.no_work_delay)
            self.no_work_delay = min(self.no_work_delay * 2, self.no_work_delay_max)
            if not self.stop_event.is_set() and self.connected:
                self.send_json({'type': 'work_request'})

        elif msg_type == 'stop':
            logger.info("Received stop signal from server")
            self.stop_event.set()

        else:
            logger.debug(f"Unknown message from server: {msg_type}")

    def _handle_server_messages(self):
        if self.socket:
            self.socket.settimeout(1.0)

        try:
            while not self.stop_event.is_set() and self.connected:
                try:
                    lines = self._recv_lines()
                except ConnectionResetError:
                    logger.warning("Connection closed by server")
                    self.connected = False
                    break
                except Exception as e:
                    logger.warning(f"Receive error: {e}")
                    self.connected = False
                    break

                for raw in lines:
                    try:
                        message = json.loads(raw)
                    except json.JSONDecodeError as e:
                        logger.debug(f"JSON decode error, skipping line: {e}")
                        continue
                    self._process_server_message(message)

        finally:
            self.connected = False

    def connect_to_server(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            s.settimeout(5)
            s.connect((self.server_ip, self.server_port))
            s.settimeout(None)  
            self.socket = s
            self.connected = True

            self.reconnect_delay = 1
            self.no_work_delay = 1

            register_msg = {'type': 'register', 'node_id': self.node_id}
            self.send_json(register_msg)
            logger.info(f"Connected & registered as {self.node_id} to {self.server_ip}:{self.server_port}")

            hb_thread = threading.Thread(target=self._send_heartbeat, daemon=True)
            hb_thread.start()

            self._handle_server_messages()

        except Exception as e:
            logger.warning(f"Failed to connect/register to server: {e}")
            self.connected = False
            try:
                if self.socket:
                    self.socket.close()
            except:
                pass
            self.socket = None

    def start(self):
        logger.info(f"Starting worker (threads={self.num_threads})")
        def _signal_handler(sig, frame):
            logger.info("Shutdown signal received")
            self.stop_event.set()
            if self.socket:
                try:
                    self.socket.shutdown(socket.SHUT_RDWR)
                except:
                    pass
                try:
                    self.socket.close()
                except:
                    pass

        signal.signal(signal.SIGINT, _signal_handler)
        signal.signal(signal.SIGTERM, _signal_handler)

        while not self.stop_event.is_set():
            if not self.connected:
                logger.info(f"Attempting connection (delay={self.reconnect_delay}s)...")
                self.connect_to_server()

                if not self.connected:
                    to_sleep = self.reconnect_delay + random.random()
                    time.sleep(to_sleep)
                    self.reconnect_delay = min(self.reconnect_delay * 2, self.reconnect_delay_max)
                else:
                    with self.attempts_lock:
                        self.total_attempts = 0
                        self.attempts_window_start = time.time()

            time.sleep(0.1)

        logger.info("Worker stopped")

def main():
    parser = argparse.ArgumentParser(description="Distributed Password Cracking Worker (polished)")
    parser.add_argument("--server", type=str, required=True, help="Server IP or hostname")
    parser.add_argument("--port", type=int, required=True, help="Server port")
    parser.add_argument("--threads", type=int, default=4, help="Number of cracking threads")
    args = parser.parse_args()

    worker = PasswordCrackingWorker(
        server_ip=args.server,
        server_port=args.port,
        num_threads=args.threads
    )
    worker.start()

if __name__ == "__main__":
    main()
