import argparse
import socket
import threading
import time
import queue
import json
import logging
from typing import Dict, List, Tuple, Optional

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class WorkUnit:
    def __init__(self, start: int, end: int, assigned_to: str = None):
        self.start = start
        self.end = end
        self.assigned_to = assigned_to
        self.last_checkpoint = start
        self.completed = False

class Node:
    def __init__(self, node_id: str, conn: socket.socket, addr: Tuple[str, int]):
        self.node_id = node_id
        self.conn = conn
        self.addr = addr
        self.work_units: List[WorkUnit] = []
        self.connected = True
        self.last_heartbeat = time.time()

class PasswordCrackingServer:
    def __init__(self, port: int, target_hash: str, work_size: int, checkpoint_interval: int, timeout: int):
        self.port = port
        self.target_hash = target_hash
        self.work_size = work_size
        self.checkpoint_interval = checkpoint_interval
        self.timeout = timeout
        
        self.nodes: Dict[str, Node] = {}
        self.work_queue = queue.Queue()
        self.completed_work: List[WorkUnit] = []
        
        self.found_password = None
        self.found_event = threading.Event()
        
        self.legal_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#%^&*()_+-=.,:;?"
        self.base = len(self.legal_chars)
        self.current_length = 1
        
        self.server_socket = None
        self.lock = threading.Lock()
        
        # Initialize work for first length
        self._generate_work_units()
    
    def _idx_to_guess(self, idx: int, length: int) -> str:
        """Convert index to password guess"""
        chars = []
        temp_idx = idx
        for _ in range(length):
            chars.append(self.legal_chars[temp_idx % self.base])
            temp_idx //= self.base
        return ''.join(reversed(chars))
    
    def _generate_work_units(self):
        """Generate work units for current password length"""
        total_passwords = self.base ** self.current_length
        
        for start in range(0, total_passwords, self.work_size):
            end = min(start + self.work_size, total_passwords)
            self.work_queue.put(WorkUnit(start, end))
    
    def _handle_node_registration(self, conn: socket.socket, addr: Tuple[str, int]):
        """Handle new node registration"""
        try:
            # Receive registration message
            data = conn.recv(4096).decode('utf-8')
            if not data:
                conn.close()
                return
            message = json.loads(data)
            
            if message.get('type') == 'register':
                node_id = message['node_id']
                
                with self.lock:
                    node = Node(node_id, conn, addr)
                    self.nodes[node_id] = node
                    logger.info(f"Node {node_id} registered from {addr}")
                
                # Send initial configuration
                config_msg = {
                    'type': 'config',
                    'target_hash': self.target_hash,
                    'checkpoint_interval': self.checkpoint_interval
                }
                try:
                    conn.send(json.dumps(config_msg).encode('utf-8'))
                except Exception as e:
                    logger.warning(f"Failed to send config to {node_id}: {e}")
                
                # Handle messages from this node in a new thread (non-blocking)
                comm_thread = threading.Thread(target=self._handle_node_communication, args=(node,), daemon=True)
                comm_thread.start()
            else:
                logger.warning(f"Unexpected registration message from {addr}: {message}")
                conn.close()
                
        except Exception as e:
            logger.error(f"Error during node registration from {addr}: {e}")
            try:
                conn.close()
            except:
                pass
    
    def _handle_node_communication(self, node: Node):
        """Handle communication with a specific node"""
        conn = node.conn
        try:
            while node.connected and not self.found_event.is_set():
                try:
                    data = conn.recv(4096).decode('utf-8')
                except ConnectionResetError:
                    raise
                if not data:
                    break
                
                try:
                    message = json.loads(data)
                except json.JSONDecodeError as e:
                    logger.warning(f"JSON decode error from {node.node_id}: {e}")
                    # ignore this message and continue
                    continue
                
                self._process_node_message(node, message)
                
        except (ConnectionResetError, ConnectionAbortedError) as e:
            logger.warning(f"Connection with node {node.node_id} lost: {e}")
        finally:
            self._handle_node_disconnection(node.node_id)
    
    def _process_node_message(self, node: Node, message: dict):
        """Process message from node"""
        msg_type = message.get('type')
        
        if msg_type == 'heartbeat':
            node.last_heartbeat = time.time()
            logger.debug(f"Heartbeat from {node.node_id}")
            
        elif msg_type == 'checkpoint':
            work_id = message['work_id']
            checkpoint_pos = message['checkpoint']
            
            with self.lock:
                for work_unit in node.work_units:
                    if work_unit.start == work_id:
                        work_unit.last_checkpoint = checkpoint_pos
                        logger.info(f"Node {node.node_id} checkpoint at {checkpoint_pos} for work {work_id}")
                        break
        
        elif msg_type == 'work_request':
            self._assign_work_to_node(node)
        
        elif msg_type == 'password_found':
            password = message['password']
            work_id = message['work_id']
            
            with self.lock:
                # If already found by another node, ignore
                if not self.found_event.is_set():
                    self.found_password = password
                    self.found_event.set()
                    
                    # Mark the specific work unit as completed
                    for work_unit in node.work_units:
                        if work_unit.start == work_id:
                            work_unit.completed = True
                            break
                
                logger.info(f"Password found by node {node.node_id}: {password}")
            
            # Notify all nodes to stop
            self._broadcast_stop_message()
        
        elif msg_type == 'work_completed':
            work_id = message['work_id']
            
            with self.lock:
                # Mark work unit as completed
                for work_unit in list(node.work_units):
                    if work_unit.start == work_id:
                        work_unit.completed = True
                        self.completed_work.append(work_unit)
                        try:
                            node.work_units.remove(work_unit)
                        except ValueError:
                            pass
                        break
            
            logger.info(f"Node {node.node_id} completed work {work_id}")
        else:
            logger.warning(f"Unknown message type from {node.node_id}: {msg_type}")
    
    def _assign_work_to_node(self, node: Node):
        """Assign work to a node"""
        if self.found_event.is_set():
            # Send stop message if password found
            stop_msg = {'type': 'stop'}
            try:
                node.conn.send(json.dumps(stop_msg).encode('utf-8'))
            except Exception:
                pass
            return
        
        work_unit = None
        
        with self.lock:
            # Try to get work from queue
            try:
                work_unit = self.work_queue.get_nowait()
            except queue.Empty:
                # No work in current length, check if we need to move to next length
                if self.work_queue.empty() and not self.found_event.is_set():
                    self.current_length += 1
                    if self.current_length <= 8:  # Arbitrary limit
                        logger.info(f"Moving to password length {self.current_length}")
                        self._generate_work_units()
                        try:
                            work_unit = self.work_queue.get_nowait()
                        except queue.Empty:
                            work_unit = None
        
        if work_unit:
            work_unit.assigned_to = node.node_id
            node.work_units.append(work_unit)
            
            work_msg = {
                'type': 'work_assignment',
                'work_id': work_unit.start,
                'start': work_unit.last_checkpoint,
                'end': work_unit.end,
                'length': self.current_length
            }
            try:
                node.conn.send(json.dumps(work_msg).encode('utf-8'))
                logger.info(f"Assigned work {work_unit.start}-{work_unit.end} to node {node.node_id}")
            except Exception as e:
                logger.warning(f"Failed to send work assignment to {node.node_id}: {e}")
                # If send fails, requeue the work
                with self.lock:
                    new_work = WorkUnit(work_unit.last_checkpoint, work_unit.end)
                    self.work_queue.put(new_work)
                    try:
                        node.work_units.remove(work_unit)
                    except ValueError:
                        pass
        else:
            # No work available
            no_work_msg = {'type': 'no_work'}
            try:
                node.conn.send(json.dumps(no_work_msg).encode('utf-8'))
            except Exception:
                pass
    
    def _handle_node_disconnection(self, node_id: str):
        """Handle node disconnection and redistribute work"""
        with self.lock:
            if node_id in self.nodes:
                node = self.nodes[node_id]
                node.connected = False
                
                logger.info(f"Node {node_id} disconnected")
                
                # Redistribute unfinished work
                for work_unit in node.work_units:
                    if not work_unit.completed:
                        # Create new work unit from last checkpoint
                        new_work = WorkUnit(work_unit.last_checkpoint, work_unit.end)
                        self.work_queue.put(new_work)
                        logger.info(f"Requeued work {work_unit.last_checkpoint}-{work_unit.end} from disconnected node {node_id}")
                
                # Remove node
                try:
                    del self.nodes[node_id]
                except KeyError:
                    pass
    
    def _broadcast_stop_message(self):
        """Broadcast stop message to all nodes"""
        stop_msg = {'type': 'stop'}
        
        with self.lock:
            for node_id, node in list(self.nodes.items()):
                try:
                    node.conn.send(json.dumps(stop_msg).encode('utf-8'))
                except Exception:
                    pass  # Node might already be disconnected
    
    def _monitor_nodes(self):
        """Monitor nodes for timeouts"""
        while not self.found_event.is_set():
            time.sleep(10)  # Check every 10 seconds
            
            current_time = time.time()
            disconnected_nodes = []
            
            with self.lock:
                for node_id, node in list(self.nodes.items()):
                    if current_time - node.last_heartbeat > self.timeout:
                        logger.warning(f"Node {node_id} timed out")
                        disconnected_nodes.append(node_id)
            
            for node_id in disconnected_nodes:
                self._handle_node_disconnection(node_id)
    
    def start(self):
        """Start the server"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # set a short timeout so accept() can be interrupted by signals and loops can check found_event
        self.server_socket.settimeout(1.0)
        self.server_socket.bind(('0.0.0.0', self.port))
        self.server_socket.listen(10)
        
        logger.info(f"Server started on port {self.port}")
        logger.info(f"Target hash: {self.target_hash}")
        logger.info(f"Work size: {self.work_size}")
        logger.info(f"Checkpoint interval: {self.checkpoint_interval}")
        logger.info(f"Timeout: {self.timeout}")
        
        # Start node monitoring thread
        monitor_thread = threading.Thread(target=self._monitor_nodes, daemon=True)
        monitor_thread.start()
        
        try:
            while not self.found_event.is_set():
                try:
                    conn, addr = self.server_socket.accept()
                    
                    # Handle the registration/initial message in a thread so accept loop isn't blocked
                    reg_thread = threading.Thread(
                        target=self._handle_node_registration,
                        args=(conn, addr),
                        daemon=True
                    )
                    reg_thread.start()
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"Accept error: {e}")
                    continue
                
        except KeyboardInterrupt:
            logger.info("Server shutdown requested")
        finally:
            self.found_event.set()
            try:
                self.server_socket.close()
            except:
                pass
            
            if self.found_password:
                print("#" * 50)
                print(f"PASSWORD FOUND: {self.found_password}")
                print("#" * 50)
            else:
                print("Password not found")

def main():
    parser = argparse.ArgumentParser(description="Distributed Password Cracking Server")
    parser.add_argument("--port", type=int, required=True, help="Port the server listens on")
    parser.add_argument("--hash", type=str, required=True, help="Hashed password to crack")
    parser.add_argument("--work-size", type=int, default=1000, help="Number of passwords assigned per node request")
    parser.add_argument("--checkpoint", type=int, default=500, help="Number of attempts before a node sends a checkpoint")
    parser.add_argument("--timeout", type=int, default=600, help="Number of seconds to wait for a checkpoint from a client")
    
    args = parser.parse_args()
    
    server = PasswordCrackingServer(
        port=args.port,
        target_hash=args.hash,
        work_size=args.work_size,
        checkpoint_interval=args.checkpoint,
        timeout=args.timeout
    )
    
    server.start()

if __name__ == "__main__":
    main()

