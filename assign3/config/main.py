from pathlib import Path
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Optional, List, Tuple
import hashlib
import bcrypt
import itertools
from dataclasses import dataclass

@dataclass
class CrackResult:
    password: Optional[str] = None
    attempts: int = 0
    time_taken: float = 0.0

class PasswordCracker:
    def __init__(self):
        self.common_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_-+=[]{}|;:,.<>?/"
        self.found_password = None
        self.attempts = 0
        
    def crypt_verify(self, password: str, shadow_data: Dict) -> bool:
        """Verify password against shadow entry using crypt"""
        try:
            # Reconstruct the crypt string
            if shadow_data['id']:
                if shadow_data['params']:
                    crypt_str = f"${shadow_data['id']}${shadow_data['params']}${shadow_data['salt']}"
                else:
                    crypt_str = f"${shadow_data['id']}${shadow_data['salt']}"
            else:
                crypt_str = shadow_data['salt'] or ""
                
            result = crypt.crypt(password, crypt_str)
            return result == shadow_data['raw']
        except Exception:
            return False

    def generate_passwords(self, length: int, charset: str, start_index: int, end_index: int) -> List[str]:
        """Generate passwords for a specific thread's range"""
        passwords = []
        total_combinations = len(charset) ** length
        
        # Calculate this thread's portion
        chunk_size = total_combinations // (end_index - start_index)
        
        for i in range(start_index, end_index):
            # Convert index to password
            password = []
            temp = i
            for _ in range(length):
                password.append(charset[temp % len(charset)])
                temp //= len(charset)
            passwords.append(''.join(password))
            
        return passwords

    def crack_worker(self, shadow_data: Dict, length: int, charset: str, 
                    start_index: int, end_index: int, worker_id: int) -> CrackResult:
        """Worker function for cracking passwords"""
        start_time = time.time()
        result = CrackResult()
        
        passwords = self.generate_passwords(length, charset, start_index, end_index)
        
        for password in passwords:
            result.attempts += 1
            self.attempts += 1
            
            if self.crypt_verify(password, shadow_data):
                result.password = password
                result.time_taken = time.time() - start_time
                self.found_password = password
                return result
                
            # Early termination if another thread found it
            if self.found_password:
                result.time_taken = time.time() - start_time
                return result
        
        result.time_taken = time.time() - start_time
        return result

    def crack_password(self, shadow_data: Dict, num_threads: int = 1) -> Optional[str]:
        """Main cracking function with threading support"""
        self.found_password = None
        self.attempts = 0
        
        # For 3-character passwords as required
        password_length = 3
        total_combinations = len(self.common_chars) ** password_length
        
        # Calculate work distribution
        chunk_size = total_combinations // num_threads
        ranges = []
        
        for i in range(num_threads):
            start = i * chunk_size
            end = (i + 1) * chunk_size if i < num_threads - 1 else total_combinations
            ranges.append((start, end))
        
        start_time = time.time()
        results = []
        
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            future_to_worker = {
                executor.submit(
                    self.crack_worker, shadow_data, password_length, 
                    self.common_chars, start, end, i
                ): i for i, (start, end) in enumerate(ranges)
            }
            
            for future in as_completed(future_to_worker):
                result = future.result()
                results.append(result)
                if result.password:
                    print(f"Worker {future_to_worker[future]} found password: {result.password}")
                    # Cancel other futures
                    for f in future_to_worker:
                        if not f.done():
                            f.cancel()
                    break
        
        total_time = time.time() - start_time
        
        # Print results
        print(f"\nCracking Results:")
        print(f"Total time: {total_time:.2f} seconds")
        print(f"Total attempts: {self.attempts}")
        print(f"Password found: {self.found_password}")
        
        return self.found_password

def main():
    if len(sys.argv) != 4:
        sys.exit("Usage: sudo python3 cracker.py <shadow_file> <username> <num_threads>")

    shadow_file = sys.argv[1]
    username = sys.argv[2]
    
    try:
        num_threads = int(sys.argv[3])
    except ValueError:
        sys.exit("num_threads must be an integer")

    # Validate thread count
    import os
    logical_cores = os.cpu_count()
    if not (1 <= num_threads <= max(4, logical_cores)):
        sys.exit(f"num_threads must be between 1 and {max(4, logical_cores)}")

    try:
        users = parse_shadow(shadow_file)
    except PermissionError:
        sys.exit("Permission denied: run as root")
    except FileNotFoundError as e:
        sys.exit(str(e))

    if username not in users:
        sys.exit(f"User '{username}' not found in shadow file.")

    parsed = users[username]

    print(f"User: {username}")
    print(f"  raw   : {parsed.get('raw')}")
    print(f"  id    : {parsed.get('id')}")
    print(f"  algo  : {parsed.get('algo')}")
    print(f"  params: {parsed.get('params')}")
    print(f"  salt  : {parsed.get('salt')}")
    print(f"  hash  : {parsed.get('hash')}\n")

    # Start cracking
    cracker = PasswordCracker()
    
    print(f"Starting password cracking with {num_threads} thread(s)...")
    print(f"Search space: 3-character passwords from {len(cracker.common_chars)} characters")
    print(f"Total combinations: {len(cracker.common_chars) ** 3:,}")
    
    password = cracker.crack_password(parsed, num_threads)
    
    if password:
        print(f"\nSUCCESS: Password for {username} is '{password}'")
    else:
        print(f"\nFAILED: Could not crack password for {username}")

if __name__ == "__main__":
    main()
