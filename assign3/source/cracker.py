#!/usr/bin/env python3
import argparse
import os
import sys
import time
import threading
import signal
from typing import Optional

from passlib.context import CryptContext
from passlib import registry

CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#%^&*()_+-=.,:;?"
assert len(CHARSET) == 79, f"CHARSET has {len(CHARSET)} characters, expected 79"

DEFAULT_MIN_LENGTH = 1
DEFAULT_MAX_LENGTH = 8
DEFAULT_CHUNK = 512

# try to import pyescrypt (preferred for yescrypt support)
_have_pyescrypt = False
_pyescrypt_impl = None
try:
    import pyescrypt  # type: ignore

    _have_pyescrypt = True
    if hasattr(pyescrypt, "Yescrypt"):
        try:
            _pyescrypt_impl = pyescrypt.Yescrypt()
        except Exception:
            _pyescrypt_impl = None
    if _pyescrypt_impl is None:
        if hasattr(pyescrypt, "check"):
            _pyescrypt_impl = pyescrypt.check
        elif hasattr(pyescrypt, "verify"):
            _pyescrypt_impl = pyescrypt.verify
except Exception:
    _have_pyescrypt = False
    _pyescrypt_impl = None

# passlib crypt context (only the algorithms we support)
DESIRED_SCHEMES = ["bcrypt", "sha512_crypt", "sha256_crypt", "md5_crypt"]
try:
    ctx = CryptContext(schemes=DESIRED_SCHEMES, deprecated="auto")
except Exception as e:
    print(f"[err] Failed to initialize CryptContext: {e}", file=sys.stderr)
    sys.exit(1)

_stop_event = threading.Event()
_counter_lock = threading.Lock()
_result_lock = threading.Lock()


def find_user_hash(path: str, username: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split(":", 2)
                if parts[0] == username and len(parts) > 1 and parts[1]:
                    return parts[1]
    except FileNotFoundError:
        return None
    return None


def idx_to_guess(i: int, length: int, charset: str = CHARSET) -> str:
    base = len(charset)
    # produce length characters (with leading charset[0] if necessary)
    chars = [""] * length
    for pos in range(length - 1, -1, -1):
        chars[pos] = charset[i % base]
        i //= base
    return "".join(chars)


def verify_yescrypt_pyescrypt(candidate: str, target_hash: str) -> bool:
    if not _have_pyescrypt or _pyescrypt_impl is None:
        return False
    pwd_bytes = candidate.encode("utf-8")
    hash_bytes = target_hash.encode("utf-8")
    try:
        # If _pyescrypt_impl is an object with compare()
        if hasattr(_pyescrypt_impl, "compare"):
            try:
                _pyescrypt_impl.compare(pwd_bytes, hash_bytes)
                return True
            except Exception:
                return False
        # If it's function-like check/verify
        if callable(_pyescrypt_impl):
            try:
                res = _pyescrypt_impl(pwd_bytes, hash_bytes)
                if isinstance(res, bool):
                    return res
                return True
            except Exception:
                return False
    except Exception:
        return False
    return False


def verify_hash(hash_field: str, password_guess: str) -> bool:
    # yescrypt has $y$ prefix
    if hash_field.startswith("$y$"):
        return verify_yescrypt_pyescrypt(password_guess, hash_field)
    else:
        try:
            return ctx.verify(password_guess, hash_field)
        except Exception:
            return False


def worker(
    counter: list,
    chunk: int,
    total: int,
    length: int,
    hash_field: str,
    result: dict,
    progress_counter: list,
):
    while not _stop_event.is_set():
        with _counter_lock:
            start = counter[0]
            counter[0] += chunk
        if start >= total:
            return
        end = min(start + chunk, total)
        local_processed = 0
        for i in range(start, end):
            if _stop_event.is_set():
                return
            guess = idx_to_guess(i, length)
            local_processed += 1
            if verify_hash(hash_field, guess):
                with _result_lock:
                    if "password" not in result:
                        result["password"] = guess
                        result["tried"] = progress_counter[0] + local_processed
                _stop_event.set()
                return
        # update global progress counter
        with _result_lock:
            progress_counter[0] += local_processed


def run_cracker(
    shadow_path: str,
    username: str,
    n_threads: int,
    min_length: int,
    max_length: int,
    chunk: int,
):
    hash_field = find_user_hash(shadow_path, username)
    if hash_field is None:
        print(f"[err] User '{username}' not found or unable to read shadow file.", file=sys.stderr)
        return

    algo = hash_field.split("$")[1] if "$" in hash_field else "unknown"
    print(f"[i] Cracking user {username} (algorithm: {algo})", file=sys.stderr)

    if hash_field.startswith("$y$") and not _have_pyescrypt:
        print("[err] yescrypt detected but 'pyescrypt' is not installed.", file=sys.stderr)
        print("      Install it with: python -m pip install pyescrypt", file=sys.stderr)
        return

    try:
        if hasattr(os, "sched_setaffinity"):
            os.sched_setaffinity(0, range(os.cpu_count() or 1))
            print("[i] Set CPU affinity to all cores", file=sys.stderr)
    except Exception:
        pass

    result = {}
    progress_counter = [0]
    start_time = time.perf_counter()

    for length in range(min_length, max_length + 1):
        if _stop_event.is_set():
            break
        base = len(CHARSET)
        total = pow(base, length)
        if total == 0:
            continue

        counter = [0]
        threads = []
        for _ in range(n_threads):
            th = threading.Thread(
                target=worker,
                args=(counter, chunk, total, length, hash_field, result, progress_counter),
                daemon=True,
            )
            threads.append(th)
            th.start()

        try:
            # join threads; they will return when done or when found
            for th in threads:
                while th.is_alive():
                    th.join(timeout=0.5)
                    # periodic progress display
                    elapsed = time.perf_counter() - start_time
                    tried = progress_counter[0]
                    rate = tried / elapsed if elapsed > 0 else 0.0
                    print(
                        f"\r[i] len={length} tried={tried}/{total} ({rate:.1f} pwd/s)",
                        end="",
                        file=sys.stderr,
                        flush=True,
                    )
                    if _stop_event.is_set():
                        break
                if _stop_event.is_set():
                    break
        except KeyboardInterrupt:
            _stop_event.set()
            for th in threads:
                th.join()
            break

        print("", file=sys.stderr)  # newline after progress line

        if "password" in result:
            elapsed = time.perf_counter() - start_time
            print("#" * 10)
            print(
                f"# of Threads:{n_threads} Time used:{elapsed:.4f}s Password is '{result['password']}'"
            )
            return

        print(f"[i] Completed length={length} (tried {progress_counter[0]} passwords so far)", file=sys.stderr)

    elapsed = time.perf_counter() - start_time
    if "password" in result:
        print("#" * 10)
        print(
            f"# of Threads:{n_threads} Time used:{elapsed:.4f}s Password is '{result['password']}'"
        )
    else:
        print(
            f"# of Threads:{n_threads} Time used:{elapsed:.4f}s Password is NOT FOUND (tried ~{progress_counter[0]} passwords)"
        )


def main():
    parser = argparse.ArgumentParser(description="Password cracker remake (pyescrypt + passlib).")
    parser.add_argument("shadow", help="path to shadow file")
    parser.add_argument("username", help="username to target")
    parser.add_argument("threads", type=int, help="number of threads")
    parser.add_argument("--min-length", type=int, default=DEFAULT_MIN_LENGTH, help="minimum password length (inclusive)")
    parser.add_argument("--max-length", type=int, default=DEFAULT_MAX_LENGTH, help="maximum password length (inclusive)")
    parser.add_argument("--chunk", type=int, default=DEFAULT_CHUNK, help="number of guesses each worker takes per allocation")
    args = parser.parse_args()

    if not os.path.isfile(args.shadow):
        print("[err] Shadow file not found:", args.shadow, file=sys.stderr)
        sys.exit(1)
    if args.threads <= 0:
        print("[err] Threads must be > 0", file=sys.stderr)
        sys.exit(1)
    if args.min_length < 1 or args.max_length < args.min_length:
        print("[err] Invalid min/max length", file=sys.stderr)
        sys.exit(1)

    # handle SIGINT cleanly
    signal.signal(signal.SIGINT, lambda s, f: _stop_event.set())

    run_cracker(
        shadow_path=args.shadow,
        username=args.username,
        n_threads=args.threads,
        min_length=args.min_length,
        max_length=args.max_length,
        chunk=args.chunk,
    )


if __name__ == "__main__":
    main()

