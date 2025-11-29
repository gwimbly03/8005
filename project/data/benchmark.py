import subprocess
import time
import csv
import signal
import os


SERVER_CMD = [
    "python3", "server.py",
    "--port", "7000",
    "--hash", "$6$Mf4Hi79vYAePjshh$taODXW9Sv9OR.ffEVsQG6HCtFQvxODo6h67OrHeklbmSzOxzYbFWS4rtRYOxRkqLr6yEIbKJHw5oIDgnhd/BK/",
    "--work-size", "10000",
    "--checkpoint", "10000",
    "--timeout", "100"
]

WORKER_CMD = [
    "python3", "worker.py",
    "--server", "127.0.0.1",
    "--port", "7000",
    "--threads", "4"         
]

TEST_WORKERS = [1, 2, 3, 4, 10]      



def run_test(num_workers: int) -> float:
    print(f"\n=== Running benchmark with {num_workers} worker(s) ===")

    server = subprocess.Popen(SERVER_CMD, preexec_fn=os.setsid)
    time.sleep(2)  

    start = time.time()

    workers = []
    for _ in range(num_workers):
        p = subprocess.Popen(WORKER_CMD, preexec_fn=os.setsid)
        workers.append(p)

    server.wait()
    end = time.time()

    for w in workers:
        if w.poll() is None:
            try:
                os.killpg(os.getpgid(w.pid), signal.SIGTERM)
            except Exception:
                pass

    duration = end - start
    print(f"Finished! Total time = {duration:.2f} seconds")

    return duration


def main():
    results = {}

    print("Starting benchmarking...")

    for n in TEST_WORKERS:
        duration = run_test(n)
        results[n] = duration

    with open("results.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["workers", "time_sec"])
        for workers, sec in results.items():
            writer.writerow([workers, sec])

    print("\n=== Benchmark Done! ===")
    print("Saved results to results.csv\n")

    for w, t in results.items():
        print(f"{w} workers → {t:.2f} sec")


if __name__ == "__main__":
    main()

