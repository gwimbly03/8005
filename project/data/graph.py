import pandas as pd
import matplotlib.pyplot as plt
import os
import sys

VALID_WORKERS = {1, 2, 3, 4, 10}

def main():
    csv_file = "results.csv"

    if not os.path.exists(csv_file):
        print(f"Error: {csv_file} not found")
        sys.exit(1)

    df = pd.read_csv(csv_file)

    if "workers" not in df.columns or "time_sec" not in df.columns:
        print("Error: CSV must contain 'workers' and 'time_sec' columns.")
        sys.exit(1)

    df = df[df["workers"].isin(VALID_WORKERS)].sort_values("workers")

    if df.empty:
        print("Error: No rows found for worker counts 1, 2, 3, 4, or 10.")
        sys.exit(1)

    plt.figure(figsize=(10, 6))
    plt.plot(df["workers"], df["time_sec"], marker="o", linewidth=2)

    plt.xticks([1,2,3,4,10])
    plt.xlabel("Number of Workers")
    plt.ylabel("Completion Time (seconds)")
    plt.title("Password Cracker Benchmark (Workers: 1,2,3,4,10)")
    plt.grid(True)

    out_file = "benchmark_filtered.png"
    plt.savefig(out_file, dpi=200)
    print(f"Saved graph as {out_file}")

    plt.show()


if __name__ == "__main__":
    main()

