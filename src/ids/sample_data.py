from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd


def build_sample_data() -> pd.DataFrame:
    rows = [
        [1.2, "tcp", 240, 4200, 18, 0, 1, "normal"],
        [0.8, "udp", 120, 900, 8, 0, 0, "normal"],
        [2.4, "tcp", 560, 6100, 32, 0, 1, "normal"],
        [0.3, "icmp", 40, 60, 2, 0, 0, "normal"],
        [1.8, "tcp", 310, 3900, 21, 1, 2, "normal"],
        [0.1, "tcp", 20, 0, 140, 17, 0, "attack"],
        [0.2, "udp", 30, 20, 180, 25, 0, "attack"],
        [7.5, "tcp", 9000, 120, 220, 4, 14, "attack"],
        [5.9, "tcp", 7600, 90, 190, 6, 10, "attack"],
        [0.4, "icmp", 15, 0, 95, 12, 0, "attack"],
        [2.1, "udp", 180, 1600, 12, 0, 0, "normal"],
        [3.2, "tcp", 420, 5100, 28, 0, 2, "normal"],
        [8.4, "tcp", 12000, 80, 260, 8, 21, "attack"],
        [0.2, "udp", 25, 10, 210, 30, 0, "attack"],
        [1.1, "tcp", 260, 4500, 20, 0, 1, "normal"],
        [0.5, "icmp", 50, 70, 3, 0, 0, "normal"],
    ]

    return pd.DataFrame(
        rows,
        columns=[
            "duration",
            "protocol",
            "src_bytes",
            "dst_bytes",
            "packets",
            "errors",
            "login_attempts",
            "label",
        ],
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Create demo IDS traffic data.")
    parser.add_argument("--output", default="data/network_traffic.csv")
    args = parser.parse_args()

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    build_sample_data().to_csv(output, index=False)
    print(f"Wrote sample dataset to {output}")


if __name__ == "__main__":
    main()
