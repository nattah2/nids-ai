#!/usr/bin/env python3

import subprocess
import time
import os
import csv
from datetime import datetime

"""
EXPLANATION:
What the fuck? This is why I write my own scripts.
"""

TARGET_IP = "192.168.122.224"  # Change if needed
SCRIPT_PATH = "./attack.py"
ATTACK_TYPES = ["normal", "sql_injection", "ddos", "port_scan"]
METADATA_CSV = "pcaps/metadata.csv"

# Ensure pcaps dir exists
os.makedirs("pcaps", exist_ok=True)

def run_traffic_gen(attack_type):
    print(f"\n=== Running: {attack_type.upper()} ===")
    start_time = int(time.time())
    try:
        subprocess.run(
            ["python3", SCRIPT_PATH, attack_type, "--target", TARGET_IP],
            check=True
        )
    except subprocess.CalledProcessError:
        print(f"[!] {attack_type} traffic generation failed.")
        return None

    end_time = int(time.time())
    filename = f"{attack_type}_{start_time}.pcap"
    return {
        "filename": filename,
        "label": attack_type,
        "start_time": start_time,
        "end_time": end_time,
        "timestamp": datetime.utcfromtimestamp(start_time).isoformat()
    }

def main():
    entries = []

    for attack_type in ATTACK_TYPES:
        entry = run_traffic_gen(attack_type)
        if entry:
            entries.append(entry)
        time.sleep(5)  # buffer between runs

    # Save metadata CSV
    with open(METADATA_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=entries[0].keys())
        writer.writeheader()
        writer.writerows(entries)

    print("\n✅ All traffic generated. Metadata saved to pcaps/metadata.csv")

if __name__ == "__main__":
    main()
