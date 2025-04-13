#!/usr/bin/env python3

import requests
from functools import wraps
from enum import Enum


DEFAULT_TARGET = "192.168.122.224"

"""OH GOD WHAT ARE YOU DOING?!?"""
def run_remote_cmd(vm_ip: str, cmd: str) -> bool:
    """Run a command on the target VM (via SSH)."""
    try:
        subprocess.run(["ssh", f"root@{vm_ip}", cmd], check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Remote command failed: {e}")
        return False
