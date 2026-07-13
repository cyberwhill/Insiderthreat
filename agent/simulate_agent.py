"""
simulate_agent.py
Cross-platform traffic generator that plays the role of the PowerShell
agent, for demoing or testing the central station / dashboard on any OS
(the real agent.ps1 requires Windows).

Usage:
    python simulate_agent.py --server http://localhost:5000 --key change-me-agent-key
"""

import argparse
import hashlib
import json
import random
import time
from datetime import datetime, timedelta

import urllib.request

HOSTS = ["TPS-WS-012", "TPS-WS-053", "TPS-WS-108"]
USERS = ["jdoe", "rhassan", "mwilliams", "asmith"]
KNOWN_SERIALS = ["USB999OK", "USB771ISSUED"]
UNKNOWN_SERIALS = ["USB123XYZ", "USBDEADBEEF", "USB000ROGUE"]
SENSITIVE_PATHS = [
    r"C:\CaseFiles\Confidential\criminal_record_4521.pdf",
    r"C:\Evidence\intel\case_9981_notes.docx",
    r"C:\CaseFiles\personnel\employee_roster.xlsx",
]
NORMAL_PATHS = [
    r"C:\Users\jdoe\Documents\shift_schedule.txt",
    r"C:\Users\asmith\Desktop\notes.txt",
]


def post(server, key, endpoint, body):
    req = urllib.request.Request(
        server + endpoint,
        data=json.dumps(body).encode("utf-8"),
        headers={"X-Agent-Key": key, "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())
    except Exception as e:
        print("send failed:", e)
        return None


def fake_hash(seed):
    return hashlib.sha256(seed.encode()).hexdigest()


def run(server, key, interval, bulk_burst_chance):
    print(f"Simulating agent traffic against {server} (Ctrl+C to stop)")
    while True:
        host = random.choice(HOSTS)
        user = random.choice(USERS)
        now = datetime.utcnow()

        if random.random() < 0.25:
            # USB event
            action = random.choice(["connect", "disconnect"])
            serial = random.choice(KNOWN_SERIALS + UNKNOWN_SERIALS) if action == "connect" else "n/a"
            post(server, key, "/api/agent/usb", {
                "agent_id": f"agent-{host}",
                "hostname": host,
                "username": user,
                "action": action,
                "serial": serial,
                "device_name": "USB Mass Storage Device",
                "vendor_id": "0781",
                "product_id": "5567",
                "event_time": now.isoformat() + "Z",
            })
            print(f"USB {action} on {host} by {user} (serial={serial})")

        else:
            # File event(s) -- occasionally simulate a bulk-access burst
            burst = 1
            if random.random() < bulk_burst_chance:
                burst = random.randint(15, 20)
                print(f"** simulating bulk access burst ({burst} events) by {user} on {host} **")

            for _ in range(burst):
                path = random.choice(SENSITIVE_PATHS if random.random() < 0.5 else NORMAL_PATHS)
                action = random.choice(["read", "write"])
                local_hour = random.choice([2, 3, 9, 14, 23])  # mix of off-hours and business hours
                local_time = now.replace(hour=local_hour % 24)
                post(server, key, "/api/agent/file", {
                    "agent_id": f"agent-{host}",
                    "hostname": host,
                    "username": user,
                    "action": action,
                    "path": path,
                    "process": "explorer.exe",
                    "file_hash": fake_hash(path + str(now)),
                    "event_time": now.isoformat() + "Z",
                    "event_time_local": local_time.strftime("%Y-%m-%dT%H:%M:%S"),
                })
                time.sleep(0.15)
            print(f"File access x{burst} on {host} by {user}")

        time.sleep(interval)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", default="http://localhost:5000")
    ap.add_argument("--key", default="change-me-agent-key")
    ap.add_argument("--interval", type=float, default=2.0, help="seconds between events")
    ap.add_argument("--bulk-chance", type=float, default=0.12, help="probability of a bulk-access burst")
    args = ap.parse_args()
    run(args.server, args.key, args.interval, args.bulk_chance)
