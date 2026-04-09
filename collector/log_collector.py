"""
Lightweight Log Collector
=========================
Watches a log file and forwards parsed events to the /events API.

USAGE (demo/debug):
    python collector/log_collector.py --file data/logs.json --mode json
    python collector/log_collector.py --file /var/log/auth.log --mode tail

MODES:
    json  - replay a logs.json file (for demos/testing)
    tail  - tail a live log file line by line (for local syslog)

# FUTURE / EXTENSIBLE HOOKS (not implemented yet):
#   - mode: ids   -> receive Snort/Suricata unified2 alerts via socket
#   - mode: syslog -> listen on UDP 514 for remote syslog
#   - mode: winevt -> parse Windows Event Log XML via pywin32
# To add a new source: implement a generator in _source_<name>() and
# register it in the mode dispatch below.
"""

import argparse
import hashlib
import json
import os
import re
import time
from datetime import datetime

import requests
from dotenv import load_dotenv

load_dotenv()

API_URL = os.getenv("COLLECTOR_API_URL", "http://localhost:8000/events")
API_KEY = os.getenv("API_KEY", "")
HEADERS = {"X-Api-Key": API_KEY, "Content-Type": "application/json"}

# Track sent hashes to avoid duplicate sends within a session
_sent = set()


def _hash(event: dict) -> str:
    key = f"{event.get('ip')}|{event.get('event')}|{event.get('timestamp')}"
    return hashlib.md5(key.encode()).hexdigest()


def _send(event: dict):
    h = _hash(event)
    if h in _sent:
        return
    _sent.add(h)
    try:
        r = requests.post(API_URL, json=event, headers=HEADERS, timeout=5)
        print(f"[SENT] {event.get('ip')} | {event.get('event')} -> {r.status_code}")
    except Exception as e:
        print(f"[ERROR] Failed to send: {e}")


def _parse_syslog_line(line: str) -> dict | None:
    """Parse auth.log style lines into event schema."""
    line = line.strip()
    if not line:
        return None
    try:
        ip_match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line)
        ip = ip_match.group() if ip_match else "0.0.0.0"
        low = line.lower()
        if "failed password" in low or "authentication failure" in low or "invalid user" in low:
            event = "login_failed"
        elif "accepted password" in low or "accepted publickey" in low:
            event = "login_success"
        elif "port" in low and "scan" in low:
            event = "port_scan"
        elif "ddos" in low:
            event = "ddos_attempt"
        elif "malware" in low:
            event = "malware_download"
        else:
            event = "unknown"
        return {"ip": ip, "event": event, "timestamp": datetime.utcnow().isoformat()}
    except Exception:
        return None  # malformed line — skip safely


def _source_json(filepath: str):
    """Replay logs.json respecting relative timestamp gaps."""
    with open(filepath) as f:
        events = json.load(f)
    prev_ts = None
    for entry in events:
        try:
            ts = entry.get("timestamp", "")
            if prev_ts and ts:
                try:
                    fmt = "%H:%M"
                    gap = (datetime.strptime(ts, fmt) - datetime.strptime(prev_ts, fmt)).seconds
                    time.sleep(min(gap, 2))  # cap at 2s for demo speed
                except Exception:
                    time.sleep(0.3)
            prev_ts = ts
            yield entry
        except Exception:
            continue


def _source_tail(filepath: str):
    """Tail a live file. Blocks until new lines appear."""
    with open(filepath) as f:
        f.seek(0, 2)  # start from end
        while True:
            line = f.readline()
            if line:
                parsed = _parse_syslog_line(line)
                if parsed:
                    yield parsed
            else:
                time.sleep(0.5)


def run(mode: str, filepath: str):
    print(f"[COLLECTOR] Starting in '{mode}' mode -> {filepath}")
    print(f"[COLLECTOR] Forwarding to: {API_URL}")

    if mode == "json":
        source = _source_json(filepath)
    elif mode == "tail":
        source = _source_tail(filepath)
    else:
        raise ValueError(f"Unknown mode: {mode}")

    for event in source:
        _send(event)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Agentic Defence Log Collector")
    parser.add_argument("--file", default="data/logs.json", help="Path to log file")
    parser.add_argument("--mode", choices=["json", "tail"], default="json",
                        help="json=replay logs.json | tail=live file tail")
    args = parser.parse_args()
    run(args.mode, args.file)
