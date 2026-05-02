"""
Distributed Attack Detector
============================
Detects low-and-slow distributed attacks: many IPs each sending
few requests that individually look innocent but collectively form
a coordinated attack pattern.
"""

import time
from collections import defaultdict
from typing import Optional

# Sliding window store: (event_type) -> list of {ip, ts}
_event_window: dict = defaultdict(list)

WINDOW = 120          # 2-minute window
IP_THRESHOLD = 5      # how many distinct IPs for same event_type = distributed
GLOBAL_RATE_THRESHOLD = 30  # total events across all IPs in window


def record(ip: str, event_type: str):
    now = time.time()
    _event_window[event_type].append({"ip": ip, "ts": now})
    # Prune old entries
    _event_window[event_type] = [
        e for e in _event_window[event_type]
        if now - e["ts"] < WINDOW
    ]


def check(ip: str, event_type: str) -> Optional[dict]:
    """
    Returns distributed attack info if pattern is detected,
    None otherwise.
    """
    entries = _event_window.get(event_type, [])
    unique_ips = {e["ip"] for e in entries}

    if len(unique_ips) >= IP_THRESHOLD:
        other_ips = [i for i in unique_ips if i != ip]
        return {
            "type": "distributed_attack",
            "event_type": event_type,
            "unique_ips": len(unique_ips),
            "total_events": len(entries),
            "other_ips": other_ips[:10],  # cap for log size
            "window_seconds": WINDOW,
        }
    return None
