"""
Time-Based Behavioral Profiling
================================
Builds per-IP behavioral baselines over time.
Detects deviations: unusual hours, sudden frequency spikes, new event types.
"""

import time
from collections import defaultdict, Counter
from datetime import datetime
from typing import Optional

# ip -> profile
_profiles: dict = {}

MIN_EVENTS_FOR_BASELINE = 10


def _get_profile(ip: str) -> dict:
    if ip not in _profiles:
        _profiles[ip] = {
            "event_counts": Counter(),
            "hour_counts": Counter(),
            "total": 0,
            "first_seen": time.time(),
            "last_seen": time.time(),
        }
    return _profiles[ip]


def record(ip: str, event_type: str):
    """Update behavioral profile for an IP."""
    p = _get_profile(ip)
    p["event_counts"][event_type] += 1
    p["hour_counts"][datetime.utcnow().hour] += 1
    p["total"] += 1
    p["last_seen"] = time.time()


def check_deviation(ip: str, event_type: str) -> Optional[dict]:
    """
    Returns deviation info if current behavior deviates from baseline.
    Only meaningful after MIN_EVENTS_FOR_BASELINE events.
    """
    p = _get_profile(ip)
    if p["total"] < MIN_EVENTS_FOR_BASELINE:
        return None

    signals = []
    hour = datetime.utcnow().hour

    # Unusual hour: current hour has never been seen before
    if p["hour_counts"].get(hour, 0) == 0 and p["total"] >= 20:
        signals.append(f"activity at unusual hour ({hour}:00 UTC)")

    # New event type never seen before from this IP
    if p["event_counts"].get(event_type, 0) == 0 and p["total"] >= 15:
        signals.append(f"new event type '{event_type}' not seen before from this IP")

    # Sudden burst: event type count doubled from expected average
    avg_per_type = p["total"] / max(len(p["event_counts"]), 1)
    current = p["event_counts"].get(event_type, 0)
    if current > avg_per_type * 3 and current > 5:
        signals.append(f"unusual frequency of '{event_type}' ({current}x vs avg {avg_per_type:.1f})")

    if signals:
        return {
            "deviation": True,
            "signals": signals,
            "total_events": p["total"],
        }
    return None
