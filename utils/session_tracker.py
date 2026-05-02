"""
Session-Level Tracking
=======================
Tracks identity across requests using session tokens or cookie IDs.
Allows correlation of attacks from same user even if IP changes.
"""

import time
from collections import defaultdict
from typing import Optional

# session_id -> activity record
_sessions: dict = {}
# ip -> set of session_ids
_ip_sessions: dict = defaultdict(set)

SESSION_TTL = 1800  # 30 minutes
SUSPICIOUS_SESSION_EVENTS = 10


def _prune():
    now = time.time()
    expired = [sid for sid, s in _sessions.items() if now - s["last_seen"] > SESSION_TTL]
    for sid in expired:
        del _sessions[sid]


def record_event(session_id: Optional[str], ip: str, event_type: str, threat: Optional[str]):
    """Record an event against a session ID."""
    if not session_id:
        return

    now = time.time()
    if session_id not in _sessions:
        _sessions[session_id] = {
            "ips": set(), "events": [], "threats": [],
            "first_seen": now, "last_seen": now
        }

    s = _sessions[session_id]
    s["ips"].add(ip)
    s["events"].append(event_type)
    s["last_seen"] = now
    if threat:
        s["threats"].append(threat)

    _ip_sessions[ip].add(session_id)

    if len(_sessions) % 50 == 0:
        _prune()


def get_session_risk(session_id: Optional[str]) -> dict:
    """
    Returns session-level risk signals:
    - multiple IPs from same session = suspicious
    - high event count = suspicious
    - previous threats in session
    """
    if not session_id or session_id not in _sessions:
        return {"risk": "unknown"}

    s = _sessions[session_id]
    ip_count = len(s["ips"])
    event_count = len(s["events"])
    threat_count = len(s["threats"])

    risk = "low"
    if ip_count >= 3 or threat_count >= 2:
        risk = "high"
    elif ip_count >= 2 or event_count >= SUSPICIOUS_SESSION_EVENTS:
        risk = "medium"

    return {
        "risk": risk,
        "ip_count": ip_count,
        "event_count": event_count,
        "threat_count": threat_count,
        "ips": list(s["ips"]),
        "recent_threats": s["threats"][-5:],
    }


def get_sessions_for_ip(ip: str) -> list:
    """All session IDs seen from this IP."""
    return list(_ip_sessions.get(ip, []))
