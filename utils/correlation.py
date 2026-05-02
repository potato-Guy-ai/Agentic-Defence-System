"""
Cross-IP Attack Correlation
============================
Links IPs that show similar attack patterns within a time window.
Used to detect coordinated/distributed attacks from different sources.
"""

from collections import defaultdict
import time
from typing import Dict, List, Optional

# Shared in-process store — replace with Redis for multi-process
_subnet_activity: Dict[str, List[dict]] = defaultdict(list)
_ip_fingerprints: Dict[str, dict] = {}  # ip -> {user_agent, asn, ...}

CORRELATION_WINDOW = 300   # 5 minutes
SUBNET_THREAT_THRESHOLD = 3  # IPs from same /24 triggering threats


def _subnet(ip: str) -> str:
    parts = ip.split(".")
    return ".".join(parts[:3]) if len(parts) == 4 else ip


def record_threat(ip: str, threat: str, confidence: float):
    """Call after each detection to track subnet-level patterns."""
    now = time.time()
    subnet = _subnet(ip)
    _subnet_activity[subnet].append({
        "ip": ip, "threat": threat,
        "confidence": confidence, "ts": now
    })
    # Prune old entries
    _subnet_activity[subnet] = [
        e for e in _subnet_activity[subnet]
        if now - e["ts"] < CORRELATION_WINDOW
    ]


def check_distributed_attack(ip: str) -> Optional[dict]:
    """
    Returns correlation info if multiple IPs from same /24
    are triggering threats within the window.
    """
    subnet = _subnet(ip)
    entries = _subnet_activity.get(subnet, [])
    unique_ips = {e["ip"] for e in entries}

    if len(unique_ips) >= SUBNET_THREAT_THRESHOLD:
        threats = [e["threat"] for e in entries]
        avg_conf = sum(e["confidence"] for e in entries) / len(entries)
        return {
            "subnet": f"{subnet}.0/24",
            "unique_ips": len(unique_ips),
            "events": len(entries),
            "common_threats": list(set(threats)),
            "avg_confidence": round(avg_conf, 2),
        }
    return None


def get_correlated_ips(ip: str) -> List[str]:
    """Return other IPs from same /24 that have recent threat activity."""
    subnet = _subnet(ip)
    return list({e["ip"] for e in _subnet_activity.get(subnet, []) if e["ip"] != ip})
