"""
Device / Request Fingerprinting
=================================
Extracts identity signals from HTTP request headers beyond IP.
Used to track attackers who rotate IPs but keep same device/browser.
"""

import hashlib
from typing import Optional
from fastapi import Request

_fingerprint_store: dict = {}  # fingerprint_hash -> list of IPs seen
_ip_fingerprint_map: dict = {}  # ip -> fingerprint_hash


def extract_fingerprint(request: Request) -> dict:
    """Extract browser/device signals from request headers."""
    headers = request.headers
    return {
        "user_agent": headers.get("user-agent", ""),
        "accept_language": headers.get("accept-language", ""),
        "accept_encoding": headers.get("accept-encoding", ""),
        "accept": headers.get("accept", ""),
        "connection": headers.get("connection", ""),
        "x_forwarded_for": headers.get("x-forwarded-for", ""),
    }


def fingerprint_hash(fp: dict) -> str:
    """Stable hash of the fingerprint signals."""
    raw = "|".join([
        fp.get("user_agent", ""),
        fp.get("accept_language", ""),
        fp.get("accept_encoding", ""),
    ])
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def record_fingerprint(ip: str, request: Request) -> dict:
    """Store fingerprint for an IP and detect IP-rotation."""
    fp = extract_fingerprint(request)
    fhash = fingerprint_hash(fp)

    _ip_fingerprint_map[ip] = fhash

    if fhash not in _fingerprint_store:
        _fingerprint_store[fhash] = {"ips": set(), "fingerprint": fp}
    _fingerprint_store[fhash]["ips"].add(ip)

    return {
        "hash": fhash,
        "ip_count": len(_fingerprint_store[fhash]["ips"]),
        "all_ips": list(_fingerprint_store[fhash]["ips"]),
    }


def is_rotating_ips(ip: str) -> Optional[dict]:
    """
    Returns info if this fingerprint has been seen from 3+ IPs.
    Signals IP rotation by same device/attacker.
    """
    fhash = _ip_fingerprint_map.get(ip)
    if not fhash:
        return None
    store = _fingerprint_store.get(fhash, {})
    ips = store.get("ips", set())
    if len(ips) >= 3:
        return {
            "fingerprint_hash": fhash,
            "ip_count": len(ips),
            "ips": list(ips),
        }
    return None
