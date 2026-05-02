"""
Geo-Intelligence
=================
Enriches IP events with country, ASN, VPN/proxy/Tor detection.
Uses ip-api.com (free, no key required, 45 req/min limit).
Optionally uses IPQualityScore for VPN/proxy detection (requires API key).
"""

import os
import time
import requests
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

IPQS_KEY = os.getenv("IPQS_KEY", "")

# Simple in-process cache: ip -> (result, timestamp)
_cache: dict = {}
CACHE_TTL = 3600  # 1 hour

HIGH_RISK_COUNTRIES = {"KP", "IR", "RU", "CN"}  # customise as needed


def _cached(ip: str) -> Optional[dict]:
    entry = _cache.get(ip)
    if entry and time.time() - entry["ts"] < CACHE_TTL:
        return entry["data"]
    return None


def lookup_ip(ip: str) -> dict:
    """
    Returns geo + risk info for an IP.
    Falls back to empty dict on failure (never blocks the pipeline).
    """
    if ip.startswith(("192.168.", "10.", "127.")):
        return {"private": True}

    cached = _cached(ip)
    if cached:
        return cached

    result = {}

    # Free geo lookup
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,countryCode,org,as,proxy,hosting"},
            timeout=3
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                result = {
                    "country": data.get("country", ""),
                    "country_code": data.get("countryCode", ""),
                    "org": data.get("org", ""),
                    "asn": data.get("as", ""),
                    "is_proxy": data.get("proxy", False),
                    "is_hosting": data.get("hosting", False),
                    "high_risk_country": data.get("countryCode", "") in HIGH_RISK_COUNTRIES,
                }
    except Exception:
        pass

    # Optional IPQS VPN/proxy/Tor check
    if IPQS_KEY and result:
        try:
            r2 = requests.get(
                f"https://ipqualityscore.com/api/json/ip/{IPQS_KEY}/{ip}",
                timeout=3
            )
            if r2.status_code == 200:
                d2 = r2.json()
                result["is_vpn"] = d2.get("vpn", False)
                result["is_tor"] = d2.get("tor", False)
                result["fraud_score"] = d2.get("fraud_score", 0)
        except Exception:
            pass

    _cache[ip] = {"data": result, "ts": time.time()}
    return result


def geo_risk_bonus(geo: dict) -> float:
    """
    Returns a 0.0-0.3 confidence bonus based on geo risk signals.
    Added on top of existing threat confidence.
    """
    bonus = 0.0
    if geo.get("high_risk_country"):
        bonus += 0.1
    if geo.get("is_proxy") or geo.get("is_vpn"):
        bonus += 0.15
    if geo.get("is_tor"):
        bonus += 0.2
    if geo.get("is_hosting"):  # datacenter/VPS = suspicious for login events
        bonus += 0.05
    return min(bonus, 0.3)
