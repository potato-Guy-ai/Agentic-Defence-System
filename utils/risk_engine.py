"""
Unified Risk Scoring Engine
============================
Combines ML confidence, rule hits, rate, reputation, and correlation
into a single 0-100 risk score with breakdown.
"""

from typing import Optional

# Weights must sum to 1.0
WEIGHTS = {
    "rule_confidence": 0.35,
    "ml_score": 0.20,
    "rate_pressure": 0.15,
    "reputation": 0.15,
    "correlation": 0.15,
}

# Threat severity multipliers
THREAT_SEVERITY = {
    "multi_stage_attack": 1.0,
    "brute_force_high": 0.95,
    "data_exfiltration": 0.95,
    "malware": 0.95,
    "impossible_travel": 0.90,
    "flood_attack": 0.90,
    "ddos": 0.90,
    "privilege_escalation": 0.85,
    "lateral_movement": 0.85,
    "known_attacker": 0.85,
    "brute_force_medium": 0.75,
    "unauthorized_access": 0.75,
    "port_scan": 0.65,
    "brute_force_low": 0.60,
    "suspicious_behavior": 0.55,
    "anomaly": 0.45,
}


def calculate_risk(
    threat: Optional[str],
    rule_confidence: float,
    ml_anomaly: bool,
    request_rate: int,
    is_known_bad: bool,
    distributed: bool,
    ip_rotating: bool,
) -> dict:
    """
    Returns unified risk score (0-100) with component breakdown.
    """
    severity = THREAT_SEVERITY.get(threat or "", 0.3)

    rule_score = rule_confidence * severity
    ml_score = 0.8 if ml_anomaly else 0.0
    rate_score = min(request_rate / 50, 1.0)
    rep_score = 1.0 if is_known_bad else (0.6 if ip_rotating else 0.0)
    corr_score = 1.0 if distributed else (0.5 if ip_rotating else 0.0)

    combined = (
        rule_score * WEIGHTS["rule_confidence"] +
        ml_score * WEIGHTS["ml_score"] +
        rate_score * WEIGHTS["rate_pressure"] +
        rep_score * WEIGHTS["reputation"] +
        corr_score * WEIGHTS["correlation"]
    )

    score = min(int(combined * 100), 100)

    return {
        "risk_score": score,
        "breakdown": {
            "rule": round(rule_score, 3),
            "ml": round(ml_score, 3),
            "rate": round(rate_score, 3),
            "reputation": round(rep_score, 3),
            "correlation": round(corr_score, 3),
        }
    }
