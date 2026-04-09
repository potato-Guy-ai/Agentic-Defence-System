"""
SOC Response Playbook Generator
================================
Generates recommended (NOT executed) response commands based on
threat type, confidence, and risk score.

All output is advisory only — no real commands are run.
"""

from typing import List

# Playbook map: threat -> list of recommended actions
_PLAYBOOK: dict[str, List[str]] = {
    "brute_force_high": [
        "Block IP at firewall: `iptables -A INPUT -s {ip} -j DROP`",
        "Disable affected user account temporarily",
        "Force password reset for targeted accounts",
        "Enable account lockout policy (threshold: 5 attempts)",
        "Alert SOC team — possible credential stuffing campaign",
    ],
    "brute_force_medium": [
        "Rate-limit IP at firewall",
        "Monitor affected accounts for successful logins",
        "Notify account owner of suspicious activity",
    ],
    "brute_force_low": [
        "Log and monitor — threshold not yet critical",
        "Add IP to watchlist",
    ],
    "ddos": [
        "Enable rate limiting on load balancer",
        "Block source IP range at upstream firewall",
        "Activate CDN DDoS protection if available",
        "Scale out application layer if traffic is legitimate",
        "Alert network team immediately",
    ],
    "flood_attack": [
        "Block IP at firewall: `iptables -A INPUT -s {ip} -j DROP`",
        "Enable connection throttling on affected service",
        "Review upstream firewall rules for rate limiting",
    ],
    "malware": [
        "Isolate endpoint from network immediately",
        "Initiate forensic image of affected system",
        "Scan all connected systems for same malware signature",
        "Block malware source domain/IP at DNS and firewall",
        "Notify IR team and begin incident response procedure",
    ],
    "data_exfiltration": [
        "Block IP at firewall immediately",
        "Revoke API keys and tokens associated with source IP",
        "Audit data access logs for scope of exfiltration",
        "Notify data protection officer (DPO) — possible GDPR breach",
        "Preserve all related logs for forensic investigation",
    ],
    "impossible_travel": [
        "Force re-authentication on affected account",
        "Temporarily disable account pending review",
        "Check if VPN or proxy is in use",
        "Notify account owner of suspicious login locations",
    ],
    "privilege_escalation": [
        "Revoke elevated privileges immediately",
        "Review sudo/admin access logs for affected account",
        "Disable compromised account",
        "Audit all admin actions taken in the last 24 hours",
    ],
    "lateral_movement": [
        "Isolate affected systems from internal network",
        "Review authentication logs across all accessed systems",
        "Reset credentials for all systems accessed by source IP",
        "Deploy honeypot on adjacent systems to track movement",
    ],
    "port_scan": [
        "Block scanning IP at perimeter firewall",
        "Review exposed services — close unnecessary open ports",
        "Enable port scan detection alerts on IDS/IPS",
    ],
    "unauthorized_access": [
        "Disconnect unknown device from network",
        "Review DHCP leases and MAC address table",
        "Enable 802.1X port-based authentication",
    ],
    "multi_stage_attack": [
        "CRITICAL: Block IP at all network layers immediately",
        "Isolate all endpoints accessed by source IP",
        "Initiate full incident response procedure",
        "Preserve all logs — do not rotate until investigation complete",
        "Escalate to senior SOC analyst / CISO",
        "Begin threat hunting across entire network segment",
    ],
    "known_attacker": [
        "Block IP at firewall — known malicious actor",
        "Cross-reference with threat intel feed for associated IOCs",
        "Check for other connections from same ASN/subnet",
    ],
    "anomaly": [
        "Flag for manual review by analyst",
        "Increase monitoring on source IP for 24 hours",
        "Correlate with other recent anomalies from same subnet",
    ],
    "suspicious_behavior": [
        "Add IP to elevated monitoring tier",
        "Review all actions from this IP in the last hour",
        "Consider temporary IP block pending analyst review",
    ],
}

_DEFAULT = [
    "Log and monitor — no specific playbook for this threat type",
    "Increase logging verbosity on affected systems",
]


def get_playbook(threat: str, ip: str, risk_score: int, action: str) -> List[str]:
    """
    Returns list of recommended response steps.
    Substitutes {ip} placeholder with actual IP.
    """
    steps = _PLAYBOOK.get(threat, _DEFAULT)
    result = [s.replace("{ip}", ip) for s in steps]

    # Add severity header
    if risk_score >= 90:
        result.insert(0, "SEVERITY: CRITICAL — Immediate action required")
    elif risk_score >= 70:
        result.insert(0, "SEVERITY: HIGH — Action required within 15 minutes")
    elif risk_score >= 50:
        result.insert(0, "SEVERITY: MEDIUM — Review within 1 hour")
    else:
        result.insert(0, "SEVERITY: LOW — Monitor and log")

    return result
