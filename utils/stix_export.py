import uuid
from datetime import datetime, timezone

def build_stix_bundle(logs: list) -> dict:
    indicators = []
    for r in logs:
        if r.get("action") != "block":
            continue
        indicators.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": datetime.now(timezone.utc).isoformat(),
            "modified": datetime.now(timezone.utc).isoformat(),
            "name": f"Blocked IP: {r.get('ip')}",
            "description": r.get("reason", ""),
            "pattern": f"[ipv4-addr:value = '{r.get('ip')}']",
            "pattern_type": "stix",
            "valid_from": datetime.now(timezone.utc).isoformat(),
            "labels": [r.get("threat", "unknown")]
        })
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": indicators
    }