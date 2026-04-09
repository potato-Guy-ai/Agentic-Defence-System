"""
Adaptive Rule Engine
====================
Logs anomaly/suspicious events, periodically analyzes patterns,
generates rule suggestions — admin must approve before they apply.
"""

import threading
import time
from collections import Counter
from datetime import datetime, timezone

from utils.supabase_client import supabase

# Threat types that qualify as candidates for new rules
CANDIDATE_THREATS = {"anomaly", "suspicious_behavior", "unknown"}

# How often to run the analyzer (seconds)
ANALYZE_INTERVAL = 300  # 5 minutes

# Minimum occurrences before suggesting a rule
MIN_OCCURRENCES = 5


def log_candidate(ip: str, threat: str, event_type: str, confidence: float):
    """Store anomaly/suspicious events for later analysis."""
    if threat not in CANDIDATE_THREATS:
        return
    try:
        supabase.table("anomaly_candidates").insert({
            "ip": ip,
            "threat": threat,
            "event_type": event_type,
            "confidence": confidence,
            "created_at": datetime.now(timezone.utc).isoformat()
        }).execute()
    except Exception as e:
        print(f"[RULE_ENGINE] log_candidate error: {e}")


def _analyze_and_suggest():
    """Pull recent candidates, find patterns, insert suggestions."""
    try:
        rows = supabase.table("anomaly_candidates") \
            .select("*").order("created_at", desc=True).limit(500).execute().data
    except Exception as e:
        print(f"[RULE_ENGINE] fetch error: {e}")
        return

    if not rows:
        return

    # Count (event_type, threat) pairs
    counter = Counter((r["event_type"], r["threat"]) for r in rows)

    for (event_type, threat), count in counter.items():
        if count < MIN_OCCURRENCES:
            continue

        # Check if suggestion already exists (pending)
        try:
            existing = supabase.table("suggested_rules") \
                .select("id").eq("event_type", event_type) \
                .eq("status", "pending").execute().data
            if existing:
                continue
        except Exception:
            continue

        rule = {
            "event_type": event_type,
            "suggested_threat": threat,
            "occurrences": count,
            "suggested_confidence": min(0.5 + (count / 100), 0.85),
            "status": "pending",  # pending | approved | rejected
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        try:
            supabase.table("suggested_rules").insert(rule).execute()
            print(f"[RULE_ENGINE] New rule suggested: {event_type} -> {threat} ({count} occurrences)")
        except Exception as e:
            print(f"[RULE_ENGINE] insert error: {e}")


def load_approved_rules() -> dict:
    """
    Returns approved dynamic rules as:
    { event_type: (threat, confidence) }
    Called by DetectionAgent on each detect() pass.
    """
    try:
        rows = supabase.table("suggested_rules") \
            .select("*").eq("status", "approved").execute().data
        return {r["event_type"]: (r["suggested_threat"], r["suggested_confidence"]) for r in rows}
    except Exception:
        return {}


def start_analyzer():
    """Run the analyzer loop in a background daemon thread."""
    def loop():
        while True:
            time.sleep(ANALYZE_INTERVAL)
            print("[RULE_ENGINE] Running pattern analysis...")
            _analyze_and_suggest()

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    print("[RULE_ENGINE] Analyzer started (interval: 5 min)")
