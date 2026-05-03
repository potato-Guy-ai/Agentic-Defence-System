"""
Visualization Data API
=======================
Provides aggregated data endpoints for dashboard charts and heatmaps.
All computation is in-memory from Supabase — no extra DB queries beyond what
the dashboard already does.
"""

from collections import Counter, defaultdict
from typing import List


def build_heatmap(logs: List[dict]) -> list:
    """
    Builds a 24x7 heatmap matrix (hour x weekday) of event counts.
    Returns list of {hour, day, count} dicts.
    """
    from datetime import datetime
    matrix = defaultdict(int)
    for r in logs:
        ts = r.get("created_at")
        if not ts:
            continue
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            matrix[(dt.hour, dt.weekday())] += 1
        except Exception:
            continue

    result = []
    for hour in range(24):
        for day in range(7):
            result.append({"hour": hour, "day": day, "count": matrix[(hour, day)]})
    return result


def build_threat_trend(logs: List[dict], days: int = 7) -> list:
    """
    Returns daily threat counts for the last N days.
    Format: [{date, count, blocked, alerted}]
    """
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)
    buckets = {}
    for i in range(days):
        d = (now - timedelta(days=i)).strftime("%Y-%m-%d")
        buckets[d] = {"date": d, "count": 0, "blocked": 0, "alerted": 0}

    for r in logs:
        ts = r.get("created_at")
        if not ts:
            continue
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            d = dt.strftime("%Y-%m-%d")
            if d in buckets:
                buckets[d]["count"] += 1
                if r.get("action") == "block":
                    buckets[d]["blocked"] += 1
                elif r.get("action") == "alert":
                    buckets[d]["alerted"] += 1
        except Exception:
            continue

    return sorted(buckets.values(), key=lambda x: x["date"])


def build_top_ips(logs: List[dict], limit: int = 10) -> list:
    """Top IPs by event count."""
    counter = Counter(r["ip"] for r in logs if r.get("ip"))
    return [{"ip": ip, "count": c} for ip, c in counter.most_common(limit)]


def build_threat_distribution(logs: List[dict]) -> list:
    """Threat type distribution."""
    counter = Counter(r["threat"] for r in logs if r.get("threat"))
    return [{"threat": t, "count": c} for t, c in counter.most_common()]
 