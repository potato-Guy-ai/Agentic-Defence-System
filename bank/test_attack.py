"""
Manual attack test script.
Run this against the bank portal to simulate attacks.

Usage:
  python bank/test_attack.py --test brute
  python bank/test_attack.py --test flood
  python bank/test_attack.py --test travel
  python bank/test_attack.py --test all
"""

import argparse
import requests
import time

BASE = "http://localhost:8001"


def safe_get_logs():
    """Safely fetch logs without crashing if blocked (HTML response)."""
    try:
        resp = requests.get(f"{BASE}/api/logs")

        content_type = resp.headers.get("content-type", "")
        if "application/json" in content_type:
            return resp.json().get("logs", [])
        else:
            print("  ⚠ Could not fetch logs (response is not JSON — likely blocked)")
            return []
    except Exception as e:
        print(f"  ⚠ Error fetching logs: {e}")
        return []


def test_brute_force():
    print("\n[TEST] Brute Force — 25 wrong password attempts")
    for i in range(25):
        r = requests.post(
            f"{BASE}/login",
            data={"username": "alice", "password": "wrongpass"},
            allow_redirects=False
        )
        status = r.status_code
        print(f"  Attempt {i+1:02d}: HTTP {status}", "🚫 BLOCKED" if status == 403 else "")
        if status == 403:
            print("  ✅ Brute force detected and blocked.")
            break
        time.sleep(0.1)


def test_flood():
    print("\n[TEST] Flood Attack — 60 rapid requests")
    session = requests.Session()

    # Login first
    session.post(
        f"{BASE}/login",
        data={"username": "alice", "password": "password123"},
        allow_redirects=True
    )

    for i in range(60):
        r = session.get(f"{BASE}/dashboard", allow_redirects=False)
        status = r.status_code
        print(f"  Request {i+1:02d}: HTTP {status}", "🚫 BLOCKED" if status == 403 else "")
        if status == 403:
            print("  ✅ Flood attack detected and blocked.")
            break


def test_impossible_travel():
    print("\n[TEST] Impossible Travel — location switch")
    s = requests.Session()

    # Login from India
    s.post(
        f"{BASE}/login",
        data={"username": "bob", "password": "securepass"},
        headers={"X-Location": "India"},
        allow_redirects=True
    )

    print("  Logged in from India")
    time.sleep(1)

    # Try again from Russia
    r = s.get(f"{BASE}/dashboard", headers={"X-Location": "Russia"})
    print(f"  Request from Russia: HTTP {r.status_code}")

    if r.status_code == 403:
        print("  🚫 Blocked due to suspicious activity (likely impossible travel)")

    logs = safe_get_logs()

    if not logs:
        print("  ⚠ Logs unavailable (IP likely blocked)")
        return

    travel = [l for l in logs if l.get("threat") == "impossible_travel"]

    if travel:
        print(f"  ✅ Impossible travel detected: {travel[0]}")
    else:
        print("  ⚠ Not yet detected (may need more requests from different location)")


def show_logs():
    logs = safe_get_logs()

    if not logs:
        print("\n[LOGS] No logs available (blocked or empty).")
        return

    print(f"\n[LOGS] Last {min(10, len(logs))} events:")
    for l in logs[:10]:
        print(
            f"  {l['timestamp'][-8:]} | "
            f"{l['ip']:15s} | "
            f"{l['event']:20s} | "
            f"threat={l['threat']:20s} | "
            f"{l['action']}"
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--test", choices=["brute", "flood", "travel", "all"], default="all")
    args = parser.parse_args()

    if args.test in ("brute", "all"):
        test_brute_force()
    if args.test in ("flood", "all"):
        test_flood()
    if args.test in ("travel", "all"):
        test_impossible_travel()

    show_logs()