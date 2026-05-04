"""
Fake Bank Portal
=================
FastAPI app with login, dashboard, logout.
Every request runs through DetectionMiddleware.
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
import uuid

from agents.detection import DetectionAgent
from agents.coordinator import CoordinatorAgent
from agents.decision import DecisionAgent
from utils.supabase_client import supabase

app = FastAPI(title="SecureBank Portal")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

detection   = DetectionAgent()
coordinator = CoordinatorAgent()
decision_ag = DecisionAgent()

# In-memory stores
blocked_ips: set = set()
sessions: dict   = {}   # token -> {ip, username}
event_log: list  = []   # local log (max 500)

# Fake users
USERS = {"alice": "password123", "bob": "securepass", "admin": "admin999"}

# All threats that should result in a block — single source of truth
BLOCKABLE_THREATS = {
    "flood_attack",
    "brute_force_high",
    "multi_stage_attack",
    "malware",
    "data_exfiltration",
    "impossible_travel",
    "privilege_escalation",
    "lateral_movement",
    "known_attacker",
    "distributed_attack",
}

# Risk score threshold above which we always block (regardless of threat name)
BLOCK_RISK_THRESHOLD = 80


# ── Helpers ───────────────────────────────────────────────────────────────────

def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host


def get_location(request: Request) -> str:
    return request.headers.get("x-location", "Unknown")


def log_event(ip, event, threat, confidence, action, reason):
    entry = {
        "ip": ip, "event": event, "threat": threat or "none",
        "confidence": round(confidence, 2), "action": action,
        "reason": reason, "timestamp": datetime.utcnow().isoformat()
    }
    event_log.append(entry)
    if len(event_log) > 500:
        event_log.pop(0)
    try:
        supabase.table("threat_logs").insert({
            "ip": ip, "threat": threat or "none", "action": action,
            "risk_score": int(confidence * 100), "reason": reason
        }).execute()
    except Exception:
        pass


def block_ip(ip: str):
    """Single function that ensures IP is blocked in memory AND Supabase."""
    blocked_ips.add(ip)
    try:
        # upsert-style: ignore if already exists
        existing = supabase.table("blacklist").select("ip").eq("ip", ip).execute()
        if not existing.data:
            supabase.table("blacklist").insert({"ip": ip}).execute()
    except Exception:
        pass


def run_detection(ip: str, event_type: str, location: str = "Unknown") -> dict:
    """Run full detection pipeline. Returns normalised result dict."""
    event       = {"ip": ip, "event": event_type, "location": location}
    threat_msg  = detection.detect(event)
    coordinated = coordinator.process(threat_msg)
    decision    = decision_ag.decide(coordinated)

    # Raw threat data even when decision is None
    raw_threat      = threat_msg["data"].get("threat") if threat_msg else None
    raw_confidence  = threat_msg["data"].get("confidence", 0) if threat_msg else 0
    raw_reasons     = threat_msg["data"].get("reasons", []) if threat_msg else []

    if decision is None:
        return {
            "action": "ignore", "threat": raw_threat,
            "confidence": raw_confidence, "risk_score": 0,
            "reasons": raw_reasons,
        }

    d = decision["data"]
    # Prefer threat from decision (coordinator may enrich it), fall back to raw
    threat = d.get("threat") or raw_threat

    return {
        "action":     d.get("action", "ignore"),
        "threat":     threat,
        "confidence": raw_confidence,
        "risk_score": d.get("risk_score", 0),
        "reasons":    d.get("reasons", raw_reasons),
    }


def should_block(result: dict) -> bool:
    """
    Returns True if the result warrants blocking.
    Two independent conditions — either is sufficient:
      1. Decision action is already 'block' (risk_score > 80)
      2. Threat type is in the BLOCKABLE_THREATS set
    This ensures high-confidence threats like impossible_travel
    are blocked even if the risk_score calculation is borderline.
    """
    threat = result.get("threat") or ""
    return (
        result.get("action") == "block"
        or result.get("risk_score", 0) >= BLOCK_RISK_THRESHOLD
        or threat in BLOCKABLE_THREATS
    )


# ── Middleware ────────────────────────────────────────────────────────────────

@app.middleware("http")
async def detection_middleware(request: Request, call_next):
    ip   = get_client_ip(request)
    path = request.url.path

    if path in ("/health", "/favicon.ico") or path.startswith(("/static", "/api")):
        return await call_next(request)

    if ip in blocked_ips:
        return HTMLResponse(BLOCKED_HTML.format(ip=ip), status_code=403)

    event_type = _path_to_event(path, request.method)
    if event_type:
        location = get_location(request)
        result   = run_detection(ip, event_type, location)
        log_event(ip, event_type, result["threat"], result["confidence"],
                  result["action"], ", ".join(result["reasons"]))
        if should_block(result):
            block_ip(ip)
            return HTMLResponse(BLOCKED_HTML.format(ip=ip), status_code=403)

    return await call_next(request)


def _path_to_event(path: str, method: str):
    mapping = {
        ("/login",     "GET"):  "page_view",
        ("/login",     "POST"): None,
        ("/dashboard", "GET"):  "page_view",
        ("/logout",    "GET"):  "logout",
        ("/admin",     "GET"):  "admin_access",
    }
    return mapping.get((path, method))


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def root():
    return RedirectResponse("/login")


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = ""):
    return HTMLResponse(LOGIN_HTML.format(
        error=f'<p class="error">{error}</p>' if error else ""
    ))


@app.post("/login", response_class=HTMLResponse)
async def login_submit(request: Request,
                       username: str = Form(...), password: str = Form(...)):
    ip       = get_client_ip(request)
    location = get_location(request)

    if ip in blocked_ips:
        return HTMLResponse(BLOCKED_HTML.format(ip=ip), status_code=403)

    if USERS.get(username) == password:
        result = run_detection(ip, "login_success", location)
        log_event(ip, "login_success", result["threat"], result["confidence"],
                  result["action"], ", ".join(result["reasons"]))
        if should_block(result):
            block_ip(ip)
            return HTMLResponse(BLOCKED_HTML.format(ip=ip), status_code=403)

        token = str(uuid.uuid4())
        sessions[token] = {"ip": ip, "username": username}
        resp = RedirectResponse("/dashboard", status_code=302)
        resp.set_cookie("session", token)
        return resp
    else:
        result = run_detection(ip, "login_failed", location)
        log_event(ip, "login_failed", result["threat"], result["confidence"],
                  result["action"], ", ".join(result["reasons"]))
        if should_block(result):
            block_ip(ip)
            return HTMLResponse(BLOCKED_HTML.format(ip=ip), status_code=403)

        threat_note = f" ({result['threat']})" if result.get("threat") else ""
        return RedirectResponse(
            f"/login?error=Invalid+credentials{threat_note}", status_code=302
        )


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    ip    = get_client_ip(request)
    token = request.cookies.get("session")
    user  = sessions.get(token, {}).get("username", "Guest")

    recent  = event_log[-20:][::-1]
    rows    = "".join([
        f"<tr>"
        f"<td>{e['timestamp'][-8:]}</td>"
        f"<td>{e['ip']}</td>"
        f"<td>{e['event']}</td>"
        f"<td class='{'threat' if e['threat'] not in ('none','') else ''}'>{e['threat']}</td>"
        f"<td>{e['action']}</td>"
        f"</tr>"
        for e in recent
    ])
    bl_rows = "".join(
        f"<tr><td>{bip}</td></tr>" for bip in list(blocked_ips)[-20:]
    )
    return HTMLResponse(DASHBOARD_HTML.format(
        user=user, ip=ip,
        rows=rows or "<tr><td colspan='5'>No events yet</td></tr>",
        bl_rows=bl_rows or "<tr><td>No blocked IPs</td></tr>",
        total=len(event_log), blocked_count=len(blocked_ips)
    ))


@app.get("/logout")
async def logout(request: Request):
    token = request.cookies.get("session")
    sessions.pop(token, None)
    resp = RedirectResponse("/login")
    resp.delete_cookie("session")
    return resp


@app.get("/health")
async def health():
    return {"status": "ok", "blocked_ips": len(blocked_ips), "events": len(event_log)}


@app.get("/api/logs")
async def api_logs():
    return {"logs": list(reversed(event_log[-100:]))}


@app.get("/api/blocked")
async def api_blocked():
    return {"blocked_ips": list(blocked_ips)}


@app.post("/api/unblock/{ip}")
async def api_unblock(ip: str):
    blocked_ips.discard(ip)
    try:
        supabase.table("blacklist").delete().eq("ip", ip).execute()
    except Exception:
        pass
    return {"status": "unblocked", "ip": ip}


# ── HTML Templates ────────────────────────────────────────────────────────────

LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecureBank — Login</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:system-ui,sans-serif;background:#0a0f1e;min-height:100vh;display:flex;align-items:center;justify-content:center}}
  .card{{background:#111827;border:1px solid #1f2937;border-radius:12px;padding:2.5rem;width:380px;box-shadow:0 20px 60px rgba(0,0,0,.5)}}
  .logo{{text-align:center;margin-bottom:2rem}}
  .logo-icon{{font-size:2.5rem}}
  .logo h1{{color:#fff;font-size:1.4rem;margin-top:.5rem}}
  .logo p{{color:#6b7280;font-size:.82rem;margin-top:.25rem}}
  label{{display:block;color:#9ca3af;font-size:.8rem;margin-bottom:.4rem;margin-top:1rem}}
  input{{width:100%;padding:.65rem .9rem;background:#1f2937;border:1px solid #374151;border-radius:8px;color:#fff;font-size:.9rem;outline:none}}
  input:focus{{border-color:#3b82f6}}
  button{{width:100%;margin-top:1.5rem;padding:.75rem;background:#2563eb;color:#fff;border:none;border-radius:8px;font-size:.95rem;cursor:pointer;font-weight:600}}
  button:hover{{background:#1d4ed8}}
  .error{{color:#f87171;font-size:.82rem;margin-top:.75rem;text-align:center;padding:.5rem;background:#3d1515;border-radius:6px}}
  .hint{{color:#374151;font-size:.75rem;text-align:center;margin-top:1.25rem}}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <div class="logo-icon">🏦</div>
    <h1>SecureBank</h1>
    <p>Protected by Agentic Defence System</p>
  </div>
  <form method="post" action="/login">
    <label>Username</label>
    <input name="username" type="text" placeholder="Enter username" required autofocus>
    <label>Password</label>
    <input name="password" type="password" placeholder="Enter password" required>
    <button type="submit">Sign In</button>
    {error}
  </form>
  <p class="hint">Test users: alice / bob / admin</p>
</div>
</body>
</html>"""

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="5">
<title>SecureBank — Dashboard</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:system-ui,sans-serif;background:#0a0f1e;color:#e5e7eb;min-height:100vh}}
  header{{background:#111827;border-bottom:1px solid #1f2937;padding:1rem 2rem;display:flex;justify-content:space-between;align-items:center}}
  header h1{{color:#fff;font-size:1.1rem}}
  header span{{color:#6b7280;font-size:.85rem}}
  .logout{{color:#f87171;text-decoration:none;font-size:.85rem;margin-left:1rem}}
  .main{{padding:2rem;max-width:1100px;margin:0 auto}}
  .cards{{display:flex;gap:1rem;margin-bottom:2rem;flex-wrap:wrap}}
  .card{{background:#111827;border:1px solid #1f2937;border-radius:10px;padding:1.25rem 1.5rem;flex:1;min-width:140px}}
  .card-label{{font-size:.75rem;color:#6b7280}}
  .card-val{{font-size:1.8rem;font-weight:600;color:#fff;margin-top:.25rem}}
  h2{{font-size:1rem;color:#9ca3af;margin-bottom:.75rem}}
  table{{width:100%;border-collapse:collapse;background:#111827;border-radius:10px;overflow:hidden;margin-bottom:1.5rem}}
  th{{text-align:left;padding:.6rem 1rem;font-size:.75rem;color:#6b7280;border-bottom:1px solid #1f2937}}
  td{{padding:.55rem 1rem;font-size:.82rem;border-bottom:1px solid #1a2332;font-family:monospace}}
  .threat{{color:#f87171;font-weight:600}}
  .info-box{{background:#111827;border:1px solid #1f2937;border-radius:10px;padding:1.25rem;font-size:.82rem;color:#6b7280}}
  .info-box strong{{color:#fff}}
</style>
</head>
<body>
<header>
  <h1>🏦 SecureBank</h1>
  <div>
    <span>Welcome, <strong style="color:#fff">{user}</strong> | Your IP: <strong style="color:#60a5fa">{ip}</strong></span>
    <a class="logout" href="/logout">Logout</a>
  </div>
</header>
<div class="main">
  <div class="cards">
    <div class="card"><div class="card-label">Total Events</div><div class="card-val">{total}</div></div>
    <div class="card"><div class="card-label">Blocked IPs</div><div class="card-val" style="color:#f87171">{blocked_count}</div></div>
    <div class="card"><div class="card-label">Status</div><div class="card-val" style="color:#4ade80;font-size:1rem;margin-top:.5rem">🟢 Protected</div></div>
  </div>
  <h2>Live Event Log (auto-refreshes every 5s)</h2>
  <table>
    <thead><tr><th>Time</th><th>IP</th><th>Event</th><th>Threat</th><th>Action</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
  <h2>Blocked IPs</h2>
  <table>
    <thead><tr><th>IP Address</th></tr></thead>
    <tbody>{bl_rows}</tbody>
  </table>
  <div class="info-box">
    <strong>Attack Testing Guide</strong><br><br>
    🔴 <strong>Brute Force:</strong> Try wrong password 20+ times → IP gets blocked<br>
    🔴 <strong>Flood Attack:</strong> Refresh this page rapidly 50+ times → flood_attack detected<br>
    🟡 <strong>Impossible Travel:</strong> Add header <code>X-Location: Russia</code> after login from India<br>
    🟡 <strong>Admin Access:</strong> Visit <code>/admin</code> → privilege escalation detected
  </div>
</div>
</body>
</html>"""

BLOCKED_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Access Denied</title>
<style>
  body{{font-family:system-ui,sans-serif;background:#0a0f1e;color:#fff;min-height:100vh;display:flex;align-items:center;justify-content:center;text-align:center}}
  .box{{background:#111827;border:1px solid #3d1515;border-radius:12px;padding:3rem;max-width:420px}}
  h1{{color:#f87171;font-size:2rem;margin-bottom:1rem}}
  p{{color:#9ca3af;margin:.5rem 0}}
  code{{background:#1f2937;padding:2px 8px;border-radius:4px;color:#f87171}}
  a{{color:#3b82f6;margin-top:1.5rem;display:inline-block}}
</style>
</head>
<body>
<div class="box">
  <h1>🚫 Access Denied</h1>
  <p>Your IP has been blocked by the</p>
  <p><strong>Agentic Defence System</strong></p>
  <br>
  <p>Blocked IP: <code>{ip}</code></p>
  <p>Reason: Suspicious / malicious activity detected</p>
  <br>
  <p style="font-size:.8rem;color:#6b7280">Contact your administrator to unblock your IP.</p>
  <a href="/api/logs">View event log →</a>
</div>
</body>
</html>"""


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("bank_app:app", host="0.0.0.0", port=8001, reload=True)
