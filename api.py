from fastapi import FastAPI, Request, Header, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import os
import requests

from agents.detection import DetectionAgent
from agents.coordinator import CoordinatorAgent
from agents.decision import DecisionAgent
from agents.response import ResponseAgent
from agents.feedback import FeedbackAgent
from agents.filter import FilterAgent
from agents.normalizer import NormalizerAgent
from models.anomaly import AnomalyModel
from utils.supabase_client import supabase
from utils.rule_engine import start_analyzer
from utils.playbook import get_playbook

API_KEY = os.getenv("API_KEY", "")
DISCORD_WEBHOOK = os.getenv("WEBHOOK_URL")

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="Agentic Defence System")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

model = AnomalyModel()
detection = DetectionAgent()
coordinator = CoordinatorAgent()
decision_agent = DecisionAgent()
response_agent = ResponseAgent()
feedback = FeedbackAgent(anomaly_model=model)
filter_agent = FilterAgent()
normalizer = NormalizerAgent()

# Start adaptive rule analyzer in background
start_analyzer()


def verify_api_key(x_api_key: Optional[str]):
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


def _send_discord(message: str):
    if not DISCORD_WEBHOOK:
        return
    try:
        import requests as req
        req.post(DISCORD_WEBHOOK, json={"content": message}, timeout=4)
    except Exception:
        pass


class EventPayload(BaseModel):
    ip: str
    event: str
    location: Optional[str] = None
    timestamp: Optional[str] = None


@app.post("/events")
@limiter.limit("60/minute")
async def receive_event(request: Request, payload: EventPayload,
                        x_api_key: Optional[str] = Header(None)):
    verify_api_key(x_api_key)
    event = normalizer.normalize(payload.dict())
    if not event or not filter_agent.is_relevant(event):
        return {"status": "ignored"}

    threat = detection.detect(event)
    coordinated = coordinator.process(threat)
    decision = decision_agent.decide(coordinated)
    response_agent.execute(decision)
    feedback.update(decision)

    if decision is None:
        return {"status": "no_action"}

    d = decision["data"]
    ip = d["ip"]
    action = d["action"]
    risk = d["risk_score"]
    threat_type = d.get("threat", threat['data']['threat'])


    # Generate SOC playbook
    playbook = get_playbook(threat_type, ip, risk, action)

    # Store playbook in threat log
    try:
        supabase.table("threat_logs").insert({
            "ip": ip,
            "threat": threat_type,
            "action": action,
            "risk_score": risk,
            "reason": ", ".join(d["reasons"]),
            "playbook": "\n".join(playbook)
        }).execute()
    except Exception:
        pass

    # Discord alert with playbook
    if action in ("block", "alert"):
        steps = "\n".join(f"  {i+1}. {s}" for i, s in enumerate(playbook[:4]))
        _send_discord(
            f"**[{action.upper()}]** `{ip}` | Threat: `{threat_type}` | Risk: `{risk}`\n"
            f"**Recommended Actions:**\n{steps}"
        )

    return {
        "status": "processed",
        "ip": ip,
        "action": action,
        "risk_score": risk,
        "reasons": d["reasons"],
        "playbook": playbook
    }


@app.get("/health")
async def health():
    return {"status": "ok"}


# ── Adaptive Rule Admin Endpoints ──────────────────────────────────────────────

@app.get("/rules/suggested")
async def get_suggested_rules(x_api_key: Optional[str] = Header(None)):
    verify_api_key(x_api_key)
    try:
        rows = supabase.table("suggested_rules").select("*") \
            .eq("status", "pending").order("occurrences", desc=True).execute().data
        return {"rules": rows}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/rules/{rule_id}/approve")
async def approve_rule(rule_id: int, x_api_key: Optional[str] = Header(None)):
    verify_api_key(x_api_key)
    try:
        supabase.table("suggested_rules").update({"status": "approved"}) \
            .eq("id", rule_id).execute()
        return {"status": "approved", "rule_id": rule_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/rules/{rule_id}/reject")
async def reject_rule(rule_id: int, x_api_key: Optional[str] = Header(None)):
    verify_api_key(x_api_key)
    try:
        supabase.table("suggested_rules").update({"status": "rejected"}) \
            .eq("id", rule_id).execute()
        return {"status": "rejected", "rule_id": rule_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Dashboard ──────────────────────────────────────────────────────────────────

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    try:
        logs = supabase.table("threat_logs").select("*") \
            .order("id", desc=True).limit(100).execute().data
        blacklist = supabase.table("blacklist").select("ip").execute().data
        pending_rules = supabase.table("suggested_rules").select("*") \
            .eq("status", "pending").order("occurrences", desc=True).limit(20).execute().data
    except Exception:
        logs, blacklist, pending_rules = [], [], []

    rows = "".join([
        f"<tr>"
        f"<td>{r.get('ip','')}</td>"
        f"<td>{r.get('threat','')}</td>"
        f"<td><span class='badge {'block' if r.get('action')=='block' else 'alert' if r.get('action')=='alert' else 'safe'}'>{r.get('action','')}</span></td>"
        f"<td>{r.get('risk_score','')}</td>"
        f"<td>{r.get('reason','')}</td>"
        f"<td style='font-size:0.75rem;color:#64748b'>{(r.get('playbook') or '').splitlines()[0] if r.get('playbook') else ''}</td>"
        f"</tr>"
        for r in logs
    ])

    rule_rows = "".join([
        f"<tr>"
        f"<td>{r.get('event_type','')}</td>"
        f"<td>{r.get('suggested_threat','')}</td>"
        f"<td>{r.get('occurrences','')}</td>"
        f"<td>{round(r.get('suggested_confidence', 0), 2)}</td>"
        f"<td>"
        f"<button onclick=\"fetch('/rules/{r['id']}/approve',{{method:'POST',headers:{{'X-Api-Key':'{API_KEY}'}}}}).then(()=>location.reload())\" style='margin-right:6px;cursor:pointer;background:#14532d;color:#4ade80;border:none;padding:3px 10px;border-radius:4px'>Approve</button>"
        f"<button onclick=\"fetch('/rules/{r['id']}/reject',{{method:'POST',headers:{{'X-Api-Key':'{API_KEY}'}}}}).then(()=>location.reload())\" style='cursor:pointer;background:#3d1515;color:#f87171;border:none;padding:3px 10px;border-radius:4px'>Reject</button>"
        f"</td>"
        f"</tr>"
        for r in pending_rules
    ])

    blocked_ips = ", ".join([b["ip"] for b in blacklist]) or "None"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="refresh" content="15">
<title>Agentic Defence — Dashboard</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:system-ui,sans-serif;background:#0f1117;color:#e2e8f0;padding:2rem}}
  h1{{font-size:1.5rem;margin-bottom:.25rem;color:#fff}}
  h2{{font-size:1rem;margin:1.5rem 0 .75rem;color:#94a3b8}}
  .sub{{color:#64748b;font-size:.85rem;margin-bottom:2rem}}
  .cards{{display:flex;gap:1rem;margin-bottom:2rem;flex-wrap:wrap}}
  .card{{background:#1e2130;border-radius:8px;padding:1.25rem 1.5rem;min-width:140px}}
  .card-label{{font-size:.75rem;color:#64748b;margin-bottom:.25rem}}
  .card-val{{font-size:1.75rem;font-weight:600;color:#fff}}
  table{{width:100%;border-collapse:collapse;background:#1e2130;border-radius:8px;overflow:hidden;margin-bottom:1rem}}
  th{{text-align:left;padding:.75rem 1rem;font-size:.75rem;color:#64748b;border-bottom:1px solid #2d3148}}
  td{{padding:.6rem 1rem;font-size:.82rem;border-bottom:1px solid #1a1d2e}}
  .badge{{padding:2px 8px;border-radius:4px;font-size:.75rem;font-weight:500}}
  .block{{background:#3d1515;color:#f87171}}
  .alert{{background:#3d2e10;color:#fbbf24}}
  .safe{{background:#0f2d1a;color:#4ade80}}
  .blacklist{{background:#1e2130;border-radius:8px;padding:1rem 1.5rem;margin-top:1.5rem;font-size:.85rem;color:#94a3b8}}
  .blacklist strong{{color:#f87171}}
</style>
</head>
<body>
  <h1>Agentic Defence System</h1>
  <p class="sub">Auto-refreshes every 15s</p>
  <div class="cards">
    <div class="card"><div class="card-label">Total Events</div><div class="card-val">{len(logs)}</div></div>
    <div class="card"><div class="card-label">Blocked</div><div class="card-val" style="color:#f87171">{sum(1 for r in logs if r.get('action')=='block')}</div></div>
    <div class="card"><div class="card-label">Alerts</div><div class="card-val" style="color:#fbbf24">{sum(1 for r in logs if r.get('action')=='alert')}</div></div>
    <div class="card"><div class="card-label">Blacklisted IPs</div><div class="card-val">{len(blacklist)}</div></div>
    <div class="card"><div class="card-label">Pending Rules</div><div class="card-val" style="color:#818cf8">{len(pending_rules)}</div></div>
  </div>

  <h2>Threat Log</h2>
  <table>
    <thead><tr><th>IP</th><th>Threat</th><th>Action</th><th>Risk</th><th>Reason</th><th>Top Playbook Step</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>

  <h2>Suggested Rules (Pending Approval)</h2>
  <table>
    <thead><tr><th>Event Type</th><th>Suggested Threat</th><th>Occurrences</th><th>Confidence</th><th>Actions</th></tr></thead>
    <tbody>{rule_rows if rule_rows else '<tr><td colspan="5" style="color:#64748b;padding:1rem">No pending rules</td></tr>'}</tbody>
  </table>

  <div class="blacklist"><strong>Blacklisted:</strong> {blocked_ips}</div>
</body>
</html>"""
    return html
