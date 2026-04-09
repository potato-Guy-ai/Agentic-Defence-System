from fastapi import FastAPI, Request, Header, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import os

from agents.detection import DetectionAgent
from agents.coordinator import CoordinatorAgent
from agents.decision import DecisionAgent
from agents.response import ResponseAgent
from agents.feedback import FeedbackAgent
from agents.filter import FilterAgent
from agents.normalizer import NormalizerAgent
from models.anomaly import AnomalyModel
from utils.supabase_client import supabase
from utils.webhook import send_alert
from utils.stix_export import build_stix_bundle

API_KEY = os.getenv("API_KEY", "")

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


def verify_api_key(x_api_key: Optional[str]):
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


class EventPayload(BaseModel):
    ip: str
    event: str
    location: Optional[str] = None
    timestamp: Optional[str] = None


@app.post("/events")
@limiter.limit("60/minute")
async def receive_event(request: Request, payload: EventPayload, x_api_key: Optional[str] = Header(None)):
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
    await send_alert(d["ip"], d["action"], d.get("threat", "unknown"), d["risk_score"])

    return {
        "status": "processed",
        "ip": d["ip"],
        "action": d["action"],
        "risk_score": d["risk_score"],
        "reasons": d["reasons"]
    }


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/export/stix")
async def export_stix():
    try:
        logs = supabase.table("threat_logs").select("*").eq("action", "block").limit(200).execute().data
    except Exception:
        logs = []
    bundle = build_stix_bundle(logs)
    return JSONResponse(content=bundle)


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    try:
        logs = supabase.table("threat_logs").select("*").order("id", desc=True).limit(100).execute().data
        blacklist = supabase.table("blacklist").select("ip").execute().data
    except Exception:
        logs, blacklist = [], []

    rows = "".join([
        f"""<tr>
            <td>{r.get('ip','')}</td>
            <td>{r.get('threat','')}</td>
            <td><span class="badge {'block' if r.get('action')=='block' else 'alert' if r.get('action')=='alert' else 'safe'}">{r.get('action','')}</span></td>
            <td>{r.get('risk_score','')}</td>
            <td>{r.get('reason','')}</td>
        </tr>"""
        for r in logs
    ])

    blocked_ips = ", ".join([b["ip"] for b in blacklist]) or "None"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="refresh" content="10">
<title>Agentic Defence — Dashboard</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: system-ui, sans-serif; background: #0f1117; color: #e2e8f0; padding: 2rem; }}
  h1 {{ font-size: 1.5rem; margin-bottom: 0.25rem; color: #fff; }}
  .sub {{ color: #64748b; font-size: 0.85rem; margin-bottom: 2rem; }}
  .cards {{ display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }}
  .card {{ background: #1e2130; border-radius: 8px; padding: 1.25rem 1.5rem; min-width: 150px; }}
  .card-label {{ font-size: 0.75rem; color: #64748b; margin-bottom: 0.25rem; }}
  .card-val {{ font-size: 1.75rem; font-weight: 600; color: #fff; }}
  table {{ width: 100%; border-collapse: collapse; background: #1e2130; border-radius: 8px; overflow: hidden; }}
  th {{ text-align: left; padding: 0.75rem 1rem; font-size: 0.75rem; color: #64748b; border-bottom: 1px solid #2d3148; }}
  td {{ padding: 0.65rem 1rem; font-size: 0.85rem; border-bottom: 1px solid #1a1d2e; }}
  .badge {{ padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 500; }}
  .block {{ background: #3d1515; color: #f87171; }}
  .alert {{ background: #3d2e10; color: #fbbf24; }}
  .safe  {{ background: #0f2d1a; color: #4ade80; }}
  .blacklist {{ background: #1e2130; border-radius: 8px; padding: 1rem 1.5rem; margin-top: 1.5rem; font-size: 0.85rem; color: #94a3b8; }}
  .blacklist strong {{ color: #f87171; }}
</style>
</head>
<body>
  <h1>Agentic Defence System</h1>
  <p class="sub">Auto-refreshes every 10s</p>
  <div class="cards">
    <div class="card"><div class="card-label">Total Events</div><div class="card-val">{len(logs)}</div></div>
    <div class="card"><div class="card-label">Blocked</div><div class="card-val" style="color:#f87171">{sum(1 for r in logs if r.get('action')=='block')}</div></div>
    <div class="card"><div class="card-label">Alerts</div><div class="card-val" style="color:#fbbf24">{sum(1 for r in logs if r.get('action')=='alert')}</div></div>
    <div class="card"><div class="card-label">Blacklisted IPs</div><div class="card-val">{len(blacklist)}</div></div>
  </div>
  <table>
    <thead><tr><th>IP</th><th>Threat</th><th>Action</th><th>Risk</th><th>Reason</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
  <div class="blacklist"><strong>Blacklisted:</strong> {blocked_ips}</div>
</body>
</html>"""
    return html
