import logging
from fastapi import FastAPI, Request, Header, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from pydantic import BaseModel
from typing import Optional
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import os
import time

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

# ------------------------------------------------------------------
# Logging configuration — show INFO+ from our own modules
# ------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
# Bump ML / detection to DEBUG so every prediction is visible
logging.getLogger("anomaly_model").setLevel(logging.DEBUG)
logging.getLogger("detection_agent").setLevel(logging.DEBUG)

logger = logging.getLogger("api")

API_KEY = os.getenv("API_KEY", "")
DISCORD_WEBHOOK = os.getenv("WEBHOOK_URL")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("[STARTUP] Starting rule analyzer...")
    try:
        start_analyzer()
        logger.info("[STARTUP] Rule analyzer started OK")
    except Exception as e:
        logger.error("[STARTUP ERROR] Rule analyzer failed to start: %s", e)

    # Eagerly verify the ML model at startup so any file / load problems
    # are surfaced immediately in the logs rather than on the first event.
    logger.info("[STARTUP] Verifying ML anomaly model...")
    try:
        probe = AnomalyModel()
        logger.info("[STARTUP] ML model status: %s", probe.status)
        if not probe.trained:
            logger.warning(
                "[STARTUP] ML model is NOT trained. "
                "It will be auto-trained on the first prediction."
            )
    except Exception as e:
        logger.error("[STARTUP ERROR] ML model verification failed: %s", e)

    yield
    logger.info("[SHUTDOWN] App closing")


limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="Agentic Defence System",
    lifespan=lifespan
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500"
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


model = AnomalyModel()
detection = DetectionAgent()
coordinator = CoordinatorAgent()
decision_agent = DecisionAgent()
response_agent = ResponseAgent()
feedback = FeedbackAgent(anomaly_model=model)
filter_agent = FilterAgent()
normalizer = NormalizerAgent()


_pipeline_stats = {
    "filter": {"status": "idle", "events": 0, "latency": "0ms", "last_active": None},
    "normalizer": {"status": "idle", "events": 0, "latency": "0ms", "last_active": None},
    "detection": {"status": "idle", "events": 0, "latency": "0ms", "last_active": None},
    "coordinator": {"status": "idle", "events": 0, "latency": "0ms", "last_active": None},
    "decision": {"status": "idle", "events": 0, "latency": "0ms", "last_active": None},
    "response": {"status": "idle", "events": 0, "latency": "0ms", "last_active": None},
}


def verify_api_key(x_api_key: Optional[str]):
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


def _send_discord(message: str):
    if not DISCORD_WEBHOOK:
        logger.debug("[DISCORD] WEBHOOK_URL not set — skipping notification")
        return
    try:
        import requests as req
        response = req.post(DISCORD_WEBHOOK, json={"content": message}, timeout=4)
        response.raise_for_status()
    except Exception as e:
        logger.error("[DISCORD ERROR] %s", e)


def _tick(agent: str, latency_ms: float):
    s = _pipeline_stats[agent]
    s["status"] = "active"
    s["events"] += 1
    s["latency"] = f"{latency_ms:.0f}ms"
    s["last_active"] = time.strftime("%H:%M:%S", time.localtime())


class EventPayload(BaseModel):
    ip: str
    event: str
    location: Optional[str] = None
    timestamp: Optional[str] = None


class BlacklistPayload(BaseModel):
    ip: str


@app.post("/events")
@limiter.limit("60/minute")
async def receive_event(
    request: Request,
    payload: EventPayload,
    x_api_key: Optional[str] = Header(None)
):
    verify_api_key(x_api_key)

    t0 = time.time()
    event = normalizer.normalize(payload.dict())
    _tick("normalizer", (time.time() - t0) * 1000)

    t0 = time.time()
    if not event or not filter_agent.is_relevant(event):
        _tick("filter", (time.time() - t0) * 1000)
        return {"status": "ignored"}
    _tick("filter", (time.time() - t0) * 1000)

    t0 = time.time()
    threat = detection.detect(event)
    _tick("detection", (time.time() - t0) * 1000)

    t0 = time.time()
    coordinated = coordinator.process(threat)
    _tick("coordinator", (time.time() - t0) * 1000)

    t0 = time.time()
    decision = decision_agent.decide(coordinated)
    _tick("decision", (time.time() - t0) * 1000)

    t0 = time.time()
    response_agent.execute(decision)
    _tick("response", (time.time() - t0) * 1000)

    feedback.update(decision)

    if decision is None:
        # Coordinator returned None (no threat) — still log to Supabase if
        # ML anomaly was the only signal (threat confidence == 0.6, action == ignore)
        threat_data = threat["data"] if threat else {}
        if threat_data.get("threat") == "anomaly":
            logger.info(
                "[PIPELINE] ML anomaly detected but coordinator dropped it "
                "(confidence below threshold). ip=%s", threat_data.get("ip")
            )
        return {"status": "no_action"}

    d = decision["data"]
    ip = d["ip"]
    action = d["action"]
    risk = d["risk_score"]
    threat_type = d.get("threat") or threat["data"].get("threat")

    playbook = get_playbook(threat_type, ip, risk, action)

    try:
        supabase.table("threat_logs").insert({
            "ip": ip,
            "threat": threat_type,
            "action": action,
            "risk_score": risk,
            "reason": ", ".join(d["reasons"]),
            "playbook": "\n".join(playbook)
        }).execute()
        logger.info(
            "[SUPABASE] Logged threat: ip=%s threat=%s action=%s risk=%s",
            ip, threat_type, action, risk
        )
    except Exception as e:
        logger.error("[SUPABASE LOG ERROR] %s", e)

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
    ml_status = detection.model.status if detection.model else {"trained": False, "error": "model_none"}
    return {"status": "ok", "ml_model": ml_status}


@app.get("/logs")
async def get_logs(limit: int = 500, x_api_key: Optional[str] = Header(None)):
    verify_api_key(x_api_key)
    try:
        rows = supabase.table("threat_logs").select("*").order("id", desc=True).limit(limit).execute().data
        return {"logs": rows}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/blacklist")
async def get_blacklist(x_api_key: Optional[str] = Header(None)):
    verify_api_key(x_api_key)
    try:
        rows = supabase.table("blacklist").select("*").order("id", desc=True).execute().data
        return {"blacklist": rows}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/blacklist")
async def add_to_blacklist(payload: BlacklistPayload, x_api_key: Optional[str] = Header(None)):
    verify_api_key(x_api_key)
    try:
        supabase.table("blacklist").insert({"ip": payload.ip}).execute()
        response_agent.blacklist.add(payload.ip)
        return {"status": "blocked", "ip": payload.ip}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/blacklist/{ip}")
async def remove_from_blacklist(ip: str, x_api_key: Optional[str] = Header(None)):
    verify_api_key(x_api_key)
    try:
        supabase.table("blacklist").delete().eq("ip", ip).execute()
        response_agent.blacklist.discard(ip)
        return {"status": "unblocked", "ip": ip}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/pipeline/status")
async def pipeline_status(x_api_key: Optional[str] = Header(None)):
    verify_api_key(x_api_key)
    return _pipeline_stats


@app.get("/rules/suggested")
async def get_suggested_rules(x_api_key: Optional[str] = Header(None)):
    verify_api_key(x_api_key)
    try:
        rows = supabase.table("suggested_rules").select("*").eq("status", "pending").order("occurrences", desc=True).execute().data
        return {"rules": rows}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/rules/{rule_id}/approve")
async def approve_rule(rule_id: int, x_api_key: Optional[str] = Header(None)):
    verify_api_key(x_api_key)
    try:
        supabase.table("suggested_rules").update({"status": "approved"}).eq("id", rule_id).execute()
        return {"status": "approved", "rule_id": rule_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/rules/{rule_id}/reject")
async def reject_rule(rule_id: int, x_api_key: Optional[str] = Header(None)):
    verify_api_key(x_api_key)
    try:
        supabase.table("suggested_rules").update({"status": "rejected"}).eq("id", rule_id).execute()
        return {"status": "rejected", "rule_id": rule_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_redirect():
    return HTMLResponse('<meta http-equiv="refresh" content="0;url=/dashboard.html">')
