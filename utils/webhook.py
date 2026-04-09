import os
import httpx
from dotenv import load_dotenv

load_dotenv()
WEBHOOK_URL = os.getenv("WEBHOOK_URL")

async def send_alert(ip: str, action: str, threat: str, risk_score: int):
    if not WEBHOOK_URL or action != "block":
        return
    payload = {
        "content": f"🚨 **BLOCK** | IP: `{ip}` | Threat: `{threat}` | Risk: `{risk_score}/100`"
    }
    try:
        async with httpx.AsyncClient() as client:
            await client.post(WEBHOOK_URL, json=payload, timeout=5)
    except Exception:
        pass