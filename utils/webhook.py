import os
import httpx
from typing import Optional

DISCORD_WEBHOOK = os.getenv("DISCORD_WEBHOOK", "")


async def send_discord(message: str) -> None:
    """Non-blocking async Discord webhook sender."""
    if not DISCORD_WEBHOOK:
        return
    try:
        async with httpx.AsyncClient(timeout=4) as client:
            await client.post(DISCORD_WEBHOOK, json={"content": message})
    except Exception:
        pass


async def send_alert(
    ip: str,
    action: str,
    threat: str,
    risk_score: int,
    playbook: Optional[list] = None
) -> None:
    """Send a formatted threat alert to Discord."""
    if action not in ("block", "alert"):
        return
    steps = ""
    if playbook:
        steps = "\n".join(f"  {i+1}. {s}" for i, s in enumerate(playbook[:4]))
        steps = f"\n**Recommended Actions:**\n{steps}"
    msg = (
        f"**[{action.upper()}]** `{ip}` | "
        f"Threat: `{threat}` | Risk: `{risk_score}`{steps}"
    )
    await send_discord(msg)
