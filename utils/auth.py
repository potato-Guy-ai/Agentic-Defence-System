import os
from fastapi import Request, HTTPException
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("API_KEY", "changeme")

async def verify_api_key(request: Request):
    key = request.headers.get("X-API-Key")
    if key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")