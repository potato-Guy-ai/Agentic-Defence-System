import os
import requests
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY")
SHODAN_KEY = os.getenv("SHODAN_KEY")

LOCAL_BLACKLIST = {"23.45.67.89"}

def check_abuseipdb(ip: str) -> bool:
    if not ABUSEIPDB_KEY:
        return False
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 30},
            timeout=3
        )
        if r.status_code == 200:
            return r.json()["data"]["abuseConfidenceScore"] > 50
    except Exception:
        pass
    return False

def check_shodan(ip: str) -> bool:
    if not SHODAN_KEY:
        return False
    try:
        r = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": SHODAN_KEY},
            timeout=3
        )
        if r.status_code == 200:
            tags = r.json().get("tags", [])
            return any(t in tags for t in ["malware", "bot", "scanner", "tor"])
    except Exception:
        pass
    return False

def is_known_bad_ip(ip: str) -> bool:
    if ip in LOCAL_BLACKLIST:
        return True
    if check_abuseipdb(ip):
        return True
    if check_shodan(ip):
        return True
    return False
