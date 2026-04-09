from utils.storage import Storage
from utils.supabase_client import supabase

class ResponseAgent:
    def __init__(self):
        self.blacklist = set()
        response = supabase.table("blacklist").select("ip").execute()

        for row in response.data:
            self.blacklist.add(row["ip"])

    def execute(self, message):
        if message is None:
            return

        data = message["data"]

        ip = data["ip"]
        action = data["action"]

        # Already blocked check
        if ip in self.blacklist:
            print(f"[BLOCKED] Incoming request from {ip} rejected")
            return

        if action == "block":
            self.blacklist.add(ip)

            supabase.table("blacklist").insert({
                "ip": ip
            }).execute()

            print(f"[ACTION] Blocked IP: {ip}")

        elif action == "alert":
            print(f"[ALERT] Suspicious activity from {ip}")

        else:
            print(f"[SAFE] No action for {ip}")

        print(f"[THREAT] {ip} → {action.upper()}")
        print(f"Reasons: {', '.join(data['reasons'])}")
        print(f"[TRACE] {data['trace']}")
        print(f"Risk Score: {data['risk_score']}")
        print("-" * 40)

        supabase.table("threat_logs").insert({
            "ip": ip,
            "threat": data.get("threat", "unknown"),
            "action": action,
            "risk_score": data["risk_score"],
            "reason": ", ".join(data["reasons"])
        }).execute()