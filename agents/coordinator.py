from utils.message import create_message

class CoordinatorAgent:
    def process(self, message):
        if message is None:
            return None

        data = message["data"]

        if data["threat"] is None:
            return None

        # 🔥 ADVANCED RISK ADJUSTMENT (ADD THIS)

        if data["threat"] == "data_exfiltration":
            data["confidence"] += 0.1

        elif data["threat"] == "privilege_escalation":
            data["confidence"] += 0.15

        elif data["threat"] == "lateral_movement":
            data["confidence"] += 0.1

        # Optional safety cap
        if data["confidence"] > 1:
            data["confidence"] = 1

        priority = "low"
        if data["confidence"] > 0.8:
            priority = "high"
        elif data["confidence"] > 0.5:
            priority = "medium"

        return create_message(
            sender="coordinator",
            data={
                "ip": data["ip"],
                "threat": data["threat"],
                "confidence": data["confidence"],
                "priority": priority,
                "reasons": data["reasons"]
            },
            priority=priority
        )