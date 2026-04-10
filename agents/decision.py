from utils.message import create_message


class DecisionAgent:
    def decide(self, message):
        if message is None:
            return None

        data = message["data"]

        risk_score = int(data["confidence"] * 100)

        if data["threat"] == "ddos":
            risk_score += 10

        risk_score = min(risk_score, 100)

        if risk_score > 80:
            action = "block"
        elif risk_score > 50:
            action = "alert"
        else:
            action = "ignore"

        trace = f"Threat={data['threat']} | Confidence={data['confidence']} -> Action={action}"

        return create_message(
            sender="decision",
            data={
                "ip": data["ip"],
                "threat": data["threat"],   # carry threat forward explicitly
                "action": action,
                "risk_score": risk_score,
                "reasons": data["reasons"],
                "trace": trace
            },
            priority=data["priority"]
        )
