import pytest
from agents.detection import DetectionAgent

agent = DetectionAgent()

def make_event(event_type, ip="1.2.3.4", location="India"):
    return {"event": event_type, "ip": ip, "location": location}

def test_brute_force_low():
    a = DetectionAgent()
    for _ in range(5):
        msg = a.detect(make_event("login_failed"))
    assert msg["data"]["threat"] is not None

def test_brute_force_high():
    a = DetectionAgent()
    for _ in range(20):
        msg = a.detect(make_event("login_failed"))
    assert msg["data"]["threat"] == "brute_force_high"
    assert msg["data"]["confidence"] == 0.95

def test_malware_detection():
    msg = agent.detect(make_event("malware_download"))
    assert msg["data"]["threat"] == "malware"

def test_impossible_travel():
    a = DetectionAgent()
    a.detect({"event": "login_success", "ip": "5.5.5.5", "location": "India"})
    msg = a.detect({"event": "login_success", "ip": "5.5.5.5", "location": "Russia"})
    assert msg["data"]["threat"] == "impossible_travel"

def test_no_threat():
    msg = agent.detect(make_event("page_view", ip="9.9.9.9"))
    assert msg["data"]["threat"] is None

def test_risk_score_capped():
    from agents.decision import DecisionAgent
    d = DecisionAgent()
    from utils.message import create_message
    msg = create_message("detection", {"ip": "x", "threat": "ddos", "confidence": 1.0, "reasons": [], "priority": "high"}, "high")
    result = d.decide(msg)
    assert result["data"]["risk_score"] <= 100