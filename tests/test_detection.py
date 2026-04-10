import pytest
from unittest.mock import patch
from agents.detection import DetectionAgent


def make_event(event_type, ip="1.2.3.4", location="India"):
    return {"event": event_type, "ip": ip, "location": location}


@patch("agents.detection.is_known_bad_ip", return_value=False)
def test_brute_force_low(mock_intel):
    a = DetectionAgent()
    for _ in range(5):
        msg = a.detect(make_event("login_failed"))
    assert msg["data"]["threat"] is not None
    assert "brute_force" in msg["data"]["threat"]


@patch("agents.detection.is_known_bad_ip", return_value=False)
def test_brute_force_high(mock_intel):
    a = DetectionAgent()
    for _ in range(20):
        msg = a.detect(make_event("login_failed"))
    assert msg["data"]["threat"] == "brute_force_high"
    assert msg["data"]["confidence"] == 0.95


@patch("agents.detection.is_known_bad_ip", return_value=False)
def test_malware_detection(mock_intel):
    a = DetectionAgent()
    msg = a.detect(make_event("malware_download"))
    assert msg["data"]["threat"] == "malware"


@patch("agents.detection.is_known_bad_ip", return_value=False)
def test_impossible_travel(mock_intel):
    a = DetectionAgent()
    a.detect({"event": "login_success", "ip": "5.5.5.5", "location": "India"})
    msg = a.detect({"event": "login_success", "ip": "5.5.5.5", "location": "Russia"})
    assert msg["data"]["threat"] == "impossible_travel"


@patch("agents.detection.is_known_bad_ip", return_value=False)
def test_no_threat(mock_intel):
    a = DetectionAgent()
    msg = a.detect(make_event("page_view", ip="9.9.9.9"))
    assert msg["data"]["threat"] is None


def test_risk_score_capped():
    from agents.decision import DecisionAgent
    from utils.message import create_message
    d = DecisionAgent()
    msg = create_message(
        "detection",
        {"ip": "x", "threat": "ddos", "confidence": 1.0, "reasons": [], "priority": "high"},
        "high"
    )
    result = d.decide(msg)
    assert result["data"]["risk_score"] <= 100
