import pytest
import time
from unittest.mock import patch
from agents.detection import DetectionAgent


def make_event(event_type, ip="1.2.3.4", location=None):
    e = {"event": event_type, "ip": ip}
    if location:
        e["location"] = location
    return e


@patch("agents.detection.is_known_bad_ip", return_value=False)
@patch("agents.detection.load_approved_rules", return_value={})
@patch("agents.detection.log_candidate")
def test_brute_force_low(m1, m2, m3):
    a = DetectionAgent()
    for _ in range(5):
        msg = a.detect(make_event("login_failed"))
    assert "brute_force" in msg["data"]["threat"]


@patch("agents.detection.is_known_bad_ip", return_value=False)
@patch("agents.detection.load_approved_rules", return_value={})
@patch("agents.detection.log_candidate")
def test_brute_force_high(m1, m2, m3):
    a = DetectionAgent()
    for _ in range(20):
        msg = a.detect(make_event("login_failed"))
    assert msg["data"]["threat"] == "brute_force_high"
    assert msg["data"]["confidence"] == 0.95


@patch("agents.detection.is_known_bad_ip", return_value=False)
@patch("agents.detection.load_approved_rules", return_value={})
@patch("agents.detection.log_candidate")
def test_malware(m1, m2, m3):
    a = DetectionAgent()
    msg = a.detect(make_event("malware_download"))
    assert msg["data"]["threat"] == "malware"


@patch("agents.detection.is_known_bad_ip", return_value=False)
@patch("agents.detection.load_approved_rules", return_value={})
@patch("agents.detection.log_candidate")
def test_impossible_travel(m1, m2, m3):
    a = DetectionAgent()
    a.detect({"event": "login_success", "ip": "5.5.5.5", "location": "India"})
    msg = a.detect({"event": "login_success", "ip": "5.5.5.5", "location": "Russia"})
    assert msg["data"]["threat"] == "impossible_travel"


@patch("agents.detection.is_known_bad_ip", return_value=False)
@patch("agents.detection.load_approved_rules", return_value={})
@patch("agents.detection.log_candidate")
def test_no_threat(m1, m2, m3):
    a = DetectionAgent()
    msg = a.detect(make_event("page_view", ip="9.9.9.9"))
    assert msg["data"]["threat"] is None


@patch("agents.detection.is_known_bad_ip", return_value=False)
@patch("agents.detection.load_approved_rules", return_value={})
@patch("agents.detection.log_candidate")
def test_multi_stage_attack(m1, m2, m3):
    a = DetectionAgent()
    ip = "77.77.77.77"
    for ev in ["port_scan", "login_failed", "admin_access", "multiple_system_access", "data_download"]:
        a.detect({"event": ev, "ip": ip})
    msg = a.detect({"event": "data_download", "ip": ip})
    assert msg["data"]["threat"] == "multi_stage_attack"


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


def test_extract_features_length():
    a = DetectionAgent()
    features = a.extract_features({"event": "login_failed", "ip": "1.2.3.4"}, rate=5)
    assert len(features) == 5


def test_ml_model_feature_count():
    from models.anomaly import AnomalyModel, EXPECTED_FEATURES
    m = AnomalyModel()
    assert EXPECTED_FEATURES == 5
    result = m.predict([1, 0, 0, 0, 9])
    assert result in (-1, 0, 1)
