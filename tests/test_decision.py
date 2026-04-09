import pytest

from agents.decision import DecisionAgent

from utils.message import create_message





@pytest.fixture

def agent():

    return DecisionAgent()





def make_msg(threat, confidence, priority="high"):

    return create_message("coordinator", {

        "ip": "1.2.3.4",

        "threat": threat,

        "confidence": confidence,

        "priority": priority,

        "reasons": ["test"]

    }, priority=priority)





def test_block_action(agent):

    result = agent.decide(make_msg("brute_force_high", 0.95))

    assert result["data"]["action"] == "block"





def test_alert_action(agent):

    result = agent.decide(make_msg("port_scan", 0.6))

    assert result["data"]["action"] == "alert"





def test_ignore_action(agent):

    result = agent.decide(make_msg("anomaly", 0.4))

    assert result["data"]["action"] == "ignore"





def test_risk_score_capped(agent):

    result = agent.decide(make_msg("ddos", 1.0))

    assert result["data"]["risk_score"] <= 100





def test_none_message(agent):

    assert agent.decide(None) is None
