"""
ML Anomaly Detection — comprehensive test suite

Covers:
  1. Model loads and trains successfully
  2. Unknown / uncategorised events reach the ML fallback
  3. Anomaly result is returned correctly
  4. Safe fallback on invalid inputs (no crash)
  5. Feature extraction correctness
  6. Model status reporting
  7. DetectionAgent does not crash when model is None
  8. Known-event types are NOT incorrectly routed to ML
"""
import pytest
import numpy as np
from unittest.mock import patch, MagicMock

from models.anomaly import AnomalyModel
from agents.detection import DetectionAgent


# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------
def make_event(event_type, ip="10.0.0.1", location="India"):
    return {"event": event_type, "ip": ip, "location": location}


# -----------------------------------------------------------------------
# 1. AnomalyModel — initialisation & training
# -----------------------------------------------------------------------
class TestAnomalyModelInit:
    def test_model_initialises_without_crash(self):
        """AnomalyModel() must not raise even if .pkl is absent."""
        model = AnomalyModel()
        assert model is not None

    def test_model_trains_on_demand(self):
        model = AnomalyModel()
        model.train()
        assert model.trained is True

    def test_status_dict_has_expected_keys(self):
        model = AnomalyModel()
        status = model.status
        assert "trained" in status
        assert "samples" in status
        assert "model_file_exists" in status

    def test_model_trains_with_minimal_data(self):
        """train() should pad and succeed even with zero seed data."""
        model = AnomalyModel()
        model.data = []          # force empty
        model.trained = False
        model.train()
        assert model.trained is True


# -----------------------------------------------------------------------
# 2. AnomalyModel — predict() edge cases
# -----------------------------------------------------------------------
class TestAnomalyModelPredict:
    def setup_method(self):
        self.model = AnomalyModel()
        self.model.train()       # ensure model is ready

    def test_predict_returns_minus1_or_1_for_valid_input(self):
        result = self.model.predict([2, 0, 0])
        assert result in (-1, 1)

    def test_predict_none_returns_0(self):
        """None input must NOT crash — returns safe fallback 0."""
        result = self.model.predict(None)
        assert result == 0

    def test_predict_wrong_length_returns_0(self):
        """Feature vector of wrong length must return 0, not raise."""
        result = self.model.predict([1, 2])        # too short
        assert result == 0
        result2 = self.model.predict([1, 2, 3, 4]) # too long
        assert result2 == 0

    def test_predict_nan_returns_0(self):
        result = self.model.predict([float("nan"), 0, 0])
        assert result == 0

    def test_predict_inf_returns_0(self):
        result = self.model.predict([float("inf"), 0, 0])
        assert result == 0

    def test_predict_string_values_returns_0(self):
        result = self.model.predict(["bad", "input", "here"])
        assert result == 0

    def test_predict_empty_list_returns_0(self):
        result = self.model.predict([])
        assert result == 0

    def test_predict_numpy_array_is_accepted(self):
        result = self.model.predict(np.array([1, 0, 0]))
        assert result in (-1, 1, 0)

    def test_predict_when_untrained_auto_trains(self):
        """If model.trained is False, predict() should train then predict."""
        model = AnomalyModel()
        model.trained = False
        result = model.predict([1, 0, 0])
        assert result in (-1, 1)   # not 0 — it should have trained
        assert model.trained is True


# -----------------------------------------------------------------------
# 3. AnomalyModel — unexpected sklearn output
# -----------------------------------------------------------------------
class TestAnomalyModelUnexpectedOutput:
    def test_unexpected_sklearn_output_returns_0(self):
        """If sklearn returns something other than -1/1, return 0 safely."""
        model = AnomalyModel()
        model.train()
        mock_inner = MagicMock()
        mock_inner.predict.return_value = np.array([99])  # garbage
        model.model = mock_inner
        result = model.predict([1, 0, 0])
        assert result == 0


# -----------------------------------------------------------------------
# 4. DetectionAgent — unknown event reaches ML fallback
# -----------------------------------------------------------------------
class TestMLFallbackTriggered:
    def test_unknown_event_reaches_ml_fallback(self):
        """
        An event type not covered by any static rule must be routed to
        the ML model. We force the ML model to return -1 (anomaly) and
        confirm the detection result reflects it.
        """
        agent = DetectionAgent()
        with patch.object(agent.model, "predict", return_value=-1) as mock_pred:
            result = agent.detect(make_event("totally_unknown_event_xyz"))
        mock_pred.assert_called_once()
        assert result["data"]["threat"] == "anomaly"
        assert result["data"]["confidence"] == 0.6

    def test_unknown_event_ml_returns_normal_no_threat(self):
        """
        If ML says normal (1) for an unknown event, threat must be None.
        """
        agent = DetectionAgent()
        with patch.object(agent.model, "predict", return_value=1):
            result = agent.detect(make_event("completely_benign_custom_event"))
        assert result["data"]["threat"] is None

    def test_ml_not_called_when_static_rule_matches(self):
        """
        ML must NOT be invoked when a static rule already produced a threat.
        """
        agent = DetectionAgent()
        with patch.object(agent.model, "predict") as mock_pred:
            result = agent.detect(make_event("malware_download"))
        mock_pred.assert_not_called()
        assert result["data"]["threat"] == "malware"

    def test_ml_not_called_when_dynamic_rule_matches(self):
        """
        ML must NOT be invoked when a dynamic rule matched.
        """
        agent = DetectionAgent()
        fake_rules = {"custom_event": ("custom_threat", 0.75)}
        with patch("agents.detection.load_approved_rules", return_value=fake_rules):
            with patch.object(agent.model, "predict") as mock_pred:
                result = agent.detect(make_event("custom_event"))
        mock_pred.assert_not_called()
        assert result["data"]["threat"] == "custom_threat"


# -----------------------------------------------------------------------
# 5. DetectionAgent — ML model failure / None model
# -----------------------------------------------------------------------
class TestMLFallbackFailSafe:
    def test_predict_raising_exception_does_not_crash_pipeline(self):
        """Even if predict() throws, detect() must return a valid message."""
        agent = DetectionAgent()
        with patch.object(agent.model, "predict", side_effect=RuntimeError("boom")):
            result = agent.detect(make_event("unknown_crash_event"))
        # Pipeline must not crash; result is a valid message with threat=None
        assert "data" in result

    def test_none_model_does_not_crash_pipeline(self):
        """If self.model is None the detection pipeline must still run."""
        agent = DetectionAgent()
        agent.model = None
        result = agent.detect(make_event("unknown_event_no_model"))
        assert "data" in result
        assert result["data"]["threat"] is None


# -----------------------------------------------------------------------
# 6. Feature extraction
# -----------------------------------------------------------------------
class TestFeatureExtraction:
    def setup_method(self):
        self.agent = DetectionAgent()

    def test_known_events_produce_nonzero_code(self):
        for etype, expected_code in [
            ("login_failed", 1),
            ("port_scan", 2),
            ("ddos_attempt", 3),
            ("wifi_intrusion", 4),
            ("malware_download", 5),
        ]:
            features = self.agent.extract_features(make_event(etype))
            assert features[0] == expected_code, f"Failed for {etype}"
            assert len(features) == 3

    def test_unknown_event_maps_to_zero(self):
        features = self.agent.extract_features(make_event("some_random_event"))
        assert features[0] == 0
        assert len(features) == 3

    def test_missing_event_key_does_not_crash(self):
        """extract_features must not raise if 'event' key is absent."""
        features = self.agent.extract_features({"ip": "1.2.3.4"})
        assert len(features) == 3


# -----------------------------------------------------------------------
# 7. AnomalyModel.update() — feedback / online learning
# -----------------------------------------------------------------------
class TestAnomalyModelUpdate:
    def test_normal_sample_is_added(self):
        model = AnomalyModel()
        before = len(model.data)
        model.update([1, 0, 0], is_attack=False)
        assert len(model.data) == before + 1

    def test_attack_sample_is_not_added(self):
        """IsolationForest learns normal distribution only."""
        model = AnomalyModel()
        before = len(model.data)
        model.update([5, 0, 0], is_attack=True)
        assert len(model.data) == before

    def test_invalid_features_in_update_do_not_crash(self):
        model = AnomalyModel()
        model.update(None, is_attack=False)          # None
        model.update([1], is_attack=False)            # wrong length
        model.update("bad_input", is_attack=False)   # wrong type
        # Just verifying no exception was raised
