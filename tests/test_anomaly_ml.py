"""
ML Anomaly Detection — pytest test suite
=========================================
Run with:
    pytest tests/test_anomaly_ml.py -v
"""
import os
import sys
import numpy as np
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.anomaly import AnomalyModel
from agents.detection import DetectionAgent


def make_event(event_type, ip="10.0.0.1", location="India"):
    return {"event": event_type, "ip": ip, "location": location}


def fresh_trained_model():
    m = AnomalyModel()
    m.train()
    return m


# ════════════════════════════════════════════════════════════════════════
# 1. AnomalyModel initialisation
# ════════════════════════════════════════════════════════════════════════
class TestAnomalyModelInit:

    def test_constructs_without_raising(self):
        m = AnomalyModel()
        assert m is not None

    def test_status_keys_present(self):
        m = AnomalyModel()
        s = m.status
        assert "trained" in s
        assert "samples" in s
        assert "model_file_exists" in s

    def test_train_with_empty_data_pads_and_succeeds(self):
        m = AnomalyModel()
        m.data = []
        m.trained = False
        m.train()
        assert m.trained is True

    def test_train_with_sufficient_data(self):
        m = AnomalyModel()
        m.data = [[1, 0, 0]] * 15
        m.trained = False
        m.train()
        assert m.trained is True


# ════════════════════════════════════════════════════════════════════════
# 2. predict() — valid inputs
# ════════════════════════════════════════════════════════════════════════
class TestPredictValid:

    @pytest.fixture(autouse=True)
    def setup(self):
        self.m = fresh_trained_model()

    @pytest.mark.parametrize("features,desc", [
        ([1, 0, 0], "normal code"),
        ([5, 0, 0], "rare code"),
        ([0, 0, 0], "all zeros"),
        (np.array([2, 0, 0]), "numpy array"),
        ([1.5, 0.0, 0.0], "float values"),
    ])
    def test_returns_minus1_or_1(self, features, desc):
        result = self.m.predict(features)
        assert result in (-1, 1), f"predict({desc}) returned {result!r} — expected -1 or 1."


# ════════════════════════════════════════════════════════════════════════
# 3. predict() — invalid inputs must return 0
# ════════════════════════════════════════════════════════════════════════
class TestPredictInvalidInputs:

    @pytest.fixture(autouse=True)
    def setup(self):
        self.m = fresh_trained_model()

    @pytest.mark.parametrize("bad_input,desc", [
        (None,                   "None"),
        ([],                     "empty list"),
        ([1, 2],                 "too short"),
        ([1, 2, 3, 4],          "too long"),
        (["a", "b", "c"],       "string values"),
        ([float("nan"), 0, 0],  "NaN"),
        ([float("inf"), 0, 0],  "Inf"),
        ([float("-inf"), 0, 0], "-Inf"),
        ([1, None, 0],           "mixed None"),
        (42,                     "bare integer"),
        ({"a": 1},               "dict"),
    ])
    def test_returns_0_not_raises(self, bad_input, desc):
        try:
            result = self.m.predict(bad_input)
        except Exception as exc:
            pytest.fail(f"predict({desc}) raised {type(exc).__name__}: {exc}")
        assert result == 0, f"predict({desc}) returned {result!r} instead of 0."


# ════════════════════════════════════════════════════════════════════════
# 4. predict() — internal sklearn errors
# ════════════════════════════════════════════════════════════════════════
class TestPredictInternalErrors:

    def test_sklearn_raises_returns_0(self):
        m = fresh_trained_model()
        m.model = MagicMock()
        m.model.predict.side_effect = RuntimeError("simulated sklearn crash")
        result = m.predict([1, 0, 0])
        assert result == 0

    def test_sklearn_returns_unexpected_value_returns_0(self):
        m = fresh_trained_model()
        m.model = MagicMock()
        m.model.predict.return_value = np.array([99])
        result = m.predict([1, 0, 0])
        assert result == 0

    def test_auto_trains_when_untrained(self):
        m = AnomalyModel()
        m.trained = False
        result = m.predict([1, 0, 0])
        assert result in (-1, 1)
        assert m.trained is True


# ════════════════════════════════════════════════════════════════════════
# 5. DetectionAgent — initialisation
# ════════════════════════════════════════════════════════════════════════
class TestDetectionAgentInit:

    def test_constructs_without_raising(self):
        a = DetectionAgent()
        assert a is not None

    def test_model_is_not_none(self):
        a = DetectionAgent()
        assert a.model is not None

    def test_model_has_status(self):
        a = DetectionAgent()
        if a.model is not None:
            assert "trained" in a.model.status


# ════════════════════════════════════════════════════════════════════════
# 6. extract_features
# ════════════════════════════════════════════════════════════════════════
class TestExtractFeatures:

    @pytest.fixture(autouse=True)
    def setup(self):
        self.a = DetectionAgent()

    @pytest.mark.parametrize("etype,code", [
        ("login_failed",    1),
        ("port_scan",       2),
        ("ddos_attempt",    3),
        ("wifi_intrusion",  4),
        ("malware_download",5),
        ("unknown_xyz",     0),
    ])
    def test_feature_code(self, etype, code):
        f = self.a.extract_features(make_event(etype))
        assert len(f) == 3
        assert f[0] == code

    def test_missing_event_key_returns_zeros(self):
        try:
            f = self.a.extract_features({"ip": "1.2.3.4"})
        except KeyError as e:
            pytest.fail(f"extract_features raised KeyError: {e}")
        assert f == [0, 0, 0]


# ════════════════════════════════════════════════════════════════════════
# 7. ML fallback routing
# ════════════════════════════════════════════════════════════════════════
class TestMLFallbackRouting:

    @patch("agents.detection.is_known_bad_ip", return_value=False)
    def test_unknown_event_ml_called_anomaly_returned(self, mock_intel):
        a = DetectionAgent()
        with patch.object(a.model, "predict", return_value=-1) as mock:
            result = a.detect(make_event("totally_unknown_xyz"))
        assert mock.call_count == 1
        assert result["data"]["threat"] == "anomaly"
        assert result["data"]["confidence"] == 0.6

    @patch("agents.detection.is_known_bad_ip", return_value=False)
    def test_unknown_event_ml_normal_no_threat(self, mock_intel):
        a = DetectionAgent()
        with patch.object(a.model, "predict", return_value=1):
            result = a.detect(make_event("benign_custom_event", ip="10.0.0.99"))
        assert result["data"]["threat"] is None

    @patch("agents.detection.is_known_bad_ip", return_value=False)
    def test_static_rule_match_ml_not_called(self, mock_intel):
        a = DetectionAgent()
        with patch.object(a.model, "predict") as mock:
            result = a.detect(make_event("malware_download"))
        assert mock.call_count == 0
        assert result["data"]["threat"] == "malware"

    @patch("agents.detection.is_known_bad_ip", return_value=False)
    def test_dynamic_rule_match_ml_not_called(self, mock_intel):
        a = DetectionAgent()
        with patch("agents.detection.load_approved_rules",
                   return_value={"custom_event": ("custom_threat", 0.75)}):
            with patch.object(a.model, "predict") as mock:
                result = a.detect(make_event("custom_event"))
        assert mock.call_count == 0
        assert result["data"]["threat"] == "custom_threat"


# ════════════════════════════════════════════════════════════════════════
# 8. Fault injection
# ════════════════════════════════════════════════════════════════════════
class TestFaultInjection:

    @patch("agents.detection.is_known_bad_ip", return_value=False)
    def test_ml_raises_pipeline_survives(self, mock_intel):
        a = DetectionAgent()
        a.model.predict = MagicMock(side_effect=RuntimeError("boom"))
        try:
            result = a.detect(make_event("crash_test", ip="9.9.9.9"))
        except Exception as exc:
            pytest.fail(f"detect() raised {type(exc).__name__}: {exc}")
        assert "data" in result

    @patch("agents.detection.is_known_bad_ip", return_value=False)
    def test_model_none_pipeline_survives(self, mock_intel):
        a = DetectionAgent()
        a.model = None
        try:
            result = a.detect(make_event("unknown_no_model", ip="8.8.8.8"))
        except AttributeError as exc:
            pytest.fail(f"detect() raised AttributeError: {exc}")
        except Exception as exc:
            pytest.fail(f"detect() raised unexpected {type(exc).__name__}: {exc}")
        assert result["data"]["threat"] is None

    def test_empty_event_dict_does_not_crash(self):
        a = DetectionAgent()
        try:
            result = a.detect({})
        except Exception as exc:
            pytest.fail(f"detect({{}}) raised {type(exc).__name__}: {exc}")
        assert "data" in result


# ════════════════════════════════════════════════════════════════════════
# 9. Stateful detection
# ════════════════════════════════════════════════════════════════════════
class TestStatefulDetection:

    @patch("agents.detection.is_known_bad_ip", return_value=False)
    def test_brute_force_thresholds(self, mock_intel):
        a = DetectionAgent()
        ip = "77.77.77.77"
        for _ in range(5):
            r = a.detect({"event": "login_failed", "ip": ip})
        assert r["data"]["threat"] == "brute_force_low"
        for _ in range(5):
            r = a.detect({"event": "login_failed", "ip": ip})
        assert r["data"]["threat"] == "brute_force_medium"
        for _ in range(10):
            r = a.detect({"event": "login_failed", "ip": ip})
        assert r["data"]["threat"] == "brute_force_high"

    @patch("agents.detection.is_known_bad_ip", return_value=False)
    def test_impossible_travel(self, mock_intel):
        a = DetectionAgent()
        ip = "55.55.55.55"
        a.detect({"event": "login_success", "ip": ip, "location": "India"})
        r = a.detect({"event": "login_success", "ip": ip, "location": "Russia"})
        assert r["data"]["threat"] == "impossible_travel"

    @patch("agents.detection.is_known_bad_ip", return_value=False)
    def test_flood_rate_guard(self, mock_intel):
        """50 requests in 60s window triggers flood_attack on the 50th call."""
        a = DetectionAgent()
        ip = "66.66.66.66"
        r = None
        for _ in range(51):
            r = a.detect({"event": "page_view", "ip": ip})
        assert r["data"]["threat"] == "flood_attack", (
            f"Expected 'flood_attack', got '{r['data']['threat']}'"
        )


# ════════════════════════════════════════════════════════════════════════
# 10. AnomalyModel.update()
# ════════════════════════════════════════════════════════════════════════
class TestAnomalyModelUpdate:

    def test_normal_sample_added(self):
        m = AnomalyModel()
        before = len(m.data)
        m.update([1, 0, 0], is_attack=False)
        assert len(m.data) == before + 1

    def test_attack_sample_not_added(self):
        m = AnomalyModel()
        before = len(m.data)
        m.update([5, 0, 0], is_attack=True)
        assert len(m.data) == before

    def test_invalid_features_silently_skipped(self):
        m = AnomalyModel()
        for bad in [None, [1], "bad_input", 42]:
            try:
                m.update(bad, is_attack=False)
            except Exception as exc:
                pytest.fail(f"update({bad!r}) raised {type(exc).__name__}: {exc}")
