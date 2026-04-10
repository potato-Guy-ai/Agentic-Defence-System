"""
ML Anomaly Detection — pytest test suite
=========================================
Standard pytest tests mirroring the diagnostic runner, with full
exception messages and step-level assertions.

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


# ── helpers ──────────────────────────────────────────────────────────────
def make_event(event_type, ip="10.0.0.1", location="India"):
    return {"event": event_type, "ip": ip, "location": location}


def fresh_trained_model():
    """Return a trained AnomalyModel regardless of what's on disk."""
    m = AnomalyModel()
    m.train()
    return m


# ════════════════════════════════════════════════════════════════════════
# 1. AnomalyModel initialisation
# ════════════════════════════════════════════════════════════════════════
class TestAnomalyModelInit:

    def test_constructs_without_raising(self):
        """Step: AnomalyModel() must never raise regardless of disk state."""
        m = AnomalyModel()   # ← if this raises, the model file is corrupt
        assert m is not None

    def test_status_keys_present(self):
        """Step: .status must expose trained / samples / model_file_exists."""
        m = AnomalyModel()
        s = m.status
        assert "trained" in s,            f"'trained' missing from status: {s}"
        assert "samples" in s,            f"'samples' missing from status: {s}"
        assert "model_file_exists" in s,  f"'model_file_exists' missing from status: {s}"

    def test_train_with_empty_data_pads_and_succeeds(self):
        """
        Step: train() with 0 samples must auto-pad to 10+ and fit
        without raising. If this fails, padding logic is broken.
        """
        m = AnomalyModel()
        m.data = []
        m.trained = False
        m.train()   # ← must not raise
        assert m.trained is True, "model.trained should be True after train()"

    def test_train_with_sufficient_data(self):
        """Step: train() with ≥10 real samples must succeed."""
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
        """
        Step: predict() on a properly-shaped numeric vector must return
        -1 (anomaly) or 1 (normal). Any other value means the model
        output is being mis-handled.
        """
        result = self.m.predict(features)
        assert result in (-1, 1), (
            f"predict({desc}) returned {result!r} — expected -1 or 1. "
            f"The sklearn prediction is leaking through unvalidated."
        )


# ════════════════════════════════════════════════════════════════════════
# 3. predict() — invalid inputs must return 0 (safe fallback), never raise
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
        """
        Step: predict() on bad input must return 0 (safe fallback) and
        must NOT raise. A raised exception here would crash the detection
        pipeline for every event.
        """
        try:
            result = self.m.predict(bad_input)
        except Exception as exc:
            pytest.fail(
                f"predict({desc}) raised {type(exc).__name__}: {exc}\n"
                "Expected safe return of 0 — guard clause is missing."
            )
        assert result == 0, (
            f"predict({desc}) returned {result!r} instead of 0. "
            "Input validation guard is incomplete."
        )


# ════════════════════════════════════════════════════════════════════════
# 4. predict() — internal sklearn errors
# ════════════════════════════════════════════════════════════════════════
class TestPredictInternalErrors:

    def test_sklearn_raises_returns_0(self):
        """
        Step: if the inner sklearn model.predict raises RuntimeError
        (e.g. corrupt model state), predict() must return 0, not crash.
        """
        m = fresh_trained_model()
        m.model = MagicMock()
        m.model.predict.side_effect = RuntimeError("simulated sklearn crash")
        result = m.predict([1, 0, 0])
        assert result == 0, (
            f"Got {result!r} — the try/except around sklearn call is missing or wrong."
        )

    def test_sklearn_returns_unexpected_value_returns_0(self):
        """
        Step: if sklearn returns an unexpected value like 99, predict()
        must return 0 instead of forwarding garbage downstream.
        """
        m = fresh_trained_model()
        m.model = MagicMock()
        m.model.predict.return_value = np.array([99])
        result = m.predict([1, 0, 0])
        assert result == 0, (
            f"Got {result!r} — the output-range guard is missing in predict()."
        )

    def test_auto_trains_when_untrained(self):
        """
        Step: if model.trained is False, predict() must auto-train before
        predicting. If this fails, the lazy-train path is broken.
        """
        m = AnomalyModel()
        m.trained = False
        result = m.predict([1, 0, 0])
        assert result in (-1, 1), (
            f"Auto-train path returned {result!r} instead of -1 or 1."
        )
        assert m.trained is True, "model.trained should be True after auto-train"


# ════════════════════════════════════════════════════════════════════════
# 5. DetectionAgent — initialisation
# ════════════════════════════════════════════════════════════════════════
class TestDetectionAgentInit:

    def test_constructs_without_raising(self):
        """Step: DetectionAgent() must not raise even on bad model state."""
        a = DetectionAgent()
        assert a is not None

    def test_model_is_not_none(self):
        """
        Step: agent.model must be a live AnomalyModel after init.
        If this fails, AnomalyModel.__init__ raised and was swallowed;
        ML detection is silently disabled.
        """
        a = DetectionAgent()
        assert a.model is not None, (
            "agent.model is None — AnomalyModel failed to initialise. "
            "Check logs for the '[DETECTION] Failed to initialise' line."
        )

    def test_model_has_status(self):
        """Step: the model attached to the agent must report status."""
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
        """
        Step: extract_features must map each event type to the correct
        numeric code in position [0]. Wrong codes mean ML gets wrong
        input and will mis-classify or always score the same.
        """
        f = self.a.extract_features(make_event(etype))
        assert len(f) == 3, f"Feature length should be 3, got {len(f)}"
        assert f[0] == code, (
            f"Event '{etype}' should map to code {code}, got {f[0]}. "
            f"Check the event_map dict in extract_features()."
        )

    def test_missing_event_key_returns_zeros(self):
        """
        Step: if 'event' key is absent from the dict, extract_features
        must not raise (should return [0,0,0]).
        """
        try:
            f = self.a.extract_features({"ip": "1.2.3.4"})
        except KeyError as e:
            pytest.fail(
                f"extract_features raised KeyError: {e}. "
                "Use .get() instead of direct dict access."
            )
        assert f == [0, 0, 0], f"Expected [0,0,0] for missing key, got {f}"


# ════════════════════════════════════════════════════════════════════════
# 7. ML fallback routing — ML called only when no rule matches
# ════════════════════════════════════════════════════════════════════════
class TestMLFallbackRouting:

    def test_unknown_event_ml_called_anomaly_returned(self):
        """
        Step: an event with no static or dynamic rule match must reach
        the ML model. If ML says -1, threat='anomaly' must be returned.
        """
        a = DetectionAgent()
        with patch.object(a.model, "predict", return_value=-1) as mock:
            result = a.detect(make_event("totally_unknown_xyz"))
        assert mock.call_count == 1, (
            f"ML predict() called {mock.call_count} times — should be exactly 1. "
            "The ML fallback block is not being reached."
        )
        assert result["data"]["threat"] == "anomaly", (
            f"Expected threat='anomaly', got '{result['data']['threat']}'. "
            "Check that the anomaly tuple is being appended to threats."
        )
        assert result["data"]["confidence"] == 0.6, (
            f"Confidence should be 0.6, got {result['data']['confidence']}"
        )

    def test_unknown_event_ml_normal_no_threat(self):
        """
        Step: if ML returns 1 (normal) for an unknown event, threat must
        be None — no false positive.
        """
        a = DetectionAgent()
        with patch.object(a.model, "predict", return_value=1):
            result = a.detect(make_event("benign_custom_event", ip="10.0.0.99"))
        assert result["data"]["threat"] is None, (
            f"Expected threat=None, got '{result['data']['threat']}'. False positive."
        )

    def test_static_rule_match_ml_not_called(self):
        """
        Step: when a static rule fires (e.g. malware_download), the ML
        model must NOT be called. If it is, the fallback-order logic is
        broken.
        """
        a = DetectionAgent()
        with patch.object(a.model, "predict") as mock:
            result = a.detect(make_event("malware_download"))
        assert mock.call_count == 0, (
            f"ML was called {mock.call_count} time(s) for a static-rule event. "
            "The 'if not threats' guard before ML is missing or wrong."
        )
        assert result["data"]["threat"] == "malware"

    def test_dynamic_rule_match_ml_not_called(self):
        """
        Step: when a dynamic rule fires, ML must not be called.
        """
        a = DetectionAgent()
        with patch("agents.detection.load_approved_rules",
                   return_value={"custom_event": ("custom_threat", 0.75)}):
            with patch.object(a.model, "predict") as mock:
                result = a.detect(make_event("custom_event"))
        assert mock.call_count == 0, (
            f"ML called {mock.call_count} time(s) despite dynamic rule match."
        )
        assert result["data"]["threat"] == "custom_threat"


# ════════════════════════════════════════════════════════════════════════
# 8. Fault injection — pipeline must never crash
# ════════════════════════════════════════════════════════════════════════
class TestFaultInjection:

    def test_ml_raises_pipeline_survives(self):
        """
        Step: if model.predict raises, detect() must catch it and still
        return a valid result dict — not propagate the exception.
        """
        a = DetectionAgent()
        a.model.predict = MagicMock(side_effect=RuntimeError("boom"))
        try:
            result = a.detect(make_event("crash_test", ip="9.9.9.9"))
        except Exception as exc:
            pytest.fail(
                f"detect() raised {type(exc).__name__}: {exc}\n"
                "The try/except in _ml_predict() is missing or incomplete."
            )
        assert "data" in result

    def test_model_none_pipeline_survives(self):
        """
        Step: if agent.model is None (init failed), detect() must not
        AttributeError. The 'if self.model is None' guard in _ml_predict
        must be present.
        """
        a = DetectionAgent()
        a.model = None
        try:
            result = a.detect(make_event("unknown_no_model", ip="8.8.8.8"))
        except AttributeError as exc:
            pytest.fail(
                f"detect() raised AttributeError: {exc}\n"
                "'if self.model is None' guard is missing in _ml_predict()."
            )
        except Exception as exc:
            pytest.fail(f"detect() raised unexpected {type(exc).__name__}: {exc}")
        assert result["data"]["threat"] is None, (
            f"Expected threat=None with no model, got '{result['data']['threat']}'"
        )

    def test_empty_event_dict_does_not_crash(self):
        """
        Step: detect({}) must not raise. Missing 'event' and 'ip' keys
        are realistic in network edge cases.
        """
        a = DetectionAgent()
        try:
            result = a.detect({})
        except Exception as exc:
            pytest.fail(
                f"detect({{}}) raised {type(exc).__name__}: {exc}\n"
                "Use .get() with defaults for 'ip' and 'event' in detect()."
            )
        assert "data" in result


# ════════════════════════════════════════════════════════════════════════
# 9. Stateful detection
# ════════════════════════════════════════════════════════════════════════
class TestStatefulDetection:

    def test_brute_force_thresholds(self):
        """
        Step: login_failed must accumulate per-IP and cross the correct
        thresholds at 5, 10, and 20 attempts.
        """
        a = DetectionAgent()
        ip = "77.77.77.77"
        for _ in range(5):
            r = a.detect({"event": "login_failed", "ip": ip})
        assert r["data"]["threat"] == "brute_force_low", (
            f"At 5 attempts expected 'brute_force_low', got '{r['data']['threat']}'"
        )
        for _ in range(5):
            r = a.detect({"event": "login_failed", "ip": ip})
        assert r["data"]["threat"] == "brute_force_medium", (
            f"At 10 attempts expected 'brute_force_medium', got '{r['data']['threat']}'"
        )
        for _ in range(10):
            r = a.detect({"event": "login_failed", "ip": ip})
        assert r["data"]["threat"] == "brute_force_high", (
            f"At 20 attempts expected 'brute_force_high', got '{r['data']['threat']}'"
        )

    def test_impossible_travel(self):
        """Step: two logins from different locations within 60 min."""
        a = DetectionAgent()
        ip = "55.55.55.55"
        a.detect({"event": "login_success", "ip": ip, "location": "India"})
        r = a.detect({"event": "login_success", "ip": ip, "location": "Russia"})
        assert r["data"]["threat"] == "impossible_travel", (
            f"Expected 'impossible_travel', got '{r['data']['threat']}'"
        )

    def test_flood_rate_guard(self):
        """Step: 51 requests in 60 s → flood_attack."""
        a = DetectionAgent()
        ip = "66.66.66.66"
        for _ in range(51):
            r = a.detect({"event": "page_view", "ip": ip})
        assert r["data"]["threat"] == "flood_attack", (
            f"Expected 'flood_attack', got '{r['data']['threat']}'"
        )


# ════════════════════════════════════════════════════════════════════════
# 10. AnomalyModel.update() — feedback loop
# ════════════════════════════════════════════════════════════════════════
class TestAnomalyModelUpdate:

    def test_normal_sample_added(self):
        """Step: is_attack=False should grow model.data by 1."""
        m = AnomalyModel()
        before = len(m.data)
        m.update([1, 0, 0], is_attack=False)
        assert len(m.data) == before + 1, (
            f"Expected {before+1} samples, got {len(m.data)}. "
            "update() may not be appending normal samples."
        )

    def test_attack_sample_not_added(self):
        """Step: is_attack=True must NOT grow model.data (IsolationForest learns normal only)."""
        m = AnomalyModel()
        before = len(m.data)
        m.update([5, 0, 0], is_attack=True)
        assert len(m.data) == before, (
            f"Attack sample was added to training data — should not be. "
            f"Check the 'if not is_attack:' guard."
        )

    def test_invalid_features_silently_skipped(self):
        """Step: update() with bad inputs must not raise."""
        m = AnomalyModel()
        for bad in [None, [1], "bad_input", 42]:
            try:
                m.update(bad, is_attack=False)
            except Exception as exc:
                pytest.fail(
                    f"update({bad!r}) raised {type(exc).__name__}: {exc}. "
                    "Input validation in update() is incomplete."
                )
