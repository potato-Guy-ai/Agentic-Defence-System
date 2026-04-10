"""
ML Anomaly Detection — Step-by-Step Diagnostic Runner
======================================================
Run this script directly to see exactly what every step is doing:

    python tests/run_ml_diagnostics.py

Each section prints a clear header, the action being taken, the result,
and — on failure — the full exception traceback so you know exactly
which line broke and why.

Designed to be read top-to-bottom: if a section fails the rest still run.
"""

import sys
import os
import traceback
import logging
import numpy as np
from unittest.mock import patch, MagicMock

# ── add repo root to path so imports work when run directly ──────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── configure logging so every logger.info / logger.debug is visible ─────
logging.basicConfig(
    level=logging.DEBUG,
    format="  [LOG %(levelname)s] %(name)s: %(message)s",
)

PASS = "\033[92m✓ PASS\033[0m"
FAIL = "\033[91m✗ FAIL\033[0m"
INFO = "\033[94m→\033[0m"

passed = 0
failed = 0


def section(title):
    print(f"\n{'='*65}")
    print(f"  {title}")
    print('='*65)


def step(description):
    print(f"  {INFO} {description}")


def ok(label, detail=""):
    global passed
    passed += 1
    suffix = f"  ({detail})" if detail else ""
    print(f"  {PASS}  {label}{suffix}")


def fail(label, exc=None):
    global failed
    failed += 1
    print(f"  {FAIL}  {label}")
    if exc:
        print("  ── Exception ──────────────────────────────────────────")
        for line in traceback.format_exception(type(exc), exc, exc.__traceback__):
            for l in line.splitlines():
                print(f"  | {l}")
        print("  ────────────────────────────────────────────────────────")


def check(label, condition, detail="", exc=None):
    if condition:
        ok(label, detail)
    else:
        fail(label, exc)


# ══════════════════════════════════════════════════════════════════════════
# SECTION 1 — AnomalyModel imports and class instantiation
# ══════════════════════════════════════════════════════════════════════════
section("1 · AnomalyModel: import and instantiation")

try:
    step("Importing AnomalyModel from models.anomaly ...")
    from models.anomaly import AnomalyModel
    ok("Import succeeded")
except Exception as e:
    fail("Import FAILED — check models/anomaly.py for syntax errors", e)
    print("\n[ABORT] Cannot continue without AnomalyModel. Fix the import first.")
    sys.exit(1)

try:
    step("Calling AnomalyModel() ...")
    model = AnomalyModel()
    ok("AnomalyModel() constructed without raising")
except Exception as e:
    fail("AnomalyModel() constructor raised an exception", e)
    model = None

if model:
    step(f"Checking .status property ...")
    try:
        status = model.status
        check("model.status has 'trained' key",    "trained"           in status, str(status))
        check("model.status has 'samples' key",    "samples"           in status, str(status))
        check("model.status has 'model_file_exists' key", "model_file_exists" in status, str(status))
        print(f"    status = {status}")
    except Exception as e:
        fail("model.status raised", e)


# ══════════════════════════════════════════════════════════════════════════
# SECTION 2 — Model file detection
# ══════════════════════════════════════════════════════════════════════════
section("2 · Model file presence on disk")

MODEL_PATH = "models/anomaly_model.pkl"
DATA_PATH  = "models/training_data.npy"

step(f"Checking if '{MODEL_PATH}' exists ...")
check(
    f"Model file found at {MODEL_PATH}",
    os.path.exists(MODEL_PATH),
    "OK" if os.path.exists(MODEL_PATH) else "MISSING — model will auto-train on first predict()"
)

step(f"Checking if '{DATA_PATH}' exists ...")
check(
    f"Training data found at {DATA_PATH}",
    os.path.exists(DATA_PATH),
    "OK" if os.path.exists(DATA_PATH) else "MISSING — model.data will start empty"
)


# ══════════════════════════════════════════════════════════════════════════
# SECTION 3 — Model training
# ══════════════════════════════════════════════════════════════════════════
section("3 · AnomalyModel.train()")

try:
    model2 = AnomalyModel()
    model2.data = []      # force empty so padding logic runs
    model2.trained = False
    step("Calling model.train() with empty data (triggers padding) ...")
    model2.train()
    check("model.trained is True after train()", model2.trained is True, str(model2.trained))
except Exception as e:
    fail("train() raised an exception", e)

try:
    model3 = AnomalyModel()
    model3.data = [[1, 0, 0]] * 15   # already enough data
    model3.trained = False
    step("Calling model.train() with 15 real samples ...")
    model3.train()
    check("model.trained is True with real data", model3.trained is True)
except Exception as e:
    fail("train() with real data raised", e)


# ══════════════════════════════════════════════════════════════════════════
# SECTION 4 — predict() happy-path
# ══════════════════════════════════════════════════════════════════════════
section("4 · AnomalyModel.predict() — valid inputs")

try:
    m = AnomalyModel()
    m.train()

    cases = [
        ("normal event code [1,0,0]",   [1, 0, 0]),
        ("rare event code [5,0,0]",      [5, 0, 0]),
        ("all-zero vector [0,0,0]",      [0, 0, 0]),
        ("numpy array input",            np.array([2, 0, 0])),
        ("float values [1.5,0.0,0.0]",  [1.5, 0.0, 0.0]),
    ]

    for label, feat in cases:
        step(f"predict({feat}) ...")
        try:
            result = m.predict(feat)
            check(
                f"predict({label}) returns -1 or 1",
                result in (-1, 1),
                f"got {result}"
            )
        except Exception as e:
            fail(f"predict({label}) raised unexpectedly", e)

except Exception as e:
    fail("Section 4 setup failed", e)


# ══════════════════════════════════════════════════════════════════════════
# SECTION 5 — predict() exception / invalid-input cases
# ══════════════════════════════════════════════════════════════════════════
section("5 · AnomalyModel.predict() — invalid inputs (must NOT crash, return 0)")

try:
    m = AnomalyModel()
    m.train()

    bad_cases = [
        ("None input",                  None),
        ("empty list",                  []),
        ("too short [1,2]",             [1, 2]),
        ("too long [1,2,3,4]",          [1, 2, 3, 4]),
        ("string values",               ["a", "b", "c"]),
        ("NaN in vector",               [float("nan"), 0, 0]),
        ("Inf in vector",               [float("inf"), 0, 0]),
        ("-Inf in vector",              [float("-inf"), 0, 0]),
        ("mixed type list",             [1, None, 0]),
        ("integer scalar (not list)",   42),
        ("dict input",                  {"a": 1}),
    ]

    for label, feat in bad_cases:
        step(f"predict({label!r}) — expecting 0 ...")
        try:
            result = m.predict(feat)
            check(
                f"predict({label}) → safe fallback 0",
                result == 0,
                f"got {result!r} (should be 0)"
            )
        except Exception as e:
            fail(
                f"predict({label}) RAISED instead of returning 0 — "
                "this means the guard is missing!", e
            )

except Exception as e:
    fail("Section 5 setup failed", e)


# ══════════════════════════════════════════════════════════════════════════
# SECTION 6 — predict() when sklearn itself throws
# ══════════════════════════════════════════════════════════════════════════
section("6 · predict() when inner sklearn model raises RuntimeError")

try:
    m = AnomalyModel()
    m.train()
    step("Replacing internal model.predict with a mock that raises RuntimeError ...")
    m.model = MagicMock()
    m.model.predict.side_effect = RuntimeError("simulated sklearn crash")

    result = m.predict([1, 0, 0])
    check(
        "predict() catches RuntimeError and returns 0",
        result == 0,
        f"got {result!r}"
    )
except Exception as e:
    fail("predict() did NOT catch internal RuntimeError — pipeline would crash here!", e)


# ══════════════════════════════════════════════════════════════════════════
# SECTION 7 — predict() when sklearn returns unexpected value
# ══════════════════════════════════════════════════════════════════════════
section("7 · predict() when sklearn returns unexpected value (e.g. 99)")

try:
    m = AnomalyModel()
    m.train()
    m.model = MagicMock()
    m.model.predict.return_value = np.array([99])

    step("Mocking sklearn to return 99 ...")
    result = m.predict([1, 0, 0])
    check(
        "predict() handles unexpected sklearn output, returns 0",
        result == 0,
        f"got {result!r}"
    )
except Exception as e:
    fail("predict() crashed on unexpected sklearn output", e)


# ══════════════════════════════════════════════════════════════════════════
# SECTION 8 — predict() when model is untrained (auto-train path)
# ══════════════════════════════════════════════════════════════════════════
section("8 · predict() auto-trains when model.trained is False")

try:
    m = AnomalyModel()
    m.trained = False
    step("Setting model.trained=False, calling predict([1,0,0]) ...")
    result = m.predict([1, 0, 0])
    check(
        "predict() auto-trained and returned -1 or 1",
        result in (-1, 1),
        f"got {result!r}"
    )
    check("model.trained is now True", m.trained is True, str(m.trained))
except Exception as e:
    fail("Auto-train path raised", e)


# ══════════════════════════════════════════════════════════════════════════
# SECTION 9 — DetectionAgent imports and initialises model
# ══════════════════════════════════════════════════════════════════════════
section("9 · DetectionAgent: import and ML model initialisation")

try:
    step("Importing DetectionAgent from agents.detection ...")
    from agents.detection import DetectionAgent
    ok("Import succeeded")
except Exception as e:
    fail("Import FAILED — check agents/detection.py", e)
    print("\n[ABORT] Cannot continue without DetectionAgent.")
    sys.exit(1)

try:
    step("Constructing DetectionAgent() ...")
    agent = DetectionAgent()
    ok("DetectionAgent() constructed without raising")
    check(
        "agent.model is not None (ML model loaded)",
        agent.model is not None,
        "model is None — AnomalyModel failed to init; ML detection is DISABLED"
    )
except Exception as e:
    fail("DetectionAgent() constructor raised", e)
    agent = None


# ══════════════════════════════════════════════════════════════════════════
# SECTION 10 — extract_features correctness
# ══════════════════════════════════════════════════════════════════════════
section("10 · DetectionAgent.extract_features()")

if agent:
    feature_cases = [
        ("login_failed",    1),
        ("port_scan",       2),
        ("ddos_attempt",    3),
        ("wifi_intrusion",  4),
        ("malware_download",5),
        ("unknown_xyz",     0),   # unknown → code 0
    ]
    for etype, expected_code in feature_cases:
        event = {"event": etype, "ip": "1.2.3.4"}
        step(f"extract_features for event='{etype}' — expecting code {expected_code} ...")
        try:
            features = agent.extract_features(event)
            check(
                f"extract_features('{etype}') → [{expected_code},0,0]",
                len(features) == 3 and features[0] == expected_code,
                f"got {features}"
            )
        except Exception as e:
            fail(f"extract_features('{etype}') raised", e)

    # Edge: missing 'event' key
    step("extract_features with no 'event' key in dict ...")
    try:
        features = agent.extract_features({"ip": "1.2.3.4"})
        check("extract_features missing key → [0,0,0]", features == [0, 0, 0], str(features))
    except Exception as e:
        fail("extract_features raised on missing key", e)


# ══════════════════════════════════════════════════════════════════════════
# SECTION 11 — Static rules fire (ML must NOT be called)
# ══════════════════════════════════════════════════════════════════════════
section("11 · Static rules: known events — ML must NOT be called")

if agent:
    static_cases = [
        ("malware_download",        "malware"),
        ("port_scan",               "port_scan"),
        ("ddos_attempt",            "ddos"),
        ("wifi_intrusion",          "unauthorized_access"),
        ("admin_access",            "privilege_escalation"),
        ("multiple_system_access",  "lateral_movement"),
    ]
    for etype, expected_threat in static_cases:
        a = DetectionAgent()
        event = {"event": etype, "ip": f"10.0.0.{static_cases.index((etype, expected_threat)) + 1}"}
        step(f"detect(event='{etype}') — expecting static threat='{expected_threat}', ML silent ...")
        try:
            with patch.object(a.model, "predict") as mock_pred:
                result = a.detect(event)
            mock_pred.assert_not_called()
            check(
                f"Static rule '{etype}' → threat='{expected_threat}'",
                result["data"]["threat"] == expected_threat,
                f"got threat='{result['data']['threat']}'"
            )
            check(
                f"ML model NOT called for static event '{etype}'",
                mock_pred.call_count == 0,
                f"called {mock_pred.call_count} times"
            )
        except AssertionError as e:
            fail(f"ML was called for static event '{etype}' — fallback order broken", e)
        except Exception as e:
            fail(f"detect('{etype}') raised", e)


# ══════════════════════════════════════════════════════════════════════════
# SECTION 12 — Unknown event routes to ML (anomaly detected)
# ══════════════════════════════════════════════════════════════════════════
section("12 · ML fallback: unknown event → ML called, anomaly returned")

if agent:
    a = DetectionAgent()
    event = {"event": "totally_unknown_event_xyz", "ip": "192.168.99.1"}
    step(f"detect(event='totally_unknown_event_xyz') with ML forced to return -1 ...")
    try:
        with patch.object(a.model, "predict", return_value=-1) as mock_pred:
            result = a.detect(event)
        check("ML predict() was called exactly once",
              mock_pred.call_count == 1, f"called {mock_pred.call_count} times")
        check("threat == 'anomaly'",
              result["data"]["threat"] == "anomaly",
              f"got '{result['data']['threat']}'")
        check("confidence == 0.6",
              result["data"]["confidence"] == 0.6,
              f"got {result['data']['confidence']}")
    except Exception as e:
        fail("Unknown-event anomaly path raised", e)


# ══════════════════════════════════════════════════════════════════════════
# SECTION 13 — Unknown event, ML says normal → threat is None
# ══════════════════════════════════════════════════════════════════════════
section("13 · ML fallback: unknown event → ML says normal → threat=None")

if agent:
    a = DetectionAgent()
    event = {"event": "benign_custom_event", "ip": "192.168.99.2"}
    step("detect(event='benign_custom_event') with ML forced to return 1 (normal) ...")
    try:
        with patch.object(a.model, "predict", return_value=1):
            result = a.detect(event)
        check("threat is None when ML says normal",
              result["data"]["threat"] is None,
              f"got '{result['data']['threat']}'")
    except Exception as e:
        fail("Normal-ML path raised", e)


# ══════════════════════════════════════════════════════════════════════════
# SECTION 14 — Dynamic rules (ML must NOT be called if dynamic rule matches)
# ══════════════════════════════════════════════════════════════════════════
section("14 · Dynamic rules matched → ML must NOT be called")

if agent:
    a = DetectionAgent()
    event = {"event": "custom_event_type", "ip": "10.10.10.10"}
    fake_rules = {"custom_event_type": ("custom_threat", 0.75)}
    step("Patching load_approved_rules to return a dynamic match, checking ML is silent ...")
    try:
        with patch("agents.detection.load_approved_rules", return_value=fake_rules):
            with patch.object(a.model, "predict") as mock_pred:
                result = a.detect(event)
        check("Dynamic rule → threat='custom_threat'",
              result["data"]["threat"] == "custom_threat",
              f"got '{result['data']['threat']}'")
        check("ML NOT called when dynamic rule matched",
              mock_pred.call_count == 0, f"called {mock_pred.call_count} times")
    except Exception as e:
        fail("Dynamic rule test raised", e)


# ══════════════════════════════════════════════════════════════════════════
# SECTION 15 — ML model raises inside _ml_predict → pipeline doesn't crash
# ══════════════════════════════════════════════════════════════════════════
section("15 · Fault injection: ML predict() raises → pipeline must not crash")

if agent:
    a = DetectionAgent()
    a.model.predict = MagicMock(side_effect=RuntimeError("simulated ML failure"))
    event = {"event": "crash_test_event", "ip": "9.9.9.9"}
    step("Injecting RuntimeError into model.predict, calling detect() ...")
    try:
        result = a.detect(event)
        check("detect() did not raise despite ML crash",
              True, "pipeline survived")
        check("Result is a valid dict with 'data' key",
              "data" in result, str(list(result.keys())))
    except Exception as e:
        fail("detect() CRASHED when ML raised — pipeline is fragile here!", e)


# ══════════════════════════════════════════════════════════════════════════
# SECTION 16 — model is None → pipeline must not crash
# ══════════════════════════════════════════════════════════════════════════
section("16 · Fault injection: agent.model = None → pipeline must not crash")

if agent:
    a = DetectionAgent()
    a.model = None
    event = {"event": "unknown_event_no_model", "ip": "8.8.8.8"}
    step("Setting agent.model = None, calling detect() ...")
    try:
        result = a.detect(event)
        check("detect() did not crash when model is None", True, "survived")
        check("threat is None (no false positive)",
              result["data"]["threat"] is None,
              f"got '{result['data']['threat']}'")
    except Exception as e:
        fail("detect() CRASHED with model=None — missing None guard!", e)


# ══════════════════════════════════════════════════════════════════════════
# SECTION 17 — AnomalyModel.update() — feedback loop
# ══════════════════════════════════════════════════════════════════════════
section("17 · AnomalyModel.update() — feedback / online learning")

try:
    m = AnomalyModel()
    before = len(m.data)

    step("update([1,0,0], is_attack=False) — should add sample ...")
    m.update([1, 0, 0], is_attack=False)
    check("Normal sample added to data", len(m.data) == before + 1,
          f"{before} → {len(m.data)}")

    before2 = len(m.data)
    step("update([5,0,0], is_attack=True) — should NOT add (attacks not learned) ...")
    m.update([5, 0, 0], is_attack=True)
    check("Attack sample NOT added", len(m.data) == before2,
          f"{before2} → {len(m.data)}")

    step("update(None, is_attack=False) — should be silently skipped ...")
    try:
        m.update(None, is_attack=False)
        ok("update(None) silently skipped")
    except Exception as e:
        fail("update(None) raised — missing input guard!", e)

    step("update([1], is_attack=False) — wrong length, should be skipped ...")
    try:
        m.update([1], is_attack=False)
        ok("update(wrong length) silently skipped")
    except Exception as e:
        fail("update(wrong length) raised", e)

except Exception as e:
    fail("Section 17 setup failed", e)


# ══════════════════════════════════════════════════════════════════════════
# SECTION 18 — Brute force accumulation (stateful, login_failed)
# ══════════════════════════════════════════════════════════════════════════
section("18 · Stateful detection: brute force login_failed accumulation")

try:
    a = DetectionAgent()
    ip = "77.77.77.77"

    step("5 login_failed events → brute_force_low ...")
    for _ in range(5):
        result = a.detect({"event": "login_failed", "ip": ip})
    check("5 failures → brute_force_low",
          result["data"]["threat"] == "brute_force_low",
          f"got '{result['data']['threat']}'")

    step("5 more (10 total) → brute_force_medium ...")
    for _ in range(5):
        result = a.detect({"event": "login_failed", "ip": ip})
    check("10 failures → brute_force_medium",
          result["data"]["threat"] == "brute_force_medium",
          f"got '{result['data']['threat']}'")

    step("10 more (20 total) → brute_force_high ...")
    for _ in range(10):
        result = a.detect({"event": "login_failed", "ip": ip})
    check("20 failures → brute_force_high",
          result["data"]["threat"] == "brute_force_high",
          f"got '{result['data']['threat']}'")

except Exception as e:
    fail("Brute force accumulation test raised", e)


# ══════════════════════════════════════════════════════════════════════════
# SECTION 19 — Impossible travel
# ══════════════════════════════════════════════════════════════════════════
section("19 · Impossible travel detection")

try:
    a = DetectionAgent()
    ip = "55.55.55.55"
    step("First login_success from India ...")
    a.detect({"event": "login_success", "ip": ip, "location": "India"})
    step("Second login_success from Russia within 60 min → impossible_travel ...")
    result = a.detect({"event": "login_success", "ip": ip, "location": "Russia"})
    check("Impossible travel detected",
          result["data"]["threat"] == "impossible_travel",
          f"got '{result['data']['threat']}'")
except Exception as e:
    fail("Impossible travel test raised", e)


# ══════════════════════════════════════════════════════════════════════════
# SECTION 20 — Flood / rate guard
# ══════════════════════════════════════════════════════════════════════════
section("20 · Flood rate guard (50+ requests in 60 s window)")

try:
    a = DetectionAgent()
    ip = "66.66.66.66"
    step("Sending 51 events from same IP inside 60-second window ...")
    for i in range(51):
        result = a.detect({"event": "page_view", "ip": ip})
    check("51 requests → flood_attack",
          result["data"]["threat"] == "flood_attack",
          f"got '{result['data']['threat']}'")
except Exception as e:
    fail("Flood rate guard test raised", e)


# ══════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════
total = passed + failed
print(f"\n{'='*65}")
print(f"  SUMMARY: {passed}/{total} passed, {failed} failed")
print('='*65)

if failed > 0:
    print(f"\n  \033[91m{failed} test(s) FAILED. Review the ✗ lines above to locate the issue.\033[0m")
    sys.exit(1)
else:
    print(f"\n  \033[92mAll {total} checks passed. ML pipeline is healthy.\033[0m")
    sys.exit(0)
