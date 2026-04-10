import os
import logging
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib

logger = logging.getLogger("anomaly_model")

MODEL_PATH = "models/anomaly_model.pkl"
DATA_PATH = "models/training_data.npy"

# Features: [event_code, request_rate_bucket, login_fail_count, is_new_ip, hour_of_day]
EXPECTED_FEATURES = 5

# Baseline normal-behaviour data (5 features)
BASELINE_DATA = np.array([
    [1, 0, 0, 0, 9],  # login_failed, low rate, 0 fails, known ip, 9am
    [1, 0, 0, 0, 10],
    [1, 0, 1, 0, 10],
    [0, 0, 0, 0, 11],  # login_success
    [0, 0, 0, 0, 14],
    [0, 1, 0, 0, 15],
    [2, 0, 0, 1, 2],   # port_scan, new ip, 2am
    [0, 0, 0, 0, 9],
    [1, 0, 2, 0, 8],
    [0, 0, 0, 0, 17],
    [1, 1, 0, 0, 13],
    [0, 0, 0, 0, 10],
    [1, 0, 0, 1, 3],
    [0, 0, 0, 0, 9],
    [1, 0, 0, 0, 11],
    [0, 0, 0, 0, 16],
])


class AnomalyModel:
    def __init__(self):
        self.model = None
        self.trained = False
        self.data = []
        self._load_model()
        self._load_data()

    def _load_model(self):
        if not os.path.exists(MODEL_PATH):
            self.model = IsolationForest(contamination=0.1, random_state=42, n_estimators=100)
            return
        try:
            self.model = joblib.load(MODEL_PATH)
            self.trained = True
            logger.info("[ML] Model loaded from '%s'", MODEL_PATH)
        except Exception as e:
            logger.error("[ML] Load failed: %s", e)
            self.model = IsolationForest(contamination=0.1, random_state=42, n_estimators=100)

    def _load_data(self):
        if not os.path.exists(DATA_PATH):
            self.data = []
            return
        try:
            self.data = list(np.load(DATA_PATH))
            logger.info("[ML] Loaded %d training samples", len(self.data))
        except Exception:
            self.data = []

    def train(self, extra: np.ndarray = None):
        base = BASELINE_DATA.copy()
        if extra is not None:
            base = np.vstack([base, extra])
        if self.data:
            base = np.vstack([base, np.array(self.data)])
        try:
            self.model.fit(base)
            self.trained = True
            os.makedirs("models", exist_ok=True)
            joblib.dump(self.model, MODEL_PATH)
            np.save(DATA_PATH, base)
            logger.info("[ML] Trained on %d samples", len(base))
        except Exception as e:
            logger.error("[ML] Training failed: %s", e)

    def retrain(self, additional: np.ndarray):
        self.train(extra=additional)

    def predict(self, features) -> int:
        """
        Returns -1 (anomaly), 1 (normal), or 0 (fallback/error).
        Expects 5 features: [event_code, rate_bucket, login_fails, is_new_ip, hour]
        """
        if features is None or len(features) != EXPECTED_FEATURES:
            return 0
        try:
            arr = np.array(features, dtype=float)
            if np.any(np.isnan(arr)) or np.any(np.isinf(arr)):
                return 0
        except Exception:
            return 0

        if not self.trained:
            self.train()

        try:
            result = int(self.model.predict([arr])[0])
            return result if result in (-1, 1) else 0
        except Exception as e:
            logger.error("[ML] Predict error: %s", e)
            return 0

    def update(self, features, is_attack: bool):
        if not isinstance(features, (list, np.ndarray)) or len(features) != EXPECTED_FEATURES:
            return
        if not is_attack:
            self.data.append(list(features))
        if len(self.data) > 1000:
            self.data = self.data[-500:]
        if len(self.data) % 20 == 0 and len(self.data) > 0:
            self.train()

    @property
    def status(self):
        return {
            "trained": self.trained,
            "samples": len(self.data),
            "model_file_exists": os.path.exists(MODEL_PATH),
            "expected_features": EXPECTED_FEATURES,
        }
