import os
import logging
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib

logger = logging.getLogger("anomaly_model")

MODEL_PATH = "models/anomaly_model.pkl"
DATA_PATH = "models/training_data.npy"

# Minimum number of features expected by the model
EXPECTED_FEATURES = 3


class AnomalyModel:
    def __init__(self):
        self.model = None
        self.trained = False
        self.data = []
        self._load_model()
        self._load_data()

    # ------------------------------------------------------------------
    # MODEL LOADING
    # ------------------------------------------------------------------
    def _load_model(self):
        """Attempt to load a pre-trained model from disk."""
        if not os.path.exists(MODEL_PATH):
            logger.warning(
                "[ML] Model file not found at '%s'. "
                "Model will be trained on first prediction.", MODEL_PATH
            )
            self.model = IsolationForest(contamination=0.1, random_state=42)
            return

        try:
            self.model = joblib.load(MODEL_PATH)
            self.trained = True
            logger.info("[ML] Model loaded successfully from '%s'", MODEL_PATH)
        except Exception as e:
            logger.error(
                "[ML] Failed to load model from '%s': %s. "
                "A fresh model will be used.", MODEL_PATH, e
            )
            self.model = IsolationForest(contamination=0.1, random_state=42)

    # ------------------------------------------------------------------
    # TRAINING DATA LOADING
    # ------------------------------------------------------------------
    def _load_data(self):
        """Load persisted training samples from disk."""
        if not os.path.exists(DATA_PATH):
            logger.debug("[ML] No training data file found at '%s'.", DATA_PATH)
            self.data = []
            return

        try:
            loaded = np.load(DATA_PATH)
            self.data = list(loaded)
            logger.info("[ML] Loaded %d training samples from '%s'", len(self.data), DATA_PATH)
        except Exception as e:
            logger.error("[ML] Failed to load training data: %s. Starting with empty dataset.", e)
            self.data = []

    # ------------------------------------------------------------------
    # TRAINING
    # ------------------------------------------------------------------
    def train(self):
        """Fit the IsolationForest on current data, persisting the result."""
        if len(self.data) < 10:
            logger.warning(
                "[ML] Insufficient training data (%d samples). "
                "Padding with synthetic normal records.", len(self.data)
            )
            self.data.extend([
                [1, 0, 0], [1, 0, 0], [1, 0, 0], [2, 0, 0],
                [1, 0, 0], [2, 0, 0], [1, 0, 0], [2, 0, 0],
                [1, 0, 0], [1, 0, 0],
            ])

        try:
            X = np.array(self.data)
            self.model.fit(X)
            self.trained = True
            os.makedirs("models", exist_ok=True)
            joblib.dump(self.model, MODEL_PATH)
            np.save(DATA_PATH, X)
            logger.info("[ML] Model trained and saved with %d samples.", len(X))
        except Exception as e:
            logger.error("[ML] Training failed: %s. Model will not be saved.", e)

    # ------------------------------------------------------------------
    # PREDICTION
    # ------------------------------------------------------------------
    def predict(self, features):
        """
        Predict whether a feature vector is anomalous.

        Returns:
            -1  → anomaly
             1  → normal
             0  → fallback (model unavailable / input error)
        """
        # --- validate input ---
        if features is None:
            logger.error("[ML] predict() received None features. Returning safe fallback (0).")
            return 0

        if not isinstance(features, (list, np.ndarray)):
            logger.error(
                "[ML] predict() expected list/ndarray, got %s. Returning safe fallback (0).",
                type(features)
            )
            return 0

        if len(features) != EXPECTED_FEATURES:
            logger.error(
                "[ML] Feature vector has wrong length: expected %d, got %d. "
                "Returning safe fallback (0).",
                EXPECTED_FEATURES, len(features)
            )
            return 0

        try:
            features_arr = np.array(features, dtype=float)
        except (ValueError, TypeError) as e:
            logger.error(
                "[ML] Cannot convert features to numeric array: %s. "
                "Raw input: %s. Returning safe fallback (0).", e, features
            )
            return 0

        if np.any(np.isnan(features_arr)) or np.any(np.isinf(features_arr)):
            logger.error(
                "[ML] Feature vector contains NaN/Inf values: %s. "
                "Returning safe fallback (0).", features_arr
            )
            return 0

        # --- ensure model is trained ---
        if not self.trained:
            logger.warning("[ML] Model not yet trained. Triggering training now.")
            self.train()

        # --- run prediction ---
        try:
            prediction = self.model.predict([features_arr])
            result = int(prediction[0])

            if result not in (-1, 1):
                logger.warning(
                    "[ML] Unexpected prediction value %s for features %s. "
                    "Returning safe fallback (0).", result, features_arr
                )
                return 0

            logger.debug(
                "[ML] predict(%s) -> %s (%s)",
                features_arr.tolist(),
                result,
                "ANOMALY" if result == -1 else "normal"
            )
            return result

        except Exception as e:
            logger.error(
                "[ML] Prediction error for features %s: %s. "
                "Returning safe fallback (0).", features, e
            )
            return 0

    # ------------------------------------------------------------------
    # FEEDBACK / ONLINE LEARNING
    # ------------------------------------------------------------------
    def update(self, features, is_attack):
        """
        Incorporate a labelled sample into the training set.

        features  : list of numerics
        is_attack : bool (True = attack, False = normal behaviour)
        """
        if not isinstance(features, (list, np.ndarray)) or len(features) != EXPECTED_FEATURES:
            logger.warning(
                "[ML] update() skipped: invalid features %s", features
            )
            return

        if not is_attack:
            # IsolationForest learns the normal distribution
            self.data.append(list(features))
            logger.debug("[ML] Normal sample added. Dataset size: %d", len(self.data))

        # Keep dataset bounded
        if len(self.data) > 1000:
            self.data = self.data[-500:]

        # Periodic retraining
        if len(self.data) > 0 and len(self.data) % 20 == 0:
            logger.info("[ML] Periodic retraining triggered at %d samples.", len(self.data))
            self.train()

    # ------------------------------------------------------------------
    # STATUS
    # ------------------------------------------------------------------
    @property
    def status(self):
        return {
            "trained": self.trained,
            "samples": len(self.data),
            "model_file_exists": os.path.exists(MODEL_PATH),
        }
