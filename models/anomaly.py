import os
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib


MODEL_PATH = "models/anomaly_model.pkl"
DATA_PATH = "models/training_data.npy"


class AnomalyModel:
    def __init__(self):
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.trained = False
        self.data = []

        # Load existing model if available
        if os.path.exists(MODEL_PATH):
            try:
                self.model = joblib.load(MODEL_PATH)
                self.trained = True
            except Exception:
                pass

        # Load training data if exists
        if os.path.exists(DATA_PATH):
            try:
                self.data = list(np.load(DATA_PATH))
            except Exception:
                self.data = []

    # -----------------------------
    # INITIAL TRAINING
    # -----------------------------
    def train(self):
        if len(self.data) < 10:
            # fallback minimal normal data
            self.data.extend([
                [1, 0, 0],
                [1, 0, 0],
                [1, 0, 0],
                [2, 0, 0],
            ])

        X = np.array(self.data)
        self.model.fit(X)
        self.trained = True
        os.makedirs("models", exist_ok=True)
        joblib.dump(self.model, MODEL_PATH)
        print(f"[MODEL] Trained and saved — {len(X)} samples")

        # Save model
        joblib.dump(self.model, MODEL_PATH)
        np.save(DATA_PATH, X)

    # -----------------------------
    # PREDICTION
    # -----------------------------
    def predict(self, features):
        if not self.trained:
            self.train()

        prediction = self.model.predict([features])
        return prediction[0]  # -1 anomaly, 1 normal

    # -----------------------------
    # FEEDBACK LEARNING
    # -----------------------------
    def update(self, features, is_attack):
        """
        features: list
        is_attack: bool (True = anomaly, False = normal)
        """

        if not is_attack:
            # Only learn normal behavior (important for IsolationForest)
            self.data.append(features)

        # Limit dataset size (avoid memory explosion)
        if len(self.data) > 1000:
            self.data = self.data[-500:]

        # Retrain periodically
        if len(self.data) % 20 == 0:
            self.train()
