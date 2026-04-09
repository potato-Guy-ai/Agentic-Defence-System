import numpy as np
import threading

EVENT_CODE_MAP = {
    "login_failed": 1, "port_scan": 2, "ddos_attempt": 3,
    "wifi_intrusion": 4, "malware_download": 5,
    "data_download": 6, "admin_access": 7,
    "multiple_system_access": 8, "login_success": 0
}

RETRAIN_THRESHOLD = 50  # retrain every N block/alert events

class FeedbackAgent:
    def __init__(self, anomaly_model=None):
        self.model = anomaly_model

    def update(self, message):
        if message is None:
            return

        # Future: adaptive learning / retraining
        # For now, just safe placeholder
        data = message.get("data", {})
        threat = data.get("threat")
        action = data.get("action")

        if self.model:
            features = [0, 0, 0]  # placeholder (we improve later)

            is_attack = action in ["block", "alert"]

            self.model.update(features, is_attack)
