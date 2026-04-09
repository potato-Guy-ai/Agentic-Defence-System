from collections import defaultdict, deque
from models.anomaly import AnomalyModel
from utils.message import create_message
from utils.threat_intel import is_known_bad_ip
import time

ATTACK_CHAIN = ["port_scan", "login_failed", "admin_access", "multiple_system_access", "data_download"]

class DetectionAgent:
    def __init__(self):
        self.ip_activity = {}
        self.request_timestamps = defaultdict(deque)
        self.login_attempts = defaultdict(int)
        self.request_count = defaultdict(int)
        self.model = AnomalyModel()
        self.last_location = {}
        self.last_location_time = {}
        self.threat_timeline = defaultdict(list)
        self.WINDOW = 60
        

    def _request_rate(self, ip):
        now = time.time()
        dq = self.request_timestamps[ip]
        dq.append(now)
        while dq and dq[0] < now - self.WINDOW:
            dq.popleft()
        return len(dq)

    def _check_attack_chain(self, ip):
        timeline_events = [e for _, e in self.threat_timeline[ip]]
        matched = sum(1 for stage in ATTACK_CHAIN if stage in timeline_events)
        return matched >= 3, matched

    def _check_impossible_travel(self, ip, new_location):
        if ip not in self.last_location:
            return False
        elapsed_minutes = (time.time() - self.last_location_time.get(ip, 0)) / 60
        return self.last_location[ip] != new_location and elapsed_minutes < 60

    def extract_features(self, event):
        event_map = {
            "login_failed": 1, "port_scan": 2,
            "ddos_attempt": 3, "wifi_intrusion": 4, "malware_download": 5
        }
        return [event_map.get(event["event"], 0), 0, 0]

    def detect(self, event):
        ip = event["ip"]
        event_type = event["event"]

        if ip not in self.ip_activity:
            self.ip_activity[ip] = {"events": [], "count": 0}

        self.threat_timeline[ip].append((time.time(), event_type))

        self.request_count[ip] += 1

        if self.request_count[ip] > 50 or self._request_rate(ip) > 50:
            return create_message(
                sender="detection",
                data={"ip": ip, "threat": "flood_attack", "confidence": 0.95,
                      "reasons": ["50+ requests in 60s window"]},
                priority="high"
            )

        threats = []

        if is_known_bad_ip(ip):
            threats.append(("known_attacker", 0.6, "matched threat intelligence feed"))

        if event_type == "malware_download":
            threats.append(("malware", 0.9, "malicious file download"))

        if event_type == "login_success":
            location = event.get("location")
            if location:
                if self._check_impossible_travel(ip, location):
                    threats.append(("impossible_travel", 0.95,
                        f"location changed {self.last_location[ip]} to {location} in under 60 min"))
                self.last_location[ip] = location
                self.last_location_time[ip] = time.time()

        if event_type == "login_failed":
            self.login_attempts[ip] += 1
            attempts = self.login_attempts[ip]
            if attempts >= 20:
                threats.append(("brute_force_high", 0.95, f"{attempts} failed logins"))
            elif attempts >= 10:
                threats.append(("brute_force_medium", 0.85, f"{attempts} failed logins"))
            elif attempts >= 5:
                threats.append(("brute_force_low", 0.7, f"{attempts} failed logins"))

        if event_type == "port_scan":
            threats.append(("port_scan", 0.7, "port scanning detected"))

        if event_type == "ddos_attempt":
            threats.append(("ddos", 0.9, "high traffic spike"))

        if event_type == "wifi_intrusion":
            threats.append(("unauthorized_access", 0.85, "unknown device connected"))

        if event_type == "data_download":
            self.ip_activity[ip]["count"] += 1
            if self.ip_activity[ip]["count"] > 10:
                threats.append(("data_exfiltration", 0.9, "large volume of data downloads"))

        if event_type == "admin_access":
            threats.append(("privilege_escalation", 0.85, "unauthorized admin access"))

        if event_type == "multiple_system_access":
            threats.append(("lateral_movement", 0.8, "accessing multiple systems rapidly"))

        self.ip_activity[ip]["events"].append(event_type)

        if len(set(self.ip_activity[ip]["events"])) > 4:
            threats.append(("suspicious_behavior", 0.75, "unusual variety of actions"))

        is_chain, stages_matched = self._check_attack_chain(ip)
        if is_chain:
            threats.append(("multi_stage_attack", 0.98,
                f"attack chain detected: {stages_matched} stages matched"))

        features = self.extract_features(event)
        if self.model.predict(features) == -1 and not threats:
            threats.append(("anomaly", 0.6, "ML anomaly detected"))

        if not threats:
            return create_message(
                sender="detection",
                data={"ip": ip, "threat": None, "confidence": 0, "reasons": []},
                priority="low"
            )

        top = max(threats, key=lambda x: x[1])
        threat, confidence, _ = top
        reasons = [t[2] for t in threats]

        return create_message(
            sender="detection",
            data={"ip": ip, "threat": threat, "confidence": confidence, "reasons": reasons},
            priority="high" if confidence > 0.7 else "low"
        )
