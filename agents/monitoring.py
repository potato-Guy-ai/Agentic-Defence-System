import os
import json
import time
from datetime import datetime

class MonitoringAgent:
    """
    Real log ingestion — three sources in priority order:
    1. Tail /var/log/auth.log (Linux syslog)
    2. Stream data/logs.json respecting timestamps
    3. Fall back to tailing any file set in LOG_FILE env var
    """

    def __init__(self):
        self.log_file = os.getenv("LOG_FILE", "/var/log/auth.log")
        self.json_log = "data/logs.json"
        self._json_index = 0
        self._json_events = []
        self._mode = self._detect_mode()
        self._tail_pos = 0

        if self._mode == "json":
            with open(self.json_log) as f:
                self._json_events = json.load(f)
            print(f"[MONITOR] JSON mode — {len(self._json_events)} events loaded")
        elif self._mode == "tail":
            # Start tail from end of file
            with open(self.log_file) as f:
                f.seek(0, 2)
                self._tail_pos = f.tell()
            print(f"[MONITOR] Tail mode — watching {self.log_file}")

    def _detect_mode(self):
        if os.path.exists(self.log_file):
            return "tail"
        if os.path.exists(self.json_log):
            return "json"
        return "json"  # default

    def get_event(self):
        if self._mode == "tail":
            return self._tail_event()
        return self._json_event()

    def _tail_event(self):
        """Non-blocking tail. Polls every 0.5s until a new line appears."""
        while True:
            try:
                with open(self.log_file) as f:
                    f.seek(self._tail_pos)
                    line = f.readline()
                    if line:
                        self._tail_pos = f.tell()
                        return self._parse_syslog(line.strip())
            except Exception as e:
                print(f"[MONITOR] tail error: {e}")
            time.sleep(0.5)

    def _parse_syslog(self, line):
        """Parse common auth.log patterns into structured events."""
        import re
        ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', line)
        ip = ip_match.group() if ip_match else "0.0.0.0"

        line_lower = line.lower()
        if "failed password" in line_lower or "authentication failure" in line_lower:
            event = "login_failed"
        elif "accepted password" in line_lower or "accepted publickey" in line_lower:
            event = "login_success"
        elif "invalid user" in line_lower:
            event = "login_failed"
        elif "port" in line_lower and "scan" in line_lower:
            event = "port_scan"
        else:
            event = "unknown"

        return {"ip": ip, "event": event, "raw": line, "timestamp": datetime.utcnow().isoformat()}

    def _json_event(self):
        """Replay logs.json respecting relative timing."""
        if self._json_index >= len(self._json_events):
            self._json_index = 0  # loop

        event = self._json_events[self._json_index]
        self._json_index += 1

        # Respect timestamp gaps between events
        if self._json_index > 1:
            prev = self._json_events[self._json_index - 2]
            curr = event
            try:
                fmt = "%H:%M"
                t1 = datetime.strptime(prev["timestamp"], fmt)
                t2 = datetime.strptime(curr["timestamp"], fmt)
                gap = (t2 - t1).seconds
                if 0 < gap <= 10:
                    time.sleep(gap)
                else:
                    time.sleep(0.2)
            except Exception:
                time.sleep(0.2)

        return event
