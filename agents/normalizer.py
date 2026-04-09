import re

class NormalizerAgent:
    def normalize(self, raw_log):
        # CASE 1: Already structured (dict)
        if isinstance(raw_log, dict):
            return raw_log

        # CASE 2: Plain text logs
        log = raw_log.lower()

        ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', log)
        ip = ip_match.group() if ip_match else "0.0.0.0"

        if "login_failed" in log or "failed login" in log:
            event = "login_failed"

        elif "login_success" in log or "login success" in log:
            event = "login_success"

        elif "ddos" in log:
            event = "ddos_attempt"

        elif "scan" in log:
            event = "port_scan"

        elif "malware" in log:
            event = "malware_download"

        elif "data_download" in log:
            event = "data_download"

        elif "admin_access" in log:
            event = "admin_access"

        elif "multiple_system_access" in log:
            event = "multiple_system_access"
        else:
            event = "unknown"

        return {
            "ip": ip,
            "event": event,
            "raw": raw_log
        }