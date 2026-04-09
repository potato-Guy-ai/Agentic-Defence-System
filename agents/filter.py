class FilterAgent:
    def __init__(self):
        # keywords for relevant security logs
        self.keywords = [
            "login", "failed", "ddos", "scan",
            "intrusion", "malware", "unauthorized",
            "admin", "data", "system", "access"
        ]

    def is_relevant(self, event):
        event_str = str(event).lower()

        for keyword in self.keywords:
            if keyword in event_str:
                return True

        return False