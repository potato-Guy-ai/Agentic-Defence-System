import json
import os

class Storage:
    def __init__(self, file="storage.json"):
        self.file = file

        if not os.path.exists(self.file):
            with open(self.file, "w") as f:
                json.dump({}, f)

    def save(self, key, value):
        with open(self.file, "r") as f:
            data = json.load(f)

        data[key] = value

        with open(self.file, "w") as f:
            json.dump(data, f, indent=2)

    def load(self, key):
        with open(self.file, "r") as f:
            data = json.load(f)

        return data.get(key, {})