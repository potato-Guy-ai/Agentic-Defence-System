import time
import subprocess
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

IGNORE = [".git", "__pycache__", ".venv"]

class AutoCommitHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.is_directory:
            return

        if any(x in event.src_path for x in IGNORE):
            return

        print(f"[CHANGE DETECTED] {event.src_path}")

        try:
            subprocess.run(["git", "add", "."], check=True)

            # Avoid empty commits
            result = subprocess.run(
                ["git", "diff", "--cached", "--quiet"]
            )
            if result.returncode == 0:
                return

            subprocess.run(
                ["git", "commit", "-m", f"auto: updated {event.src_path}"],
                check=True
            )
            subprocess.run(["git", "push"], check=True)

            print("[PUSHED TO GITHUB]")

        except Exception as e:
            print("[ERROR]", e)

if __name__ == "__main__":
    observer = Observer()
    observer.schedule(AutoCommitHandler(), ".", recursive=True)
    observer.start()

    print("[WATCHING FILE CHANGES...]")

    try:
        while True:
            time.sleep(3)
    except KeyboardInterrupt:
        observer.stop()

    observer.join()