import time
import pyperclip
import subprocess

last = ""

print("Watching clipboard...")

while True:
    current = pyperclip.paste()

    if current != last and "FILE:" in current:
        print("New Claude output detected")

        with open("claude_output.txt", "a", encoding="utf-8") as f:
            f.write("\n\n" + current)  # add spacing between outputs

        subprocess.run(["python", "apply_changes.py"])

        last = current

    time.sleep(2)