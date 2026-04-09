import re
import os

# ✅ Allowed file types (edit if needed)
ALLOWED_EXTENSIONS = [
    ".py", ".txt", ".json", ".js", ".ts",
    ".env", ".md", ".yaml", ".yml"
]

def apply_changes(text):
    pattern = r"FILE:\s*(.*?)\n```(?:\w+)?\n(.*?)```"
    matches = re.findall(pattern, text, re.DOTALL)

    if not matches:
        print("[NO VALID FILE BLOCKS FOUND]")
        return

    for file_path, content in matches:
        try:
            file_path = file_path.strip().replace("\\", "/")

            # 🚫 Prevent directory traversal
            if ".." in file_path:
                print(f"[SKIPPED - INVALID PATH] {file_path}")
                continue

            # 🚫 Check allowed extensions
            if not any(file_path.endswith(ext) for ext in ALLOWED_EXTENSIONS):
                print(f"[SKIPPED - INVALID FILE TYPE] {file_path}")
                continue

            dir_name = os.path.dirname(file_path)

            # ✅ Create folders if missing
            if dir_name and not os.path.exists(dir_name):
                os.makedirs(dir_name, exist_ok=True)
                print(f"[CREATED FOLDER] {dir_name}")

            # ✅ Write file safely
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content.strip() + "\n")

            print(f"[UPDATED FILE] {file_path}")

        except Exception as e:
            print(f"[ERROR] {file_path} -> {e}")

if __name__ == "__main__":
    try:
        with open("claude_output.txt", "r", encoding="utf-8") as f:
            data = f.read()

        apply_changes(data)

    except FileNotFoundError:
        print("[ERROR] claude_output.txt not found")