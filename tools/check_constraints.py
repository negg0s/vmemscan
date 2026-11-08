import os
import sys

banned_words = [
    "robust",
    "comprehensive",
    "seamless",
    "leverage",
    "utilize",
    "powerful",
    "blazing",
    "cutting-edge",
    "game changer",
    "it's worth noting",
    "in order to",
    "delve",
]

banned_chars = ["\u2014", "\u2013"]

violations = []
root_dir = r"D:\Projects\vmemscan"

for dirpath, dirnames, filenames in os.walk(root_dir):
    if ".git" in dirpath or "build" in dirpath:
        continue
    for fname in filenames:
        if fname.endswith((".cpp", ".hpp", ".h", ".txt", ".md", ".yml", ".yaml", ".json")):
            fpath = os.path.join(dirpath, fname)
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                for c in banned_chars:
                    if c in content:
                        violations.append(f"Banned char {repr(c)} in {fpath}")
                for w in banned_words:
                    if w in content.lower():
                        violations.append(f"Banned word '{w}' in {fpath}")
                for char in content:
                    cp = ord(char)
                    if (
                        (0x1F600 <= cp <= 0x1F64F)
                        or (0x1F300 <= cp <= 0x1F5FF)
                        or (0x1F680 <= cp <= 0x1F6FF)
                        or (0x1F1E0 <= cp <= 0x1F1FF)
                        or (0x2600 <= cp <= 0x26FF)
                        or (0x2700 <= cp <= 0x27BF)
                    ):
                        violations.append(f"Emoji {repr(char)} in {fpath}")
                        break

if violations:
    print(f"Violations found ({len(violations)}):")
    for v in violations:
        print(f"  - {v}")
    sys.exit(1)
else:
    print("All files clean: zero em-dashes, zero emojis, zero banned buzzwords.")
    sys.exit(0)
