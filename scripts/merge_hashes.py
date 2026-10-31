"""Merge MalwareBazaar API responses into db/android_sha256.txt (deduplicated, capped)."""
import json
import re
import sys

DB = "db/android_sha256.txt"
CAP = 200_000
HEX64 = re.compile(r"^[0-9a-f]{64}$")

existing = []
with open(DB, encoding="utf-8") as f:
    for line in f:
        h = line.strip().lower()
        if HEX64.match(h):
            existing.append(h)

seen = set(existing)
new = []
for path in sys.argv[1:]:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"skip {path}: {e}")
        continue
    if data.get("query_status") != "ok":
        print(f"{path}: {data.get('query_status')}")
        continue
    for item in data.get("data") or []:
        h = (item.get("sha256_hash") or "").lower()
        if HEX64.match(h) and h not in seen:
            seen.add(h)
            new.append(h)

merged = (new + existing)[:CAP]  # newest first
with open(DB, "w", encoding="utf-8") as f:
    f.write("# Android malware SHA-256 hashes from MalwareBazaar (abuse.ch) — updated daily\n")
    f.write("\n".join(merged))
    f.write("\n")
print(f"added {len(new)}, total {len(merged)}")
