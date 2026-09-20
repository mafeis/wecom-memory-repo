# -*- coding: utf-8 -*-
"""Extract and persist wxSQLite3 keys per account snapshot. Saves keys.json."""
import sys, os, json

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "vendors", "wecom-reader"))
from wecom_reader.crypto.key_extract import extract_key

RAW = os.path.join(BASE, "wxwork_data", "raw")
OUT = os.path.join(BASE, "wxwork_data", "keys.json")

result = {}
accounts = [d for d in os.listdir(RAW) if d.isdigit()]
for acc in accounts:
    db_dir = os.path.join(RAW, acc)
    print(f"extracting keys for {acc} ...", flush=True)
    try:
        km = extract_key(db_dir=db_dir, timeout=180)
        km.pop("_db_dir", None)
        result[acc] = km
        print(f"  {len(km)} keys")
    except Exception as e:
        print(f"  FAILED: {e}")

with open(OUT, "w", encoding="utf-8") as f:
    json.dump(result, f, indent=2)
print(f"saved -> {OUT}")
