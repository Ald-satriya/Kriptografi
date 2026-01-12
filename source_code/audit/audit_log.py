import hashlib
import json
from datetime import datetime


def append_log(log_path, activity, prev_hash=""):
    """
    Low-level audit logger (hash chained)
    """
    entry = {
        "time": datetime.utcnow().isoformat(),
        "activity": activity,
        "prev_hash": prev_hash
    }

    raw = json.dumps(entry, sort_keys=True)
    entry["hash"] = hashlib.sha256(raw.encode()).hexdigest()

    with open(log_path, "a") as f:
        f.write(json.dumps(entry) + "\n")

    return entry["hash"]


# ✅ ALIAS UNTUK app.py (WAJIB ADA)
def log_action(filename, status):
    """
    High-level audit action logger
    Dipanggil dari app.py / execute / test
    """
    activity = f"{filename} - {status}"
    append_log("audit_log.json", activity)
