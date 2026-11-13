"""
OBSYRON – Log Ingestor & Normalizer
Corrects clock skew, sorts logs chronologically, parses uploaded files.
"""
import json, csv, os
from datetime import datetime, timezone, timedelta
from typing import Optional

IST = timezone(timedelta(hours=5, minutes=30))


def normalize_logs(raw_logs: list) -> list:
    """
    Correct host clock skew and sort logs by normalized timestamp.
    normalized_timestamp = raw_timestamp - host_skew_sec
    """
    normalized = []
    for log in raw_logs:
        log = dict(log)
        try:
            raw_dt = datetime.fromisoformat(log["raw_timestamp"])
        except Exception:
            raw_dt = datetime.now(IST)

        skew_sec = log.get("host_skew_sec", 0) or 0
        # Correct the skew
        norm_dt = raw_dt - timedelta(seconds=skew_sec)
        log["normalized_timestamp"] = norm_dt.isoformat()
        log["skew_corrected_sec"]   = -skew_sec
        log["is_malicious"] = log.get("is_malicious", log.get("log_id", "").startswith("LOG-APT"))
        normalized.append(log)

    normalized.sort(key=lambda x: x["normalized_timestamp"])
    return normalized


def parse_uploaded_file(filepath: str) -> list:
    """
    Parse uploaded .json or .csv log file and normalize it.
    """
    ext = os.path.splitext(filepath)[1].lower()
    raw = []

    if ext == ".json":
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            raw = data
        elif isinstance(data, dict) and "logs" in data:
            raw = data["logs"]

    elif ext == ".csv":
        with open(filepath, "r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                raw.append(dict(row))
    else:
        raise ValueError(f"Unsupported file type: {ext}")

    # Normalize schema – fill missing fields with defaults
    normalized_schema = []
    for i, row in enumerate(raw):
        normalized_schema.append({
            "log_id":          row.get("log_id",          f"UPLOAD-{i+1:04d}"),
            "raw_timestamp":   row.get("raw_timestamp",   row.get("timestamp", datetime.now(IST).isoformat())),
            "true_timestamp":  row.get("true_timestamp",  row.get("raw_timestamp", datetime.now(IST).isoformat())),
            "source_host":     row.get("source_host",     row.get("host", "unknown")),
            "host_skew_sec":   int(float(row.get("host_skew_sec", 0))),
            "entity_type":     row.get("entity_type",     "DEVICE"),
            "source":          row.get("source",          row.get("src", "unknown")),
            "target":          row.get("target",          row.get("dst", "unknown")),
            "action":          row.get("action",          "UNKNOWN"),
            "protocol":        row.get("protocol",        "TCP"),
            "port":            int(float(row.get("port", 0))),
            "mitre_tag":       row.get("mitre_tag",       ""),
            "mitre_technique": row.get("mitre_technique", ""),
            "severity":        row.get("severity",        "LOW"),
            "is_malicious":    str(row.get("is_malicious", "false")).lower() == "true",
            "raw_payload":     row.get("raw_payload",     json.dumps(dict(row))),
        })

    return normalize_logs(normalized_schema)


def get_timeline_snapshot(normalized_logs: list, up_to_timestamp: str) -> list:
    """
    Return logs where normalized_timestamp <= up_to_timestamp.
    """
    try:
        cutoff = datetime.fromisoformat(up_to_timestamp)
    except Exception:
        return normalized_logs

    return [
        log for log in normalized_logs
        if datetime.fromisoformat(log["normalized_timestamp"]) <= cutoff
    ]


if __name__ == "__main__":
    from log_generator import generate_logs
    raw = generate_logs()
    normed = normalize_logs(raw)
    print(f"Normalized {len(normed)} logs")
    print(f"Timeline: {normed[0]['normalized_timestamp']} → {normed[-1]['normalized_timestamp']}")
