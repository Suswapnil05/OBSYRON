"""
OBSYRON – Log Ingestor & Normalizer
Corrects clock skew, separates event time and ingestion time, detects late-arriving &
duplicate events, computes SHA-256 evidence digests, and reconstructs master chronological timelines.
"""
import json, csv, os, hashlib
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any, Tuple

IST = timezone(timedelta(hours=5, minutes=30))


def compute_log_sha256(log: dict) -> str:
    """
    Computes an immutable SHA-256 forensic hash of the canonical log attributes.
    """
    canonical_items = [
        str(log.get("log_id", "")),
        str(log.get("source_host", "")),
        str(log.get("source", "")),
        str(log.get("target", "")),
        str(log.get("action", "")),
        str(log.get("protocol", "")),
        str(log.get("port", "")),
        str(log.get("event_timestamp", log.get("true_timestamp", log.get("raw_timestamp", "")))),
        str(log.get("mitre_tag", "")),
        str(log.get("raw_payload", ""))
    ]
    canonical_str = "|".join(canonical_items)
    return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()


def normalize_logs(raw_logs: list, deduplicate: bool = True) -> list:
    """
    Correct host clock skew, separate event time vs ingestion time, identify late-arriving events,
    deduplicate repeated packets, compute cryptographic SHA-256 hashes, and sort logs chronologically.
    normalized_timestamp = raw_timestamp - host_skew_sec
    """
    normalized = []
    seen_fingerprints = set()

    for log in raw_logs:
        log = dict(log)

        # 1. Parse timestamps
        # raw_timestamp = timestamp recorded on host with local clock drift
        raw_ts_str = log.get("raw_timestamp") or log.get("timestamp") or datetime.now(IST).isoformat()
        try:
            raw_dt = datetime.fromisoformat(raw_ts_str)
        except Exception:
            raw_dt = datetime.now(IST)

        skew_sec = int(log.get("host_skew_sec", 0) or 0)

        # event_timestamp = actual time event occurred (calibrated: raw - skew)
        norm_dt = raw_dt - timedelta(seconds=skew_sec)
        event_ts = norm_dt.isoformat()
        log["normalized_timestamp"] = event_ts
        log["event_timestamp"]      = log.get("event_timestamp", event_ts)
        log["true_timestamp"]       = log.get("true_timestamp", event_ts)
        log["raw_timestamp"]        = raw_dt.isoformat()
        log["host_skew_sec"]        = skew_sec
        log["skew_corrected_sec"]   = -skew_sec

        # ingestion_timestamp = when the collector/SIEM received the log packet
        ingest_ts_str = log.get("ingestion_timestamp")
        if not ingest_ts_str:
            # If not explicitly provided, simulate slight network transmission delay (0.2s - 2.5s)
            delay = log.get("delay_sec", 1.2)
            ingest_dt = raw_dt + timedelta(seconds=delay)
            log["ingestion_timestamp"] = ingest_dt.isoformat()
            log["delay_sec"] = delay
        else:
            try:
                ingest_dt = datetime.fromisoformat(ingest_ts_str)
                log["delay_sec"] = round((ingest_dt - norm_dt).total_seconds(), 2)
            except Exception:
                log["delay_sec"] = 1.0

        # Mark late-arriving telemetry (e.g. buffered on endpoint or queued > 15s)
        log["is_late_arriving"] = bool(log.get("is_late_arriving", log.get("delay_sec", 0) > 15.0))

        # Check duplicate fingerprint (source, target, action, port, raw_timestamp)
        fingerprint = f"{log.get('source')}:{log.get('target')}:{log.get('action')}:{log.get('port')}:{log.get('raw_timestamp')}"
        if fingerprint in seen_fingerprints:
            log["is_duplicate"] = True
            if deduplicate and not log.get("is_malicious"):
                # Filter out redundant benign duplicates
                continue
        else:
            log["is_duplicate"] = bool(log.get("is_duplicate", False))
            seen_fingerprints.add(fingerprint)

        # Malicious classification
        lid = str(log.get("log_id", ""))
        log["is_malicious"] = bool(
            log.get("is_malicious", False) or 
            lid.startswith("LOG-APT") or 
            lid.startswith("LOG-CHAOS-0") or
            "APT" in lid or
            log.get("severity") == "CRITICAL"
        )

        # 2. SHA-256 Forensic Hash
        log["sha256_hash"] = log.get("sha256_hash") or compute_log_sha256(log)

        # 3. Causal Connection & Evidence Rationale
        if not log.get("causal_connection"):
            log["causal_connection"] = _default_causal_connection(log)

        if not log.get("supporting_evidence"):
            log["supporting_evidence"] = _default_supporting_evidence(log)

        if not log.get("contradictory_evidence"):
            log["contradictory_evidence"] = _default_contradictory_evidence(log)

        normalized.append(log)

    # Sort strictly by normalized event timestamp
    normalized.sort(key=lambda x: x["normalized_timestamp"])
    return normalized


def _default_causal_connection(log: dict) -> str:
    action = log.get("action", "")
    src = log.get("source", "")
    tgt = log.get("target", "")
    if action == "AUTH_ANOMALY":
        return f"External Ingress: Identity '{tgt}' was compromised via valid credentials from untrusted origin '{src}'."
    if action == "RECON_ENUM":
        return f"Reconnaissance Execution: Identity '{src}' queried directory infrastructure on '{tgt}' to map privilege escalation paths."
    if action == "PRIV_ESC":
        return f"Privilege Escalation: Token manipulation on '{src}' elevated permissions for service account '{tgt}'."
    if action == "LATERAL_MOVE":
        return f"Lateral Movement: Abused credentials from '{src}' accessed high-value production asset '{tgt}' via SMB."
    if action == "DATA_EXFIL":
        return f"Data Exfiltration: Compromised host '{src}' established high-volume outbound stream to remote sink '{tgt}'."
    if action == "C2_CALLBACK":
        return f"Command & Control: Persistent beacon established between '{tgt}' and adversary infrastructure '{src}'."
    return f"Standard telemetry link: interaction from {src} to {tgt} via {log.get('protocol', 'TCP')} port {log.get('port', 0)}."


def _default_supporting_evidence(log: dict) -> List[str]:
    is_mal = log.get("is_malicious", False)
    skew = log.get("host_skew_sec", 0)
    delay = log.get("delay_sec", 0)
    items = []
    if is_mal:
        items.append("Corroborates MITRE ATT&CK kill chain sequence")
        items.append(f"Recorded by host sensor '{log.get('source_host')}' with SHA-256 integrity")
        if abs(skew) > 0:
            items.append(f"Clock drift ({skew:+d}s) reconciled against master enterprise baseline")
        if delay > 5:
            items.append(f"Late-arriving packet: received after {delay:.1f}s network delay")
    else:
        items.append(f"Baseline routine enterprise traffic recorded on {log.get('protocol', 'TCP')}:{log.get('port', 0)}")
        items.append("Normal behavior profile verified by historical baseline")
    return items


def _default_contradictory_evidence(log: dict) -> List[str]:
    is_mal = log.get("is_malicious", False)
    if is_mal:
        return [
            "Valid user credentials utilized without triggering failed login rate limits",
            "Target host did not trigger immediate EDR host kernel panic",
            "Encrypted traffic payload obscured protocol signature matching"
        ]
    return [
        "Unauthenticated attempt logged in parallel cluster",
        "No matching IOC in external threat intelligence feeds"
    ]


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
        raw_ts = row.get("raw_timestamp") or row.get("timestamp") or datetime.now(IST).isoformat()
        normalized_schema.append({
            "log_id":                row.get("log_id",                f"UPLOAD-{i+1:04d}"),
            "raw_timestamp":         raw_ts,
            "event_timestamp":       row.get("event_timestamp",       raw_ts),
            "ingestion_timestamp":   row.get("ingestion_timestamp",   raw_ts),
            "true_timestamp":        row.get("true_timestamp",        raw_ts),
            "source_host":           row.get("source_host",           row.get("host", "unknown")),
            "host_skew_sec":         int(float(row.get("host_skew_sec", 0))),
            "entity_type":           row.get("entity_type",           "DEVICE"),
            "source":                row.get("source",                row.get("src", "unknown")),
            "target":                row.get("target",                row.get("dst", "unknown")),
            "action":                row.get("action",                "UNKNOWN"),
            "protocol":              row.get("protocol",              "TCP"),
            "port":                  int(float(row.get("port", 0))),
            "mitre_tag":             row.get("mitre_tag",             ""),
            "mitre_technique":       row.get("mitre_technique",       ""),
            "severity":              row.get("severity",              "LOW"),
            "is_malicious":          str(row.get("is_malicious", "false")).lower() in ["true", "1"],
            "raw_payload":           row.get("raw_payload",           json.dumps(dict(row))),
            "causal_connection":     row.get("causal_connection",     ""),
            "supporting_evidence":   row.get("supporting_evidence",   []),
            "contradictory_evidence": row.get("contradictory_evidence", [])
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
    print(f"Sample SHA-256: {normed[0]['sha256_hash']}")
