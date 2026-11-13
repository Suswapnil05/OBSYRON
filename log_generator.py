"""
OBSYRON – Log Generator
Generates synthetic enterprise logs with embedded 6-step APT kill chain.
"""
import random, json
from datetime import datetime, timezone, timedelta
from copy import deepcopy

# IST timezone offset
IST = timezone(timedelta(hours=5, minutes=30))

# Base date for simulation
BASE_DATE = datetime(2026, 11, 14, 1, 0, 0, tzinfo=IST)

# Host clock skew offsets (seconds) – consistent per host
HOST_SKEW = {
    "wkst-04-dev":        12,
    "dc-01":              -7,
    "app-srv-02":         18,
    "db-prod-01":         -5,
    "mail-srv-03":         9,
    "wkst-07-fin":       -14,
    "ext-185.220.101.47":  3,
}

INTERNAL_USERS  = ["emp_alice", "emp_bob", "emp_carol", "emp_dave", "emp_eve", "emp_rohan"]
INTERNAL_HOSTS  = ["wkst-04-dev", "dc-01", "app-srv-02", "db-prod-01", "mail-srv-03", "wkst-07-fin"]
SERVICES        = ["svc_ci_deploy", "svc_ldap", "svc_backup", "svc_monitor", "svc_mail"]
INT_IPS         = ["10.0.1.10", "10.0.1.11", "10.0.2.5", "10.0.2.6", "10.0.1.20"]


def _ts(minutes_offset: float, host: str, inject_skew: bool) -> str:
    """Return ISO timestamp with optional host clock skew applied."""
    true_time = BASE_DATE + timedelta(minutes=minutes_offset)
    skew = HOST_SKEW.get(host, 0) if inject_skew else 0
    raw_time = true_time + timedelta(seconds=skew)
    return raw_time.isoformat()


def _make_log(log_id, minutes_offset, source_host, entity_type,
              source, target, action, protocol, port, mitre_tag,
              mitre_technique, severity, raw_payload_extra,
              inject_skew=True):
    skew = HOST_SKEW.get(source_host, 0) if inject_skew else 0
    true_time = BASE_DATE + timedelta(minutes=minutes_offset)
    raw_time  = true_time + timedelta(seconds=skew)
    payload = {
        "log_id": log_id,
        "source_host": source_host,
        "source": source,
        "target": target,
        "action": action,
        **raw_payload_extra
    }
    return {
        "log_id":           log_id,
        "raw_timestamp":    raw_time.isoformat(),
        "true_timestamp":   true_time.isoformat(),
        "source_host":      source_host,
        "host_skew_sec":    skew,
        "entity_type":      entity_type,
        "source":           source,
        "target":           target,
        "action":           action,
        "protocol":         protocol,
        "port":             port,
        "mitre_tag":        mitre_tag,
        "mitre_technique":  mitre_technique,
        "severity":         severity,
        "is_malicious":     log_id.startswith("LOG-APT"),
        "raw_payload":      json.dumps(payload),
    }


def _apt_kill_chain(inject_skew=True):
    """The 6-step stealth APT kill chain logs."""
    return [
        _make_log("LOG-APT-001", 15.0, "wkst-04-dev", "USER",
                  "185.220.101.47", "emp_rohan", "AUTH_ANOMALY",
                  "HTTPS", 443, "T1078", "T1078 - Valid Accounts (Initial Access)",
                  "CRITICAL",
                  {"detail": "Off-hours login from external IP 185.220.101.47 to wkst-04-dev",
                   "geo": "TOR exit node", "user_agent": "Mozilla/5.0"},
                  inject_skew),
        _make_log("LOG-APT-002", 16.0, "wkst-04-dev", "USER",
                  "emp_rohan", "wkst-04-dev", "RECON_ENUM",
                  "LDAP", 389, "T1087", "T1087 - Account Discovery",
                  "HIGH",
                  {"command": "net user /domain", "stdout_lines": 42,
                   "detail": "Domain user enumeration via LDAP port 389"},
                  inject_skew),
        _make_log("LOG-APT-003", 18.0, "wkst-04-dev", "SERVICE",
                  "wkst-04-dev", "svc_ci_deploy", "PRIV_ESC",
                  "RPC", 135, "T1558", "T1558 - Steal or Forge Kerberos Tickets",
                  "CRITICAL",
                  {"privilege": "SeDebugPrivilege", "granted_by": "emp_rohan",
                   "detail": "Service account svc_ci_deploy silently granted SeDebugPrivilege on wkst-04-dev"},
                  inject_skew),
        _make_log("LOG-APT-004", 20.0, "db-prod-01", "SERVICE",
                  "svc_ci_deploy", "db-prod-01", "LATERAL_MOVE",
                  "SMB", 445, "T1021", "T1021 - Remote Services (SMB ADMIN$)",
                  "CRITICAL",
                  {"auth_type": "NTLM", "share": "ADMIN$",
                   "detail": "svc_ci_deploy authenticates to db-prod-01 via SMB ADMIN$"},
                  inject_skew),
        _make_log("LOG-APT-005", 22.0, "db-prod-01", "DEVICE",
                  "db-prod-01", "185.220.101.47", "DATA_EXFIL",
                  "TCP", 4444, "T1048", "T1048 - Exfiltration Over Alternative Protocol",
                  "CRITICAL",
                  {"bytes_sent": 2457600, "dst_port": 4444,
                   "detail": "db-prod-01 opens outbound TCP:4444 to external IP – 2.45 MB exfiltrated"},
                  inject_skew),
        _make_log("LOG-APT-006", 23.0, "ext-185.220.101.47", "AUTH_ENDPOINT",
                  "185.220.101.47", "db-prod-01", "C2_CALLBACK",
                  "TCP", 4444, "T1048", "T1048 - Command and Control Beaconing",
                  "CRITICAL",
                  {"beacon_interval_sec": 30, "encrypted": True,
                   "detail": "C2 beacon established from db-prod-01 to 185.220.101.47"},
                  inject_skew),
    ]


def _benign_logs(count=350, inject_skew=True):
    """Generate benign background enterprise noise logs."""
    logs = []
    benign_actions = [
        ("AUTH_SUCCESS", "LDAP",     389, "T1078", "Routine LDAP authentication",      "LOW"),
        ("DNS_QUERY",    "DNS",       53, "",      "Routine DNS resolution",           "LOW"),
        ("PROC_START",   "HOST",       0, "",      "Background service process start", "LOW"),
        ("NET_FLOW",     "TCP",      443, "",      "Internal HTTPS flow",              "LOW"),
        ("FILE_READ",    "SMB",      445, "",      "Routine file share read",          "LOW"),
        ("KERBEROS_TGT", "Kerberos",  88, "T1558", "Kerberos TGT ticket refresh",      "LOW"),
        ("SVC_HEARTBEAT","TCP",     8080, "",      "Service health check probe",       "LOW"),
        ("MAIL_RECV",    "SMTP",      25, "",      "Inbound SMTP email transport",     "LOW"),
        ("BACKUP_JOB",   "TCP",     9000, "",      "Daily backup synchronization",     "LOW"),
        ("LOGOFF",       "HOST",       0, "",      "User session termination",         "LOW"),
    ]
    for i in range(count):
        action, proto, port, mitre, detail, sev = random.choice(benign_actions)
        user   = random.choice(INTERNAL_USERS)
        src_h  = random.choice(INTERNAL_HOSTS)
        dst_h  = random.choice(INTERNAL_HOSTS + INT_IPS)
        mins   = random.uniform(0, 60)
        lid    = f"LOG-{i+1:04d}"
        skew   = HOST_SKEW.get(src_h, 0) if inject_skew else 0
        true_t = BASE_DATE + timedelta(minutes=mins)
        raw_t  = true_t + timedelta(seconds=skew)
        entity = random.choice(["USER", "DEVICE", "SERVICE"])
        src    = random.choice([user] + SERVICES)
        payload = json.dumps({"log_id": lid, "source": src, "target": dst_h,
                              "action": action, "detail": detail})
        logs.append({
            "log_id":           lid,
            "raw_timestamp":    raw_t.isoformat(),
            "true_timestamp":   true_t.isoformat(),
            "source_host":      src_h,
            "host_skew_sec":    skew,
            "entity_type":      entity,
            "source":           src,
            "target":           dst_h,
            "action":           action,
            "protocol":         proto,
            "port":             port,
            "mitre_tag":        mitre,
            "mitre_technique":  detail,
            "severity":         sev,
            "is_malicious":     False,
            "raw_payload":      payload,
        })
    return logs


def generate_logs(shuffle=True, inject_skew=True, drop_telemetry=False, drop_rate=0.15):
    """
    Generate full enterprise log dataset with embedded APT kill chain.
    Returns list of log dicts.
    """
    apt = _apt_kill_chain(inject_skew=inject_skew)
    benign = _benign_logs(count=350, inject_skew=inject_skew)

    if drop_telemetry:
        # Intentionally drop LOG-APT-003 (privilege escalation) to create a telemetry gap
        apt = [l for l in apt if l["log_id"] != "LOG-APT-003"]
        # Drop ~15% of benign logs randomly to simulate fragmentation
        benign = [l for l in benign if random.random() > drop_rate]

    all_logs = apt + benign

    if shuffle:
        random.shuffle(all_logs)
    else:
        all_logs.sort(key=lambda x: x["raw_timestamp"])

    return all_logs


if __name__ == "__main__":
    logs = generate_logs(shuffle=True, inject_skew=True, drop_telemetry=False)
    print(f"Generated {len(logs)} logs ({sum(1 for l in logs if l['is_malicious'])} malicious)")
    sample = [l for l in logs if l['is_malicious']]
    for s in sample:
        print(f"  {s['log_id']} | {s['raw_timestamp']} | {s['action']} | {s['mitre_tag']}")
