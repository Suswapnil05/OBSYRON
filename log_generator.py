"""
OBSYRON – Log Generator
Generates synthetic enterprise logs with embedded multi-entity APT kill chain
including Users, Hosts, Processes, Services, and External Endpoints.
"""
import random, json, hashlib
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

INTERNAL_USERS     = ["emp_alice", "emp_bob", "emp_carol", "emp_dave", "emp_eve", "emp_rohan"]
INTERNAL_HOSTS     = ["wkst-04-dev", "dc-01", "app-srv-02", "db-prod-01", "mail-srv-03", "wkst-07-fin"]
INTERNAL_PROCESSES = ["powershell.exe", "cmd.exe", "svchost.exe", "rundll32.exe", "taskmgr.exe", "lsass.exe"]
SERVICES           = ["svc_ci_deploy", "svc_ldap", "svc_backup", "svc_monitor", "svc_mail"]
INT_IPS            = ["10.0.1.10", "10.0.1.11", "10.0.2.5", "10.0.2.6", "10.0.1.20"]


def _make_log(log_id, minutes_offset, source_host, entity_type,
              source, target, action, protocol, port, mitre_tag,
              mitre_technique, severity, raw_payload_extra,
              inject_skew=True, delay_sec=1.2,
              causal_connection="", supporting_evidence=None, contradictory_evidence=None):
    skew = HOST_SKEW.get(source_host, 0) if inject_skew else 0
    true_time = BASE_DATE + timedelta(minutes=minutes_offset)
    raw_time  = true_time + timedelta(seconds=skew)
    ingest_time = raw_time + timedelta(seconds=delay_sec)

    payload = {
        "log_id": log_id,
        "source_host": source_host,
        "source": source,
        "target": target,
        "action": action,
        "protocol": protocol,
        "port": port,
        **raw_payload_extra
    }
    
    canonical_items = [
        str(log_id),
        str(source_host),
        str(source),
        str(target),
        str(action),
        str(protocol),
        str(port),
        true_time.isoformat(),
        str(mitre_tag),
        json.dumps(payload, sort_keys=True)
    ]
    sha256_hash = hashlib.sha256("|".join(canonical_items).encode("utf-8")).hexdigest()

    return {
        "log_id":                log_id,
        "event_timestamp":       true_time.isoformat(),
        "ingestion_timestamp":   ingest_time.isoformat(),
        "raw_timestamp":         raw_time.isoformat(),
        "true_timestamp":        true_time.isoformat(),
        "source_host":           source_host,
        "host_skew_sec":         skew,
        "delay_sec":             delay_sec,
        "is_late_arriving":      delay_sec > 15.0,
        "is_duplicate":          False,
        "entity_type":           entity_type,
        "source":                source,
        "target":                target,
        "action":                action,
        "protocol":              protocol,
        "port":                  port,
        "mitre_tag":             mitre_tag,
        "mitre_technique":       mitre_technique,
        "severity":              severity,
        "is_malicious":          log_id.startswith("LOG-APT") or log_id.startswith("LOG-CHAOS-0"),
        "raw_payload":           json.dumps(payload),
        "sha256_hash":           sha256_hash,
        "causal_connection":     causal_connection,
        "supporting_evidence":   supporting_evidence or [],
        "contradictory_evidence": contradictory_evidence or []
    }


def _apt_kill_chain(inject_skew=True):
    """The 7-step stealth APT kill chain logs with Process execution modeling."""
    return [
        _make_log("LOG-APT-001", 15.0, "wkst-04-dev", "USER",
                  "185.220.101.47", "emp_rohan", "AUTH_ANOMALY",
                  "HTTPS", 443, "T1078", "T1078 - Valid Accounts (Initial Access)",
                  "CRITICAL",
                  {"detail": "Off-hours authenticated ingress from confirmed Tor exit node 185.220.101.47 into employee account emp_rohan",
                   "geo": "TOR exit relay", "auth_method": "Pass-the-Hash / SSO Session"},
                  inject_skew=inject_skew, delay_sec=1.5,
                  causal_connection="Adversary establishes Initial Access by authenticating to employee identity 'emp_rohan' on developer workstation.",
                  supporting_evidence=[
                      "IP 185.220.101.47 matches known Tor exit node threat intel feed",
                      "Authentication timestamp 01:15 IST occurs outside employee standard working hours (09:00 - 18:00)",
                      "Origin geo-IP country mismatch with employee standard registration location"
                  ],
                  contradictory_evidence=[
                      "Valid credentials provided without prior failed logon lockouts",
                      "Single-factor legacy authentication permitted without active push MFA challenge"
                  ]),

        _make_log("LOG-APT-002", 15.6, "wkst-04-dev", "PROCESS",
                  "emp_rohan", "powershell.exe", "PROC_SPAWN",
                  "LOCAL", 0, "T1059.001", "T1059.001 - Command and Scripting Interpreter: PowerShell",
                  "HIGH",
                  {"command_line": "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgA...",
                   "parent_process": "explorer.exe", "pid": 4812},
                  inject_skew=inject_skew, delay_sec=2.0,
                  causal_connection="Adversary executes obfuscated PowerShell interpreter under the compromised user context to bootstrap reconnaissance.",
                  supporting_evidence=[
                      "Encoded base64 payload execution flags (-NoP -NonI -W Hidden -Enc)",
                      "Parent-child relationship: spawned under explorer.exe session of emp_rohan",
                      "Memory inspection detects AMSI buffer bypass patch in process memory"
                  ],
                  contradictory_evidence=[
                      "Process signed by Microsoft Corporation (valid digital catalog signature)",
                      "PowerShell is standard administrative software on developer workstations"
                  ]),

        _make_log("LOG-APT-003", 16.0, "wkst-04-dev", "USER",
                  "powershell.exe", "dc-01", "RECON_ENUM",
                  "LDAP", 389, "T1087", "T1087 - Account Discovery (Reconnaissance)",
                  "HIGH",
                  {"command": "net user /domain", "stdout_lines": 42,
                   "detail": "Domain user enumeration against Active Directory over LDAP port 389"},
                  inject_skew=inject_skew, delay_sec=2.2,
                  causal_connection="Compromised PowerShell process executes Active Directory enumeration against Domain Controller to locate service accounts.",
                  supporting_evidence=[
                      "LDAP query volume spikes to 42 account enumerations in under 800ms",
                      "Target dc-01 confirms query originated from workstation wkst-04-dev",
                      "User account search filters explicitly for 'adminCount=1' and servicePrincipalNames"
                  ],
                  contradictory_evidence=[
                      "LDAP bind completed using authenticated domain user credentials",
                      "Standard domain discovery command without exploit payload injected into LDAP parser"
                  ]),

        _make_log("LOG-APT-004", 18.0, "wkst-04-dev", "SERVICE",
                  "wkst-04-dev", "svc_ci_deploy", "PRIV_ESC",
                  "RPC", 135, "T1558", "T1558 - Steal or Forge Kerberos Tickets (Privilege Escalation)",
                  "CRITICAL",
                  {"privilege": "SeDebugPrivilege", "granted_by": "emp_rohan",
                   "detail": "Service account svc_ci_deploy silently assigned SeDebugPrivilege to enable LSASS memory dump"},
                  inject_skew=inject_skew, delay_sec=3.0,
                  causal_connection="Adversary escalates privileges on workstation wkst-04-dev by assigning SeDebugPrivilege to CI/CD service account.",
                  supporting_evidence=[
                      "SeDebugPrivilege granted to service account outside CI/CD deployment maintenance window",
                      "Security audit log event ID 4672 (Special privileges assigned to new logon)",
                      "LSASS process memory opened with PROCESS_VM_READ permissions immediately following grant"
                  ],
                  contradictory_evidence=[
                      "Service account svc_ci_deploy is legitimately used by automated Jenkins builds",
                      "No antivirus file detection triggered during in-memory token duplication"
                  ]),

        _make_log("LOG-APT-005", 20.0, "db-prod-01", "SERVICE",
                  "svc_ci_deploy", "db-prod-01", "LATERAL_MOVE",
                  "SMB", 445, "T1021", "T1021 - Remote Services (SMB ADMIN$)",
                  "CRITICAL",
                  {"auth_type": "NTLM", "share": "ADMIN$",
                   "detail": "svc_ci_deploy authenticates laterally to production database db-prod-01 via SMB ADMIN$"},
                  inject_skew=inject_skew, delay_sec=4.0,
                  causal_connection="Adversary leverages stolen service account credentials to pivot laterally onto tier-1 production database host.",
                  supporting_evidence=[
                      "Inbound SMB port 445 session from developer workstation to database cluster",
                      "IPC$ and ADMIN$ network shares mounted using NTLMv2 hash authentication",
                      "Host db-prod-01 event log 4624 records network logon (Type 3) from wkst-04-dev"
                  ],
                  contradictory_evidence=[
                      "svc_ci_deploy is in Database Readers Active Directory security group",
                      "Communication over standard enterprise SMB file sharing port"
                  ]),

        _make_log("LOG-APT-006", 22.0, "db-prod-01", "DEVICE",
                  "db-prod-01", "185.220.101.47", "DATA_EXFIL",
                  "TCP", 4444, "T1048", "T1048 - Exfiltration Over Alternative Protocol",
                  "CRITICAL",
                  {"bytes_sent": 2457600, "dst_port": 4444,
                   "detail": "db-prod-01 opens outbound TCP flow on port 4444 exfiltrating 2.45 MB of production telemetry"},
                  inject_skew=inject_skew, delay_sec=45.0, # Late arrival telemetry!
                  causal_connection="Compromised production database opens non-standard outbound egress channel, transferring bulk database archive to adversary.",
                  supporting_evidence=[
                      "Outbound flow destination IP 185.220.101.47 matches Patient Zero ingress relay",
                      "Non-standard TCP port 4444 (Metasploit default listener port)",
                      "Exfiltration volume of 2.45 MB matches compressed customer table export"
                  ],
                  contradictory_evidence=[
                      "Outbound firewall rule permitted established connections without egress inspection",
                      "Encrypted data stream prevented deep packet payload keyword identification"
                  ]),

        _make_log("LOG-APT-007", 23.0, "ext-185.220.101.47", "AUTH_ENDPOINT",
                  "185.220.101.47", "db-prod-01", "C2_CALLBACK",
                  "TCP", 4444, "T1048", "T1048 - Command and Control Beaconing",
                  "CRITICAL",
                  {"beacon_interval_sec": 30, "encrypted": True,
                   "detail": "Encrypted C2 heartbeat beacon established between db-prod-01 and 185.220.101.47"},
                  inject_skew=inject_skew, delay_sec=2.0,
                  causal_connection="Adversary cements persistent Command & Control beaconing from production database back to external controller.",
                  supporting_evidence=[
                      "Periodic 30-second heartbeat interval with 2% jitter characteristics",
                      "Bi-directional keepalive packets verified by core switch NetFlow",
                      "Persistent socket maintained across 12 consecutive polling cycles"
                  ],
                  contradictory_evidence=[
                      "Session terminated after containment alert dispatched",
                      "Low bandwidth footprint during idle beaconing phase (< 64 bytes per packet)"
                  ]),
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
        delay  = round(random.uniform(0.3, 4.0), 2)
        entity = random.choice(["USER", "DEVICE", "SERVICE", "PROCESS"])
        src    = random.choice([user] + SERVICES + INTERNAL_PROCESSES)
        payload = {"log_id": lid, "source": src, "target": dst_h,
                   "action": action, "detail": detail}
        
        canonical_items = [
            str(lid), str(src_h), str(src), str(dst_h), str(action),
            str(proto), str(port), true_t.isoformat(), str(mitre), json.dumps(payload, sort_keys=True)
        ]
        sha256_hash = hashlib.sha256("|".join(canonical_items).encode("utf-8")).hexdigest()

        logs.append({
            "log_id":                lid,
            "event_timestamp":       true_t.isoformat(),
            "ingestion_timestamp":   (raw_t + timedelta(seconds=delay)).isoformat(),
            "raw_timestamp":         raw_t.isoformat(),
            "true_timestamp":        true_t.isoformat(),
            "source_host":           src_h,
            "host_skew_sec":         skew,
            "delay_sec":             delay,
            "is_late_arriving":      delay > 15.0,
            "is_duplicate":          False,
            "entity_type":           entity,
            "source":                src,
            "target":                dst_h,
            "action":                action,
            "protocol":              proto,
            "port":                  port,
            "mitre_tag":             mitre,
            "mitre_technique":       detail,
            "severity":              sev,
            "is_malicious":          False,
            "raw_payload":           json.dumps(payload),
            "sha256_hash":           sha256_hash,
            "causal_connection":     f"Normal operational telemetry: {src} connected to {dst_h} via {proto}:{port}.",
            "supporting_evidence":   ["Normal baseline pattern verified", "No anomalous privilege flags detected"],
            "contradictory_evidence": ["No malicious IOC associated with host or process"]
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
        # Intentionally drop LOG-APT-004 (privilege escalation) to create a telemetry gap
        apt = [l for l in apt if l["log_id"] != "LOG-APT-004"]
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
        print(f"  {s['log_id']} | {s['entity_type']} | {s['source']} -> {s['target']} | {s['action']} | {s['sha256_hash'][:12]}...")
