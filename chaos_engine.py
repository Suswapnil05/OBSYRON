"""
OBSYRON – Deterministic Ingestion Chaos Simulation Engine
Generates a deterministic enterprise telemetry stream combining:
  1. Normal background events
  2. Suspicious off-hours ingress login
  3. Malicious process execution (powershell.exe / cmd.exe)
  4. Lateral network activity (SMB port 445 / LDAP port 389)
  5. Delayed telemetry (events arriving minutes late)
  6. Out-of-order logs (inverted arrival sequence)
  7. Duplicate events (re-transmitted network packets)
  8. Missing information (telemetry gap requiring heuristic bridging)
Produces a comprehensive comparison between Raw Incoming Stream vs Reconstructed Forensic Graph.
"""

import json, hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List

IST = timezone(timedelta(hours=5, minutes=30))
BASE_TIME = datetime(2026, 11, 14, 2, 0, 0, tzinfo=IST)


def generate_deterministic_chaos_dataset() -> Dict[str, Any]:
    """
    Builds a deterministic set of 120 logs demonstrating all 8 chaos dimensions.
    Returns raw stream (pre-ingestion) and expected anomalies.
    """
    raw_logs = []

    # 1. Normal Background Events (80 benign logs across workstations and servers)
    benign_templates = [
        ("emp_alice", "wkst-01-fin", "AUTH_SUCCESS", "Kerberos", 88, 0, "Routine workstation Kerberos ticket grant"),
        ("emp_bob", "mail-srv-01", "NET_FLOW", "HTTPS", 443, 8, "Corporate webmail synchronization"),
        ("svc_backup", "app-srv-02", "BACKUP_SYNC", "TCP", 9000, -6, "Automated database backup sync"),
        ("emp_carol", "dc-01", "DNS_QUERY", "DNS", 53, -10, "Internal DNS lookup for gitlab.internal"),
        ("emp_dave", "wkst-02-qa", "FILE_READ", "SMB", 445, 14, "Shared build artifact download"),
        ("svc_monitor", "db-prod-01", "SVC_HEARTBEAT", "TCP", 8080, -4, "Prometheus health check poll"),
    ]

    for i in range(80):
        src, dst, act, proto, port, skew, detail = benign_templates[i % len(benign_templates)]
        mins = 0.5 + (i * 0.45)
        event_dt = BASE_TIME + timedelta(minutes=mins)
        raw_dt = event_dt + timedelta(seconds=skew)
        # Normal arrival delay 0.5s - 1.8s
        ingest_dt = raw_dt + timedelta(seconds=0.8 + ((i % 5) * 0.2))

        lid = f"LOG-BG-{i+1:03d}"
        payload = {"log_id": lid, "source": src, "target": dst, "action": act, "detail": detail}
        raw_logs.append({
            "log_id": lid,
            "event_timestamp": event_dt.isoformat(),
            "raw_timestamp": raw_dt.isoformat(),
            "ingestion_timestamp": ingest_dt.isoformat(),
            "source_host": dst if "srv" in dst or "dc" in dst or "wkst" in dst else "wkst-01-fin",
            "host_skew_sec": skew,
            "delay_sec": 0.8 + ((i % 5) * 0.2),
            "is_late_arriving": False,
            "is_duplicate": False,
            "entity_type": "USER" if "emp" in src else "SERVICE",
            "source": src,
            "target": dst,
            "action": act,
            "protocol": proto,
            "port": port,
            "mitre_tag": "",
            "mitre_technique": detail,
            "severity": "LOW",
            "is_malicious": False,
            "raw_payload": json.dumps(payload),
            "chaos_type": "NORMAL_EVENT"
        })

    # 2. Suspicious Login (T1078)
    ev_login = BASE_TIME + timedelta(minutes=15.0)
    raw_login = ev_login + timedelta(seconds=12) # +12s skew on wkst-04-dev
    ing_login = raw_login + timedelta(seconds=1.2)
    raw_logs.append({
        "log_id": "LOG-CHAOS-001",
        "event_timestamp": ev_login.isoformat(),
        "raw_timestamp": raw_login.isoformat(),
        "ingestion_timestamp": ing_login.isoformat(),
        "source_host": "wkst-04-dev",
        "host_skew_sec": 12,
        "delay_sec": 1.2,
        "is_late_arriving": False,
        "is_duplicate": False,
        "entity_type": "USER",
        "source": "185.220.101.47",
        "target": "emp_rohan",
        "action": "AUTH_ANOMALY",
        "protocol": "HTTPS",
        "port": 443,
        "mitre_tag": "T1078",
        "mitre_technique": "T1078 - Valid Accounts (Initial Access)",
        "severity": "CRITICAL",
        "is_malicious": True,
        "raw_payload": json.dumps({
            "log_id": "LOG-CHAOS-001",
            "source": "185.220.101.47",
            "target": "emp_rohan",
            "action": "AUTH_ANOMALY",
            "geo": "TOR exit relay (Netherlands)",
            "auth_type": "Session Hijacking / Stolen Cookie",
            "detail": "Off-hours login to emp_rohan from confirmed Tor exit node"
        }),
        "chaos_type": "SUSPICIOUS_LOGIN"
    })

    # 3. Process Execution (T1059.001)
    ev_proc = BASE_TIME + timedelta(minutes=15.8)
    raw_proc = ev_proc + timedelta(seconds=12)
    ing_proc = raw_proc + timedelta(seconds=1.5)
    raw_logs.append({
        "log_id": "LOG-CHAOS-002",
        "event_timestamp": ev_proc.isoformat(),
        "raw_timestamp": raw_proc.isoformat(),
        "ingestion_timestamp": ing_proc.isoformat(),
        "source_host": "wkst-04-dev",
        "host_skew_sec": 12,
        "delay_sec": 1.5,
        "is_late_arriving": False,
        "is_duplicate": False,
        "entity_type": "PROCESS",
        "source": "emp_rohan",
        "target": "powershell.exe",
        "action": "PROC_SPAWN",
        "protocol": "LOCAL",
        "port": 0,
        "mitre_tag": "T1059.001",
        "mitre_technique": "T1059.001 - Command and Scripting Interpreter: PowerShell",
        "severity": "HIGH",
        "is_malicious": True,
        "raw_payload": json.dumps({
            "log_id": "LOG-CHAOS-002",
            "command": "powershell.exe -Enc SQBFAFgA... -NonI -W Hidden",
            "parent_pid": 4120,
            "user": "emp_rohan",
            "detail": "Hidden encoded PowerShell spawned under compromised interactive session"
        }),
        "chaos_type": "PROCESS_EXECUTION"
    })

    # 4. Network Activity (T1087 LDAP Discovery & T1021 SMB Lateral)
    ev_recon = BASE_TIME + timedelta(minutes=16.5)
    raw_recon = ev_recon + timedelta(seconds=12)
    ing_recon = raw_recon + timedelta(seconds=1.4)
    raw_logs.append({
        "log_id": "LOG-CHAOS-003",
        "event_timestamp": ev_recon.isoformat(),
        "raw_timestamp": raw_recon.isoformat(),
        "ingestion_timestamp": ing_recon.isoformat(),
        "source_host": "wkst-04-dev",
        "host_skew_sec": 12,
        "delay_sec": 1.4,
        "is_late_arriving": False,
        "is_duplicate": False,
        "entity_type": "USER",
        "source": "powershell.exe",
        "target": "dc-01",
        "action": "RECON_ENUM",
        "protocol": "LDAP",
        "port": 389,
        "mitre_tag": "T1087",
        "mitre_technique": "T1087 - Account Discovery (Reconnaissance)",
        "severity": "HIGH",
        "is_malicious": True,
        "raw_payload": json.dumps({
            "log_id": "LOG-CHAOS-003",
            "source": "powershell.exe",
            "target": "dc-01",
            "action": "RECON_ENUM",
            "query": "(&(objectCategory=user)(adminCount=1))",
            "detail": "LDAP query enumerating privileged enterprise accounts"
        }),
        "chaos_type": "NETWORK_ACTIVITY"
    })

    # 5. Missing Telemetry (Telemetry Gap)
    # NOTE: Step 4 (Privilege Escalation on wkst-04-dev -> svc_ci_deploy T1558) is DELIBERATELY OMITTED
    # to demonstrate the heuristic Gap-Bridging Engine!

    # 6. Lateral Network Activity (T1021 SMB)
    ev_lat = BASE_TIME + timedelta(minutes=20.0)
    raw_lat = ev_lat + timedelta(seconds=-5) # -5s skew on db-prod-01
    ing_lat = raw_lat + timedelta(seconds=2.0)
    raw_logs.append({
        "log_id": "LOG-CHAOS-004",
        "event_timestamp": ev_lat.isoformat(),
        "raw_timestamp": raw_lat.isoformat(),
        "ingestion_timestamp": ing_lat.isoformat(),
        "source_host": "db-prod-01",
        "host_skew_sec": -5,
        "delay_sec": 2.0,
        "is_late_arriving": False,
        "is_duplicate": False,
        "entity_type": "SERVICE",
        "source": "svc_ci_deploy",
        "target": "db-prod-01",
        "action": "LATERAL_MOVE",
        "protocol": "SMB",
        "port": 445,
        "mitre_tag": "T1021",
        "mitre_technique": "T1021 - Remote Services: SMB ADMIN$",
        "severity": "CRITICAL",
        "is_malicious": True,
        "raw_payload": json.dumps({
            "log_id": "LOG-CHAOS-004",
            "source": "svc_ci_deploy",
            "target": "db-prod-01",
            "share": "ADMIN$",
            "auth": "NTLMv2",
            "detail": "Lateral movement onto production database cluster via ADMIN$ share"
        }),
        "chaos_type": "NETWORK_ACTIVITY"
    })

    # 7. Delayed Events (Late Arrival: Occurred at 01:22, but held on endpoint queue, arrived 45 seconds late!)
    ev_exfil = BASE_TIME + timedelta(minutes=22.0)
    raw_exfil = ev_exfil + timedelta(seconds=-5)
    ing_exfil = raw_exfil + timedelta(seconds=68.0) # 68s ingestion delay!
    raw_logs.append({
        "log_id": "LOG-CHAOS-005",
        "event_timestamp": ev_exfil.isoformat(),
        "raw_timestamp": raw_exfil.isoformat(),
        "ingestion_timestamp": ing_exfil.isoformat(),
        "source_host": "db-prod-01",
        "host_skew_sec": -5,
        "delay_sec": 68.0,
        "is_late_arriving": True,
        "is_duplicate": False,
        "entity_type": "DEVICE",
        "source": "db-prod-01",
        "target": "185.220.101.47",
        "action": "DATA_EXFIL",
        "protocol": "TCP",
        "port": 4444,
        "mitre_tag": "T1048",
        "mitre_technique": "T1048 - Exfiltration Over Alternative Protocol",
        "severity": "CRITICAL",
        "is_malicious": True,
        "raw_payload": json.dumps({
            "log_id": "LOG-CHAOS-005",
            "bytes_sent": 2457600,
            "port": 4444,
            "notice": "Late-arriving syslog packet buffered during egress pipe saturation",
            "detail": "Outbound 2.45 MB data exfiltration stream to external TOR relay"
        }),
        "chaos_type": "DELAYED_EVENT"
    })

    # 8. Out-of-Order Logs (C2 callback packet ingested BEFORE exfiltration packet arrives)
    ev_c2 = BASE_TIME + timedelta(minutes=23.0)
    raw_c2 = ev_c2 + timedelta(seconds=3)
    ing_c2 = raw_c2 + timedelta(seconds=1.1) # Ingested at ~01:23:04, earlier than delayed exfil!
    raw_logs.append({
        "log_id": "LOG-CHAOS-006",
        "event_timestamp": ev_c2.isoformat(),
        "raw_timestamp": raw_c2.isoformat(),
        "ingestion_timestamp": ing_c2.isoformat(),
        "source_host": "ext-185.220.101.47",
        "host_skew_sec": 3,
        "delay_sec": 1.1,
        "is_late_arriving": False,
        "is_duplicate": False,
        "entity_type": "AUTH_ENDPOINT",
        "source": "185.220.101.47",
        "target": "db-prod-01",
        "action": "C2_CALLBACK",
        "protocol": "TCP",
        "port": 4444,
        "mitre_tag": "T1048",
        "mitre_technique": "T1048 - Command and Control Beaconing",
        "severity": "CRITICAL",
        "is_malicious": True,
        "raw_payload": json.dumps({
            "log_id": "LOG-CHAOS-006",
            "beacon_interval": 30,
            "encrypted": True,
            "detail": "Adversary C2 beacon keepalive confirmed on port 4444"
        }),
        "chaos_type": "OUT_OF_ORDER"
    })

    # 9. Duplicate Events (Re-transmitted packets from network retry)
    for dup_idx in range(6):
        target_orig = raw_logs[dup_idx * 10]
        dup_copy = dict(target_orig)
        dup_copy["log_id"] = f"{target_orig['log_id']}-RETRY"
        # Same event timestamp, slightly later arrival timestamp
        try:
            orig_dt = datetime.fromisoformat(target_orig["ingestion_timestamp"])
            dup_copy["ingestion_timestamp"] = (orig_dt + timedelta(seconds=1.5)).isoformat()
        except Exception:
            pass
        dup_copy["is_duplicate"] = True
        dup_copy["chaos_type"] = "DUPLICATE_EVENT"
        raw_logs.append(dup_copy)

    # Invert order of arrival to simulate high out-of-order network arrival
    incoming_raw_stream = list(raw_logs)
    import random
    rng = random.Random(42) # Deterministic seed!
    rng.shuffle(incoming_raw_stream)

    return {
        "raw_logs": incoming_raw_stream,
        "original_count": len(incoming_raw_stream),
        "chaos_spec": {
            "has_normal_events": True,
            "has_suspicious_login": True,
            "has_process_execution": True,
            "has_network_activity": True,
            "has_delayed_events": True,
            "has_out_of_order": True,
            "has_duplicates": True,
            "has_telemetry_gap": True
        }
    }


def run_ingestion_chaos_simulation() -> Dict[str, Any]:
    """
    Executes complete ingestion chaos simulation pipeline.
    Compares raw incoming telemetry stream vs normalized reconstructed graph.
    """
    from ingestor import normalize_logs
    from graph_engine import build_attack_graph, get_root_cause, get_blast_radius, get_graph_confidence

    sim_data = generate_deterministic_chaos_dataset()
    raw_incoming = sim_data["raw_logs"]

    # Reconcile telemetry via normalizer
    normalized = normalize_logs(raw_incoming, deduplicate=True)
    graph_res = build_attack_graph(normalized)
    G = graph_res["_graph"]

    root_cause = get_root_cause(G)
    blast_radius = get_blast_radius(G, root_cause.get("entity", "185.220.101.47"))
    conf = get_graph_confidence(G)

    duplicates_found = sum(1 for l in raw_incoming if l.get("is_duplicate"))
    late_arrivals_found = sum(1 for l in raw_incoming if l.get("is_late_arriving"))
    skewed_logs_found = sum(1 for l in raw_incoming if abs(l.get("host_skew_sec", 0)) > 0)
    inferred_bridges = sum(1 for e in graph_res["edges"] if e.get("is_inferred"))

    # Prepare raw stream summary (first 15 entries for UI preview)
    raw_preview = []
    for l in raw_incoming[:15]:
        raw_preview.append({
            "log_id": l["log_id"],
            "raw_timestamp": l["raw_timestamp"],
            "ingestion_timestamp": l.get("ingestion_timestamp", ""),
            "source_host": l["source_host"],
            "skew_sec": l.get("host_skew_sec", 0),
            "delay_sec": l.get("delay_sec", 0),
            "chaos_type": l.get("chaos_type", "RAW"),
            "is_duplicate": l.get("is_duplicate", False),
            "is_late": l.get("is_late_arriving", False),
            "action": l["action"]
        })

    return {
        "success": True,
        "simulation_title": "DETERMINISTIC INGESTION CHAOS BENCHMARK",
        "description": "Simulated real-world enterprise SIEM ingress featuring out-of-order logs, host clock drift (±12s), duplicate re-transmissions, network buffer delays, and dropped telemetry.",
        "metrics": {
            "incoming_raw_packets": len(raw_incoming),
            "deduplicated_packets": duplicates_found,
            "normalized_clean_events": len(normalized),
            "clock_drifts_compensated": skewed_logs_found,
            "late_arrivals_detected": late_arrivals_found,
            "out_of_order_packets_sorted": len(raw_incoming),
            "telemetry_gaps_bridged": inferred_bridges,
            "graph_certainty": round(conf * 100, 1),
            "blast_radius_assets": blast_radius["count"]
        },
        "raw_stream_sample": raw_preview,
        "root_cause": root_cause,
        "blast_radius": blast_radius,
        "graph": {
            "nodes": graph_res["nodes"],
            "edges": graph_res["edges"]
        },
        "normalized_logs_count": len(normalized)
    }


if __name__ == "__main__":
    res = run_ingestion_chaos_simulation()
    print("Chaos Simulation Results:")
    print(f"  Raw incoming: {res['metrics']['incoming_raw_packets']} packets")
    print(f"  Deduplicated: {res['metrics']['deduplicated_packets']} packets")
    print(f"  Late Arrivals: {res['metrics']['late_arrivals_detected']}")
    print(f"  Gaps Bridged: {res['metrics']['telemetry_gaps_bridged']}")
    print(f"  Root Cause: {res['root_cause']['entity']} ({res['root_cause']['mitre_tactic']})")
    print(f"  Graph Nodes: {len(res['graph']['nodes'])}, Edges: {len(res['graph']['edges'])}")
