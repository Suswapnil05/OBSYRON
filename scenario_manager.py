"""
OBSYRON – Incident Scenario & Threat Library Manager
Manages 7 predefined safe cybersecurity simulation scenarios,
Atomic Red Team test telemetry, Windows Sysmon and Linux audit logs,
and downloadable lab test kits for isolated hypervisors/VMs.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timezone, timedelta
import json
import os

from log_generator import generate_logs

IST = timezone(timedelta(hours=5, minutes=30))

SCENARIO_CATALOG = {
    "powershell_exec": {
        "id": "powershell_exec",
        "title": "1. Suspicious PowerShell Execution",
        "threat_actor": "Atomic Red Team (T1059.001 Test Harness)",
        "complexity": "MEDIUM",
        "category": "Execution",
        "mitre_technique_id": "T1059.001",
        "mitre_technique_name": "Command and Scripting Interpreter: PowerShell",
        "mitre_tactic": "Execution",
        "description": "Simulates adversary executing base64 encoded download cradle (powershell -enc) with -ExecutionPolicy Bypass to fetch stage-2 payload into memory.",
        "mitre_techniques": ["T1059.001", "T1027", "T1105"],
        "target_assets": ["wkst-04-dev", "powershell.exe"],
        "telemetry_source": "Windows Sysmon Event ID 1 (Process Creation)",
        "telemetry_count": 185,
        "provenance": "CONTROLLED_SIMULATION"
    },
    "failed_auth_spray": {
        "id": "failed_auth_spray",
        "title": "2. Failed Authentication & Password Spray",
        "threat_actor": "External Ingress (Bulletproof ASN51167 / 45.33.32.156)",
        "complexity": "LOW",
        "category": "Credential Access",
        "mitre_technique_id": "T1110.003",
        "mitre_technique_name": "Brute Force: Password Spraying",
        "mitre_tactic": "Credential Access",
        "description": "Simulates low-and-slow authentication spray targeting corporate SSH bastion and VPN gateway across 50 enterprise usernames.",
        "mitre_techniques": ["T1110.001", "T1110.003", "T1078"],
        "target_assets": ["bastion-ssh-01", "vpn.obsyron.corp"],
        "telemetry_source": "Linux /var/log/auth.log & OpenCanary SSH Honeypot",
        "telemetry_count": 142,
        "provenance": "CONTROLLED_SIMULATION"
    },
    "process_masquerade": {
        "id": "process_masquerade",
        "title": "3. Suspicious Process Creation & Masquerading",
        "threat_actor": "Defense Evasion Payload (svchost.exe spoof)",
        "complexity": "MEDIUM",
        "category": "Defense Evasion",
        "mitre_technique_id": "T1036.005",
        "mitre_technique_name": "Masquerading: Match Legitimate Name or Location",
        "mitre_tactic": "Defense Evasion",
        "description": "Adversary launches binary named 'svchost.exe' or 'taskhost.exe' from unusual directory path (C:\\Users\\Public or /tmp) with parent process cmd.exe.",
        "mitre_techniques": ["T1036", "T1036.005", "T1059"],
        "target_assets": ["wkst-09-fin", "svchost.exe"],
        "telemetry_source": "Windows Sysmon Event ID 1 & Event ID 7",
        "telemetry_count": 210,
        "provenance": "CONTROLLED_SIMULATION"
    },
    "credential_access": {
        "id": "credential_access",
        "title": "4. Credential Access & Kerberoasting Simulation",
        "threat_actor": "Internal Threat / Kerberoasting Actor",
        "complexity": "HIGH",
        "category": "Credential Access",
        "mitre_technique_id": "T1558.003",
        "mitre_technique_name": "Steal or Forge Kerberos Tickets: Kerberoasting",
        "mitre_tactic": "Credential Access",
        "description": "Requests Kerberos Ticket Granting Service (TGS) tickets for Service Principal Names (SPNs) with RC4 encryption downgrade to crack offline.",
        "mitre_techniques": ["T1558.003", "T1003.001", "T1078.002"],
        "target_assets": ["CORP-DC-01", "svc_sql_admin", "wkst-12-qa"],
        "telemetry_source": "Windows Security Event 4769 & Sysmon Event ID 10",
        "telemetry_count": 194,
        "provenance": "CONTROLLED_SIMULATION"
    },
    "lateral_movement": {
        "id": "lateral_movement",
        "title": "5. Lateral Movement Simulation (RDP & SMB Admin Share)",
        "threat_actor": "Compromised Service Token (svc_ci_deploy)",
        "complexity": "HIGH",
        "category": "Lateral Movement",
        "mitre_technique_id": "T1021.002",
        "mitre_technique_name": "Remote Services: SMB/Windows Admin Shares",
        "mitre_tactic": "Lateral Movement",
        "description": "Pivoting across internal workstation VLAN using interactive Remote Desktop (RDP) and administrative C$ network share mounting to production SQL cluster.",
        "mitre_techniques": ["T1021.001", "T1021.002", "T1078"],
        "target_assets": ["wkst-04-dev", "svc_ci_deploy", "db-prod-01"],
        "telemetry_source": "Windows Security Event 4624 (Logon Type 10) & Sysmon Event 3",
        "telemetry_count": 275,
        "provenance": "CONTROLLED_SIMULATION"
    },
    "c2_network_beacon": {
        "id": "c2_network_beacon",
        "title": "6. Suspicious Network Connection & C2 Beaconing",
        "threat_actor": "Cobalt Strike / Sliver C2 Beacon (84.17.42.19)",
        "complexity": "MEDIUM",
        "category": "Command and Control",
        "mitre_technique_id": "T1071.001",
        "mitre_technique_name": "Application Layer Protocol: Web Protocols",
        "mitre_tactic": "Command and Control",
        "description": "Persistent, periodic outbound TCP connections with jitter established to external unclassified IP address on HTTPS port 8443.",
        "mitre_techniques": ["T1071.001", "T1573.002", "T1046"],
        "target_assets": ["wkst-04-dev", "198.51.100.23"],
        "telemetry_source": "Palo Alto NetFlow Logs & Sysmon Event ID 3",
        "telemetry_count": 220,
        "provenance": "CONTROLLED_SIMULATION"
    },
    "data_exfil": {
        "id": "data_exfil",
        "title": "7. Simulated Data Exfiltration Over Alternative Protocol",
        "threat_actor": "External Drop Server (198.51.100.23)",
        "complexity": "CRITICAL",
        "category": "Exfiltration",
        "mitre_technique_id": "T1048",
        "mitre_technique_name": "Exfiltration Over Alternative Protocol",
        "mitre_tactic": "Exfiltration",
        "description": "Database archive dump compressed into password-protected archive and transmitted outbound via encrypted TLS tunnel to cloud drop server.",
        "mitre_techniques": ["T1048", "T1560.001", "T1020"],
        "target_assets": ["db-prod-01", "198.51.100.23"],
        "telemetry_source": "Perimeter Firewall NetFlow & Database Audit Logs",
        "telemetry_count": 357,
        "provenance": "CONTROLLED_SIMULATION"
    },
    "apt29_stealth_exfil": {
        "id": "apt29_stealth_exfil",
        "title": "APT29 Stealth Ingress & Exfiltration (Full Multi-Stage Attack)",
        "threat_actor": "APT29 / Cozy Bear (TOR Relay 185.220.101.47)",
        "complexity": "CRITICAL",
        "category": "Targeted Cyber Espionage",
        "mitre_technique_id": "T1078",
        "mitre_technique_name": "Valid Accounts: Initial Ingress",
        "mitre_tactic": "Initial Access",
        "description": "Full end-to-end multi-stage cyber intrusion: TOR ingress -> developer host hijack -> PowerShell execution -> privilege escalation bridge -> SMB lateral move -> production database exfiltration.",
        "mitre_techniques": ["T1078", "T1087", "T1558", "T1021", "T1048"],
        "target_assets": ["wkst-04-dev", "svc_ci_deploy", "db-prod-01", "198.51.100.23"],
        "telemetry_source": "Integrated Enterprise SIEM & Sysmon Cluster",
        "telemetry_count": 357,
        "provenance": "CONTROLLED_SIMULATION"
    }
}


def list_available_scenarios() -> List[Dict[str, Any]]:
    """Returns catalog of all registered cybersecurity investigation scenarios."""
    return list(SCENARIO_CATALOG.values())


def get_scenario_metadata(scenario_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves metadata for a specific scenario."""
    return SCENARIO_CATALOG.get(scenario_id)


def generate_lab_test_script(scenario_id: str, platform: str = "windows") -> str:
    """
    Generates safe, non-destructive Atomic Red Team simulation commands
    for execution in authorized, isolated lab hypervisors/VMs.
    """
    scen = SCENARIO_CATALOG.get(scenario_id, SCENARIO_CATALOG["powershell_exec"])
    now_str = datetime.now(timezone.utc).isoformat()

    if platform.lower() in ["powershell", "windows", "win", "ps1"]:
        return f"""<#
.SYNOPSIS
    OBSYRON Lab Test Kit — Safe Controlled Atomic Red Team Simulation
.DESCRIPTION
    Scenario: {scen['title']}
    MITRE ATT&CK: {scen.get('mitre_technique_id')} - {scen.get('mitre_technique_name')}
    Generated: {now_str}
    Notice: Safe simulation test harness for isolated research environments.
#>

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " [OBSYRON SIMULATION LAB] Executing Safe Test Harness" -ForegroundColor Green
Write-Host " Scenario: {scen['title']}" -ForegroundColor Yellow
Write-Host " Technique: {scen.get('mitre_technique_id')} ({scen.get('mitre_tactic')})" -ForegroundColor Yellow
Write-Host " Target Asset: {scen.get('target_assets', ['localhost'])[0]}" -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Create localized mock test directory in isolated user sandbox
$labDir = "$env:TEMP\\obsyron_simulation_lab"
if (!(Test-Path $labDir)) {{ New-Item -ItemType Directory -Path $labDir -Force | Out-Null }}
Set-Location $labDir

# 2. Execute safe test simulation corresponding to {scenario_id}
try {{
    Write-Host "[*] Emulating telemetry generation for {scen.get('mitre_technique_id')}..." -ForegroundColor White
    $mockPayload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("Write-Output 'OBSYRON Controlled Test Token - T1059.001'"))
    
    # Non-destructive benign execution
    $simResult = [PSCustomObject]@{{
        TestId = "ART-{scen.get('mitre_technique_id')}"
        Scenario = "{scen['id']}"
        Timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
        Hostname = $env:COMPUTERNAME
        User = $env:USERNAME
        Technique = "{scen.get('mitre_technique_id')}"
        Status = "SIMULATION_CAPTURED"
    }}

    $outJson = "$labDir\\telemetry_export.json"
    $simResult | ConvertTo-Json | Out-File -FilePath $outJson -Encoding UTF8
    Write-Host "[+] Controlled simulation executed successfully!" -ForegroundColor Green
    Write-Host "[+] Safe telemetry artifact exported to: $outJson" -ForegroundColor Cyan
    Write-Host "[*] You can upload this file into OBSYRON Simulation Lab." -ForegroundColor White
}} catch {{
    Write-Warning "Simulation execution notice: $_"
}}
"""
    else:
        # Bash / Linux script
        return f"""#!/usr/bin/env bash
# ==========================================================
# OBSYRON Lab Test Kit — Safe Controlled Simulation (Linux)
# Scenario: {scen['title']}
# MITRE ATT&CK: {scen.get('mitre_technique_id')} - {scen.get('mitre_technique_name')}
# Generated: {now_str}
# Notice: Safe simulation test harness for isolated research environments.
# ==========================================================

set -e
echo "=========================================================="
echo " [OBSYRON SIMULATION LAB] Running Safe Test Harness"
echo " Scenario: {scen['title']}"
echo " Technique: {scen.get('mitre_technique_id')} ({scen.get('mitre_tactic')})"
echo "=========================================================="

LAB_DIR="/tmp/obsyron_simulation_lab"
mkdir -p "$LAB_DIR"
OUT_JSON="$LAB_DIR/telemetry_export.json"

cat <<EOF > "$OUT_JSON"
{{
  "test_id": "ART-{scen.get('mitre_technique_id')}",
  "scenario": "{scen['id']}",
  "timestamp": "$(date -u +'%Y-%m-%dT%H:%M:%SZ')",
  "hostname": "$(hostname)",
  "user": "$(whoami)",
  "technique": "{scen.get('mitre_technique_id')}",
  "status": "SIMULATION_CAPTURED"
}}
EOF

echo "[+] Controlled test completed."
echo "[+] Telemetry saved to $OUT_JSON"
echo "[*] Ready for upload into OBSYRON Simulation Lab."
"""


def load_scenario_telemetry(scenario_id: str) -> List[Dict[str, Any]]:
    """
    Generates rich, realistic log telemetry corresponding to the selected scenario,
    including authentic Sysmon Event IDs, Linux auth.log strings, and network packets.
    """
    base_logs = generate_logs(shuffle=True, inject_skew=True, drop_telemetry=False)
    now_dt = datetime.now(IST)

    if scenario_id == "powershell_exec":
        ps_logs = [
            {
                "log_id": "SIM-PS-001",
                "raw_timestamp": (now_dt - timedelta(minutes=4, seconds=12)).isoformat(),
                "normalized_timestamp": (now_dt - timedelta(minutes=4)).isoformat(),
                "source_host": "wkst-04-dev",
                "host_skew_sec": 12,
                "skew_corrected_sec": -12,
                "entity_type": "PROCESS",
                "source": "explorer.exe",
                "target": "powershell.exe",
                "action": "PROC_CREATE",
                "protocol": "LOCAL_EXEC",
                "port": 0,
                "mitre_tag": "T1059.001",
                "mitre_technique": "Command and Scripting Interpreter: PowerShell",
                "severity": "CRITICAL",
                "is_malicious": True,
                "raw_payload": '{"EventID":1,"Image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","CommandLine":"powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIA...","ParentImage":"C:\\\\Windows\\\\explorer.exe","User":"emp_rohan"}',
                "causal_connection": "Sysmon Event ID 1: Encoded PowerShell process spawned with execution policy bypass flags.",
                "supporting_evidence": ["Base64 encoded payload", "-ExecutionPolicy Bypass specified", "Parent process explorer.exe"],
                "contradictory_evidence": []
            },
            {
                "log_id": "SIM-PS-002",
                "raw_timestamp": (now_dt - timedelta(minutes=3, seconds=45)).isoformat(),
                "normalized_timestamp": (now_dt - timedelta(minutes=3, seconds=30)).isoformat(),
                "source_host": "wkst-04-dev",
                "host_skew_sec": 15,
                "skew_corrected_sec": -15,
                "entity_type": "DEVICE",
                "source": "powershell.exe",
                "target": "185.220.101.47",
                "action": "NET_CONNECT",
                "protocol": "TCP",
                "port": 4444,
                "mitre_tag": "T1071",
                "mitre_technique": "Application Layer Protocol: C2 Ingress",
                "severity": "CRITICAL",
                "is_malicious": True,
                "raw_payload": '{"EventID":3,"Image":"powershell.exe","SourceIp":"10.0.4.15","DestinationIp":"185.220.101.47","DestinationPort":4444}',
                "causal_connection": "Sysmon Event ID 3: PowerShell established outbound socket to TOR relay 185.220.101.47:4444.",
                "supporting_evidence": ["Direct outbound socket to known adversary IP", "Non-standard port 4444"],
                "contradictory_evidence": []
            }
        ]
        return ps_logs + base_logs[:180]

    elif scenario_id == "failed_auth_spray":
        spray_logs = [
            {
                "log_id": f"SIM-SPRAY-{i:03d}",
                "raw_timestamp": (now_dt - timedelta(minutes=6, seconds=i*8)).isoformat(),
                "normalized_timestamp": (now_dt - timedelta(minutes=6, seconds=i*8)).isoformat(),
                "source_host": "bastion-ssh-01",
                "host_skew_sec": 0,
                "skew_corrected_sec": 0,
                "entity_type": "AUTH_ENDPOINT",
                "source": "45.33.32.156",
                "target": "bastion-ssh-01",
                "action": "SSH_FAILED_AUTH",
                "protocol": "SSH",
                "port": 22,
                "mitre_tag": "T1110.003",
                "mitre_technique": "Brute Force: Password Spraying",
                "severity": "HIGH",
                "is_malicious": True,
                "raw_payload": f'{{"raw_line":"Failed password for invalid user account_{i} from 45.33.32.156 port {44000+i} ssh2"}}',
                "causal_connection": f"Linux auth.log: Consecutive authentication failure for dictionary account_{i}.",
                "supporting_evidence": ["Distributed attempt from bulletproof hosting ASN", "Rapid account rotation"],
                "contradictory_evidence": []
            }
            for i in range(1, 6)
        ]
        return spray_logs + base_logs[:140]

    elif scenario_id == "process_masquerade":
        masq_logs = [
            {
                "log_id": "SIM-MASQ-001",
                "raw_timestamp": (now_dt - timedelta(minutes=5)).isoformat(),
                "normalized_timestamp": (now_dt - timedelta(minutes=5)).isoformat(),
                "source_host": "wkst-09-fin",
                "host_skew_sec": 0,
                "skew_corrected_sec": 0,
                "entity_type": "PROCESS",
                "source": "cmd.exe",
                "target": "svchost.exe",
                "action": "MASQUERADE_EXEC",
                "protocol": "LOCAL_EXEC",
                "port": 0,
                "mitre_tag": "T1036.005",
                "mitre_technique": "Masquerading: Match Legitimate Name or Location",
                "severity": "CRITICAL",
                "is_malicious": True,
                "raw_payload": '{"EventID":1,"Image":"C:\\\\Users\\\\Public\\\\svchost.exe","CommandLine":"C:\\\\Users\\\\Public\\\\svchost.exe -daemon","ParentImage":"C:\\\\Windows\\\\System32\\\\cmd.exe"}',
                "causal_connection": "Sysmon Event ID 1: Bogus svchost.exe launched from C:\\Users\\Public instead of System32.",
                "supporting_evidence": ["Abnormal path C:\\Users\\Public", "Parent cmd.exe instead of services.exe"],
                "contradictory_evidence": []
            }
        ]
        return masq_logs + base_logs[:200]

    elif scenario_id == "credential_access":
        krb_logs = [
            {
                "log_id": "SIM-KRB-001",
                "raw_timestamp": (now_dt - timedelta(minutes=7, seconds=20)).isoformat(),
                "normalized_timestamp": (now_dt - timedelta(minutes=7)).isoformat(),
                "source_host": "CORP-DC-01",
                "host_skew_sec": 20,
                "skew_corrected_sec": -20,
                "entity_type": "SERVICE",
                "source": "wkst-12-qa",
                "target": "svc_sql_admin",
                "action": "KERBEROS_TGS_REQ",
                "protocol": "KERBEROS",
                "port": 88,
                "mitre_tag": "T1558.003",
                "mitre_technique": "Steal or Forge Kerberos Tickets: Kerberoasting",
                "severity": "CRITICAL",
                "is_malicious": True,
                "raw_payload": '{"EventID":4769,"TargetUserName":"svc_sql_admin","ServiceName":"MSSQLSvc/db-prod-01:1433","TicketEncryptionType":"0x17 (RC4-HMAC)","ClientAddress":"::ffff:192.168.10.84"}',
                "causal_connection": "Security Event 4769: Kerberos TGS-REQ requested with weak RC4 downgrade cipher.",
                "supporting_evidence": ["RC4 encryption downgrade requested", "High-privilege database service principal target"],
                "contradictory_evidence": []
            }
        ]
        return krb_logs + base_logs[:190]

    elif scenario_id == "lateral_movement":
        lat_logs = [
            {
                "log_id": "SIM-LAT-001",
                "raw_timestamp": (now_dt - timedelta(minutes=4)).isoformat(),
                "normalized_timestamp": (now_dt - timedelta(minutes=4)).isoformat(),
                "source_host": "wkst-04-dev",
                "host_skew_sec": 0,
                "skew_corrected_sec": 0,
                "entity_type": "DEVICE",
                "source": "svc_ci_deploy",
                "target": "db-prod-01",
                "action": "SMB_LATERAL_MOVE",
                "protocol": "SMB",
                "port": 445,
                "mitre_tag": "T1021.002",
                "mitre_technique": "Remote Services: SMB/Windows Admin Shares",
                "severity": "HIGH",
                "is_malicious": True,
                "raw_payload": '{"EventID":5140,"ShareName":"\\\\\\\\db-prod-01\\\\C$","SubjectUserName":"svc_ci_deploy","AccessMask":"0x1"}',
                "causal_connection": "Windows Security Event 5140: Administrative C$ network share accessed across subnets.",
                "supporting_evidence": ["Administrative C$ share mounted", "Service token used interactively outside CI pipeline"],
                "contradictory_evidence": []
            }
        ]
        return lat_logs + base_logs[:270]

    elif scenario_id == "c2_network_beacon":
        c2_logs = [
            {
                "log_id": "SIM-C2-001",
                "raw_timestamp": (now_dt - timedelta(minutes=2)).isoformat(),
                "normalized_timestamp": (now_dt - timedelta(minutes=2)).isoformat(),
                "source_host": "wkst-04-dev",
                "host_skew_sec": 0,
                "skew_corrected_sec": 0,
                "entity_type": "DEVICE",
                "source": "wkst-04-dev",
                "target": "198.51.100.23",
                "action": "C2_BEACON",
                "protocol": "HTTPS",
                "port": 8443,
                "mitre_tag": "T1071.001",
                "mitre_technique": "Application Layer Protocol: Web Protocols",
                "severity": "CRITICAL",
                "is_malicious": True,
                "raw_payload": '{"EventID":3,"DestinationIp":"198.51.100.23","DestinationPort":8443,"BeaconIntervalSec":30,"Jitter":0.15}',
                "causal_connection": "Firewall NetFlow: Persistent HTTPS beaconing on port 8443 matching Cobalt Strike profile.",
                "supporting_evidence": ["Periodic 30s jittered beacons", "Untrusted drop server IP"],
                "contradictory_evidence": []
            }
        ]
        return c2_logs + base_logs[:215]

    elif scenario_id == "data_exfil":
        exfil_logs = [
            {
                "log_id": "SIM-EXFIL-001",
                "raw_timestamp": (now_dt - timedelta(minutes=1)).isoformat(),
                "normalized_timestamp": (now_dt - timedelta(minutes=1)).isoformat(),
                "source_host": "db-prod-01",
                "host_skew_sec": 0,
                "skew_corrected_sec": 0,
                "entity_type": "DEVICE",
                "source": "db-prod-01",
                "target": "198.51.100.23",
                "action": "C2_EXFILTRATION",
                "protocol": "HTTPS",
                "port": 443,
                "mitre_tag": "T1048",
                "mitre_technique": "Exfiltration Over Alternative Protocol",
                "severity": "CRITICAL",
                "is_malicious": True,
                "raw_payload": '{"bytes_sent":88291040,"bytes_received":1024,"duration_sec":42.5,"archive":"production_dump.enc"}',
                "causal_connection": "NetFlow NetRecord: High-volume egress (84.2 MB) transmitted from database server to external drop IP.",
                "supporting_evidence": ["84.2 MB volume anomaly", "Direct outbound connection from restricted database subnet"],
                "contradictory_evidence": []
            }
        ]
        return exfil_logs + base_logs[:350]

    # Default full APT29 multi-stage kill chain
    return base_logs
