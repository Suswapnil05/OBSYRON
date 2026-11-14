"""
OBSYRON – Incident Scenario & Threat Library Manager
Manages pre-configured enterprise cyber investigation scenarios
for training, demonstration, and automated defense validation.
"""

from typing import Dict, Any, List, Optional
from log_generator import generate_logs


SCENARIO_CATALOG = {
    "apt29_stealth_exfil": {
        "id": "apt29_stealth_exfil",
        "title": "APT29 Stealth Ingress & Exfiltration (Default Kill Chain)",
        "threat_actor": "APT29 / Cozy Bear (TOR Relay 185.220.101.47)",
        "complexity": "HIGH",
        "category": "Targeted Cyber Espionage",
        "description": "Multi-stage intrusion beginning with off-hours credential access on developer workstation, Active Directory LDAP discovery, privilege escalation, SMB pass-the-hash lateral pivot, and encrypted exfiltration on port 4444.",
        "mitre_techniques": ["T1078", "T1087", "T1558", "T1021", "T1048"],
        "target_assets": ["wkst-04-dev", "svc_ci_deploy", "db-prod-01"],
        "telemetry_count": 356
    },
    "ransomware_outbreak": {
        "id": "ransomware_outbreak",
        "title": "BlackCat / ALPHV Lateral Ransomware Outbreak",
        "threat_actor": "Ransomware Affiliate Group (External Ingress 194.26.29.112)",
        "complexity": "CRITICAL",
        "category": "Enterprise Ransomware",
        "description": "Rapid automated lateral propagation across enterprise subnets via SMB PsExec and WMI, targeting finance workstations and file repositories prior to payload detonation.",
        "mitre_techniques": ["T1190", "T1047", "T1021.002", "T1486", "T1490"],
        "target_assets": ["wkst-07-fin", "fs-corp-01", "backup-srv-01"],
        "telemetry_count": 280
    },
    "insider_threat_leak": {
        "id": "insider_threat_leak",
        "title": "Malicious Insider Credential & Database Harvest",
        "threat_actor": "Disgruntled Privileged Developer (emp_alex)",
        "complexity": "MEDIUM",
        "category": "Insider Threat",
        "description": "Authorized employee utilizing valid credentials off-hours to stage 5GB of customer financial records from staging database, archiving via 7-Zip and uploading to personal cloud endpoint.",
        "mitre_techniques": ["T1078.003", "T1560.001", "T1567.002"],
        "target_assets": ["wkst-02-dev", "db-stage-02"],
        "telemetry_count": 195
    },
    "supply_chain_poison": {
        "id": "supply_chain_poison",
        "title": "Compromised CI/CD Pipeline Artifact Poisoning",
        "threat_actor": "Adversary Infrastructure (pkg-mirror-c2.net)",
        "complexity": "HIGH",
        "category": "Supply Chain Attack",
        "description": "Compromised third-party npm/PyPI dependency injected into CI build runner during automated build, deploying persistent backdoored daemon on deployment host.",
        "mitre_techniques": ["T1195.002", "T1059.006", "T1574.006"],
        "target_assets": ["build-runner-01", "app-srv-02"],
        "telemetry_count": 240
    }
}


def list_available_scenarios() -> List[Dict[str, Any]]:
    """Returns catalog of all registered cybersecurity investigation scenarios."""
    return list(SCENARIO_CATALOG.values())


def get_scenario_metadata(scenario_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves metadata for a specific scenario."""
    return SCENARIO_CATALOG.get(scenario_id)


def load_scenario_telemetry(scenario_id: str) -> List[Dict[str, Any]]:
    """
    Generates tailored log telemetry corresponding to the selected scenario.
    """
    if scenario_id == "ransomware_outbreak":
        # Generate base telemetry and overlay ransomware attack signals
        logs = generate_logs(shuffle=True, inject_skew=True, drop_telemetry=False)
        # Add ransomware lateral movement indicators
        ransom_logs = [
            {
                "log_id": "LOG-RANSOM-001",
                "raw_timestamp": "2026-11-14T02:00:15+05:30",
                "normalized_timestamp": "2026-11-14T02:00:00+05:30",
                "source_host": "wkst-07-fin",
                "host_skew_sec": 15,
                "skew_corrected_sec": -15,
                "entity_type": "DEVICE",
                "source": "194.26.29.112",
                "target": "wkst-07-fin",
                "action": "EXPLOIT_PUBLIC_APP",
                "protocol": "HTTPS",
                "port": 443,
                "mitre_tag": "T1190",
                "mitre_technique": "Exploit Public-Facing Application",
                "severity": "CRITICAL",
                "is_malicious": True,
                "raw_payload": '{"service":"vpn_gateway","vulnerability":"CVE-2024-21887"}'
            },
            {
                "log_id": "LOG-RANSOM-002",
                "raw_timestamp": "2026-11-14T02:02:15+05:30",
                "normalized_timestamp": "2026-11-14T02:02:00+05:30",
                "source_host": "wkst-07-fin",
                "host_skew_sec": 15,
                "skew_corrected_sec": -15,
                "entity_type": "DEVICE",
                "source": "wkst-07-fin",
                "target": "fs-corp-01",
                "action": "WMI_LATERAL_EXEC",
                "protocol": "WMI / RPC",
                "port": 135,
                "mitre_tag": "T1047",
                "mitre_technique": "Windows Management Instrumentation",
                "severity": "HIGH",
                "is_malicious": True,
                "raw_payload": '{"command":"wmic /node:fs-corp-01 process call create cmd.exe"}'
            }
        ]
        return logs[:300] + ransom_logs
    else:
        # Default APT29 kill chain
        return generate_logs(shuffle=True, inject_skew=True, drop_telemetry=False)
