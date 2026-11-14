"""
OBSYRON XTM 2.0 — Relational Storage & Multi-User Investigation Database
Implements all 10 core tables, secure PBKDF2 password hashing, user isolation,
telemetry parsing persistence, evidence ledger tracking, and live dashboard stats.
"""

import os
import sqlite3
import json
import hashlib
import secrets
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

if os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
    default_db = "/tmp/obsyron.db"
else:
    default_db = os.path.join(os.path.dirname(os.path.abspath(__file__)), "obsyron.db")

DB_FILE = os.environ.get("SQLITE_DB_PATH", default_db)


def hash_password(password: str) -> str:
    """Secure password hashing using PBKDF2-HMAC-SHA256 with 100,000 rounds."""
    salt = secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return f"{salt.hex()}${key.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verifies a plaintext password against a stored PBKDF2 salt$key hash."""
    if not stored_hash:
        return False
    # Demo legacy bypass for obsyron2026 if plain
    if stored_hash in ["obsyron2026", "admin"]:
        return password == stored_hash
    try:
        parts = stored_hash.split("$")
        if len(parts) != 2:
            return password == stored_hash
        salt = bytes.fromhex(parts[0])
        expected_key = parts[1]
        key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
        return secrets.compare_digest(key.hex(), expected_key)
    except Exception:
        return False


class SQLiteStorage:
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or DB_FILE
        self._init_db()
        self._seed_default_profiles()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init_db(self):
        """Initializes all 10 core database tables with proper relational constraints."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # 1. Profiles Table (Authentication & User Identity)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS profiles (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                full_name TEXT NOT NULL,
                role TEXT DEFAULT 'Forensic Investigator',
                department TEXT DEFAULT 'Threat Intelligence & Forensic CIRT',
                clearance TEXT DEFAULT 'Level 3 (Secret)',
                clearance_code TEXT DEFAULT 'L3',
                avatar TEXT DEFAULT '🛡️',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """)

            # 2. Investigations Table (Owned by authenticated users)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS investigations (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT DEFAULT '',
                severity TEXT DEFAULT 'HIGH',
                status TEXT DEFAULT 'ACTIVE',
                dataset_name TEXT DEFAULT 'Enterprise Telemetry APT29',
                raw_log_count INTEGER DEFAULT 0,
                malicious_signal_count INTEGER DEFAULT 0,
                initial_access_entity TEXT DEFAULT '185.220.101.47',
                initial_access_tactic TEXT DEFAULT 'Initial Access',
                blast_radius_count INTEGER DEFAULT 0,
                overall_confidence REAL DEFAULT 0.95,
                nodes_count INTEGER DEFAULT 0,
                edges_count INTEGER DEFAULT 0,
                analysis_json TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES profiles(id) ON DELETE CASCADE
            )
            """)

            # 3. Telemetry Files Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS telemetry_files (
                id TEXT PRIMARY KEY,
                investigation_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                filename TEXT NOT NULL,
                file_size INTEGER DEFAULT 0,
                file_format TEXT DEFAULT 'JSON',
                record_count INTEGER DEFAULT 0,
                valid_count INTEGER DEFAULT 0,
                invalid_count INTEGER DEFAULT 0,
                duplicate_count INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY(investigation_id) REFERENCES investigations(id) ON DELETE CASCADE,
                FOREIGN KEY(user_id) REFERENCES profiles(id) ON DELETE CASCADE
            )
            """)

            # 4. Telemetry Events Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS telemetry_events (
                id TEXT PRIMARY KEY,
                file_id TEXT,
                investigation_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                raw_timestamp TEXT,
                normalized_timestamp TEXT,
                host TEXT,
                entity_type TEXT DEFAULT 'DEVICE',
                source TEXT,
                target TEXT,
                action TEXT,
                mitre_tag TEXT,
                severity TEXT DEFAULT 'LOW',
                confidence REAL DEFAULT 0.7,
                is_malicious INTEGER DEFAULT 0,
                raw_payload TEXT,
                sha256_hash TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(investigation_id) REFERENCES investigations(id) ON DELETE CASCADE,
                FOREIGN KEY(user_id) REFERENCES profiles(id) ON DELETE CASCADE
            )
            """)

            # 5. Attack Nodes Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS attack_nodes (
                id TEXT PRIMARY KEY,
                investigation_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                entity_type TEXT DEFAULT 'DEVICE',
                label TEXT,
                severity TEXT DEFAULT 'LOW',
                is_malicious INTEGER DEFAULT 0,
                centrality REAL DEFAULT 0.0,
                mitre_tags TEXT DEFAULT '[]',
                FOREIGN KEY(investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
            )
            """)

            # 6. Attack Edges Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS attack_edges (
                id TEXT PRIMARY KEY,
                investigation_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                source TEXT NOT NULL,
                target TEXT NOT NULL,
                action TEXT,
                mitre_tag TEXT,
                severity TEXT DEFAULT 'LOW',
                confidence REAL DEFAULT 0.8,
                is_inferred INTEGER DEFAULT 0,
                causal_connection TEXT,
                FOREIGN KEY(investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
            )
            """)

            # 7. Evidence Records Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS evidence_records (
                id TEXT PRIMARY KEY,
                investigation_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                sha256_hash TEXT,
                merkle_root TEXT,
                is_verified INTEGER DEFAULT 1,
                raw_log TEXT,
                supporting_facts TEXT DEFAULT '[]',
                contradictory_facts TEXT DEFAULT '[]',
                created_at TEXT NOT NULL,
                FOREIGN KEY(investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
            )
            """)

            # 8. Investigation Notes Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS investigation_notes (
                id TEXT PRIMARY KEY,
                investigation_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                author_name TEXT NOT NULL,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
            )
            """)

            # 9. Deception Events Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS deception_events (
                id TEXT PRIMARY KEY,
                investigation_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                sensor_type TEXT DEFAULT 'Cowrie SSH',
                src_ip TEXT,
                target_decoy TEXT,
                trigger_timestamp TEXT,
                payload TEXT,
                severity TEXT DEFAULT 'CRITICAL',
                created_at TEXT NOT NULL,
                FOREIGN KEY(investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
            )
            """)

            # 10. Investigation Reports Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS investigation_reports (
                id TEXT PRIMARY KEY,
                investigation_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                format TEXT NOT NULL,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
            )
            """)

            # Legacy Audit Logs Table (backward compatibility)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                log_id TEXT PRIMARY KEY,
                raw_timestamp TEXT,
                normalized_timestamp TEXT,
                host TEXT,
                entity_type TEXT,
                source TEXT,
                target TEXT,
                action TEXT,
                mitre_tag TEXT,
                severity TEXT,
                confidence REAL,
                is_malicious INTEGER,
                raw_payload TEXT,
                created_at TEXT
            )
            """)

            # Legacy Containment Actions Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS containment_actions (
                action_id TEXT PRIMARY KEY,
                investigation_id TEXT,
                entity_id TEXT NOT NULL,
                action_type TEXT NOT NULL,
                status TEXT DEFAULT 'EXECUTED',
                executed_at TEXT,
                operator TEXT,
                impact TEXT
            )
            """)

            conn.commit()

    def _seed_default_profiles(self):
        """Seeds default operator accounts with securely hashed passwords and complete forensic demo datasets."""
        now = datetime.now(timezone.utc).isoformat()
        default_users = [
            {
                "id": "usr_maya_thorne",
                "email": "maya@obsyron.corp",
                "username": "analyst_lead",
                "password_hash": hash_password("obsyron2026"),
                "full_name": "Cmdr. Maya Thorne",
                "role": "Lead Forensic Director",
                "department": "Global Threat Intel & Forensic CIRT",
                "clearance": "Level 4 (Top Secret / SCI)",
                "clearance_code": "L4",
                "avatar": "🛡️"
            },
            {
                "id": "usr_alex_chen",
                "email": "alex@obsyron.corp",
                "username": "soc_tier2",
                "password_hash": hash_password("obsyron2026"),
                "full_name": "Lt. Alex Chen",
                "role": "Senior Incident Responder",
                "department": "SOC Tier 2 Forensics",
                "clearance": "Level 3 (Secret / OpSec)",
                "clearance_code": "L3",
                "avatar": "⚡"
            },
            {
                "id": "usr_elena_rostova",
                "email": "elena@obsyron.corp",
                "username": "sec_auditor",
                "password_hash": hash_password("obsyron2026"),
                "full_name": "Sgt. Elena Rostova",
                "role": "Compliance & Triage Specialist",
                "department": "Security Audit Division",
                "clearance": "Level 2 (Confidential)",
                "clearance_code": "L2",
                "avatar": "🔍"
            }
        ]

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for u in default_users:
                cursor.execute("""
                INSERT OR IGNORE INTO profiles (
                    id, email, username, password_hash, full_name, role,
                    department, clearance, clearance_code, avatar, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    u["id"], u["email"], u["username"], u["password_hash"], u["full_name"],
                    u["role"], u["department"], u["clearance"], u["clearance_code"],
                    u["avatar"], now, now
                ))
            conn.commit()

        # Seed full relational forensic demo data across all 10 tables for all default operators
        for u in default_users:
            self.seed_complete_forensic_demo_data(u["id"])

    def seed_complete_forensic_demo_data(self, target_user_id: str, force_reset: bool = False) -> Dict[str, Any]:
        """
        Seeds complete, realistic forensic demo records across all 10 tables for the specified user.
        Includes 4 investigations, telemetry files, normalized events, rectangular attack nodes,
        causal attack edges, SHA-256 Merkle evidence records, CIRT handover notes,
        deception honeypot events, and executive forensic reports.
        """
        now = datetime.now(timezone.utc).isoformat()
        u_suffix = "001" if target_user_id == "usr_maya_thorne" else target_user_id[-6:]

        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Check if user already has investigations
            cursor.execute("SELECT count(*) as cnt FROM investigations WHERE user_id = ?", (target_user_id,))
            cnt = cursor.fetchone()["cnt"]
            if cnt >= 4 and not force_reset:
                return {
                    "success": True,
                    "message": "Demo data already seeded for operator",
                    "investigations_count": cnt
                }

            if force_reset:
                cursor.execute("DELETE FROM investigations WHERE user_id = ?", (target_user_id,))

            inv1_id = "OBS-INV-20261114-001" if target_user_id == "usr_maya_thorne" else f"OBS-INV-{u_suffix}-001"
            inv2_id = "OBS-INV-20261114-002" if target_user_id == "usr_maya_thorne" else f"OBS-INV-{u_suffix}-002"
            inv3_id = "OBS-INV-20261114-003" if target_user_id == "usr_maya_thorne" else f"OBS-INV-{u_suffix}-003"
            inv4_id = "OBS-INV-20261114-004" if target_user_id == "usr_maya_thorne" else f"OBS-INV-{u_suffix}-004"

            # 1. Four Core Investigations with Rich Analysis JSON
            inv1_analysis = {
                "raw_log_count": 357,
                "malicious_signal_count": 7,
                "snr": "357 Raw Logs → 7 Malicious Signals",
                "initial_access": {
                    "entity": "185.220.101.47",
                    "target": "vpn.obsyron.corp",
                    "mitre_tactic": "Initial Access",
                    "mitre_id": "T1078",
                    "timestamp": "2026-03-31T01:14:02Z",
                    "confidence": 0.98,
                    "why_suspicious": "Known TOR exit node authenticating to corporate VPN gateway without MFA token challenge."
                },
                "blast_radius": {
                    "count": 15,
                    "entities": ["vpn.obsyron.corp", "emp_rohan", "wkst-04-dev", "powershell.exe", "svc_ci_deploy", "db-prod-01", "198.51.100.23"]
                },
                "overall_confidence": 0.944,
                "timeline_min": "2026-03-31T01:14:02Z",
                "timeline_max": "2026-03-31T01:21:40Z",
                "merkle_root": "160bce742077ef960056115f3f14a6f840de042fcbb65693cde49436d1f007e0",
                "nodes": [
                    {"id": "185.220.101.47", "label": "185.220.101.47", "entity_type": "AUTH_ENDPOINT", "is_malicious": True, "centrality": 0.354, "log_ids": ["EVT-001"], "mitre_tags": ["T1078"], "color": "#EF4444"},
                    {"id": "vpn.obsyron.corp", "label": "vpn.obsyron.corp", "entity_type": "GATEWAY", "is_malicious": True, "centrality": 0.281, "log_ids": ["EVT-001", "EVT-002"], "mitre_tags": ["T1078"], "color": "#38BDF8"},
                    {"id": "emp_rohan", "label": "emp_rohan", "entity_type": "USER", "is_malicious": True, "centrality": 0.291, "log_ids": ["EVT-002", "EVT-003"], "mitre_tags": ["T1078.004"], "color": "#818CF8"},
                    {"id": "wkst-04-dev", "label": "wkst-04-dev", "entity_type": "DEVICE", "is_malicious": True, "centrality": 0.482, "log_ids": ["EVT-003", "EVT-004"], "mitre_tags": ["T1021.001"], "color": "#34D399"},
                    {"id": "powershell.exe", "label": "powershell.exe", "entity_type": "PROCESS", "is_malicious": True, "centrality": 0.412, "log_ids": ["EVT-004", "EVT-005"], "mitre_tags": ["T1059.001"], "color": "#F59E0B"},
                    {"id": "svc_ci_deploy", "label": "svc_ci_deploy", "entity_type": "SERVICE", "is_malicious": True, "centrality": 0.228, "log_ids": ["EVT-005", "EVT-006"], "mitre_tags": ["T1558"], "color": "#818CF8"},
                    {"id": "db-prod-01", "label": "db-prod-01", "entity_type": "DEVICE", "is_malicious": True, "centrality": 0.186, "log_ids": ["EVT-006", "EVT-007"], "mitre_tags": ["T1021.002"], "color": "#EC4899"},
                    {"id": "198.51.100.23", "label": "198.51.100.23", "entity_type": "AUTH_ENDPOINT", "is_malicious": True, "centrality": 0.125, "log_ids": ["EVT-007"], "mitre_tags": ["T1048"], "color": "#EF4444"}
                ],
                "edges": [
                    {"id": "e0", "source": "185.220.101.47", "target": "vpn.obsyron.corp", "action": "EXTERNAL_AUTH", "confidence": 0.98, "is_inferred": False, "is_malicious": True, "mitre_tag": "T1078"},
                    {"id": "e1", "source": "vpn.obsyron.corp", "target": "emp_rohan", "action": "VALID_CREDENTIALS", "confidence": 0.95, "is_inferred": False, "is_malicious": True, "mitre_tag": "T1078.004"},
                    {"id": "e2", "source": "emp_rohan", "target": "wkst-04-dev", "action": "RDP_ACCESS", "confidence": 0.92, "is_inferred": False, "is_malicious": True, "mitre_tag": "T1021.001"},
                    {"id": "e3", "source": "wkst-04-dev", "target": "powershell.exe", "action": "PROC_CREATE", "confidence": 0.99, "is_inferred": False, "is_malicious": True, "mitre_tag": "T1059.001"},
                    {"id": "e4", "source": "powershell.exe", "target": "svc_ci_deploy", "action": "INFERRED_LATERAL_BRIDGE", "confidence": 0.62, "is_inferred": True, "is_malicious": True, "mitre_tag": "T1558"},
                    {"id": "e5", "source": "svc_ci_deploy", "target": "db-prod-01", "action": "SMB_LATERAL_MOVE", "confidence": 0.88, "is_inferred": False, "is_malicious": True, "mitre_tag": "T1021.002"},
                    {"id": "e6", "source": "db-prod-01", "target": "198.51.100.23", "action": "C2_EXFILTRATION", "confidence": 0.99, "is_inferred": False, "is_malicious": True, "mitre_tag": "T1048"}
                ],
                "xai_report": [
                    {"step": 1, "title": "Initial Access: Ingress via Stolen Credentials", "entity": "185.220.101.47", "target": "vpn.obsyron.corp", "action": "EXTERNAL_AUTH", "mitre": "T1078", "severity": "CRITICAL", "confidence": 0.98, "why_suspicious": "Anomalous ingress from known TOR exit relay matching compromised credentials of emp_rohan.", "time": "01:14:02 UTC", "log_citations": ["LOG-APT-001"], "is_inferred": False},
                    {"step": 2, "title": "Identity Hijack: Valid Account Session Issue", "entity": "vpn.obsyron.corp", "target": "emp_rohan", "action": "VALID_CREDENTIALS", "mitre": "T1078.004", "severity": "HIGH", "confidence": 0.95, "why_suspicious": "Single-factor VPN tunnel established without required MFA biometric challenge.", "time": "01:14:35 UTC", "log_citations": ["LOG-APT-002"], "is_inferred": False},
                    {"step": 3, "title": "Lateral Movement: Remote Desktop Access to Dev Host", "entity": "emp_rohan", "target": "wkst-04-dev", "action": "RDP_ACCESS", "mitre": "T1021.001", "severity": "HIGH", "confidence": 0.92, "why_suspicious": "RDP connection initiated outside scheduled shifts with abnormal screen resolution.", "time": "01:15:10 UTC", "log_citations": ["LOG-APT-003"], "is_inferred": False},
                    {"step": 4, "title": "Execution: Obfuscated PowerShell Command Launch", "entity": "wkst-04-dev", "target": "powershell.exe", "action": "PROC_CREATE", "mitre": "T1059.001", "severity": "CRITICAL", "confidence": 0.99, "why_suspicious": "Base64-encoded PowerShell script spawned by explorer.exe bypassing execution policies.", "time": "01:16:45 UTC", "log_citations": ["LOG-APT-004"], "is_inferred": False},
                    {"step": 5, "title": "Privilege Escalation: Inferred Token Elevation Bridge", "entity": "powershell.exe", "target": "svc_ci_deploy", "action": "INFERRED_LATERAL_BRIDGE", "mitre": "T1558", "severity": "CRITICAL", "confidence": 0.62, "why_suspicious": "Telemetry gap bridged: wkst-04-dev memory dump followed by privileged service token activity.", "time": "01:18:00 UTC", "log_citations": ["INFERRED-GAP-BRIDGE"], "is_inferred": True},
                    {"step": 6, "title": "Lateral Movement: Production SQL Database Mounting", "entity": "svc_ci_deploy", "target": "db-prod-01", "action": "SMB_LATERAL_MOVE", "mitre": "T1021.002", "severity": "HIGH", "confidence": 0.88, "why_suspicious": "Administrative C$ share mounted on production database cluster from developer workstation.", "time": "01:19:15 UTC", "log_citations": ["LOG-APT-005"], "is_inferred": False},
                    {"step": 7, "title": "Exfiltration: High-Volume Egress to Drop Server", "entity": "db-prod-01", "target": "198.51.100.23", "action": "C2_EXFILTRATION", "mitre": "T1048", "severity": "CRITICAL", "confidence": 0.99, "why_suspicious": "84.2 MB compressed SQL backup dumped to unclassified external IP over encrypted HTTPS stream.", "time": "01:21:40 UTC", "log_citations": ["LOG-APT-006"], "is_inferred": False}
                ]
            }

            inv2_analysis = {
                "raw_log_count": 194,
                "malicious_signal_count": 5,
                "snr": "194 Raw Logs → 5 Malicious Signals",
                "initial_access": {
                    "entity": "192.168.10.84",
                    "target": "CORP-DC-01",
                    "mitre_tactic": "Credential Access",
                    "mitre_id": "T1558.003",
                    "timestamp": "2026-03-31T02:05:12Z",
                    "confidence": 0.91,
                    "why_suspicious": "SPN Kerberos TGS-REQ ticket requested with RC4 encryption downgrade (Kerberoasting)."
                },
                "blast_radius": {
                    "count": 8,
                    "entities": ["wkst-12-qa", "CORP-DC-01", "svc_sql_admin", "db-cluster-01", "app-server-02"]
                },
                "overall_confidence": 0.887,
                "timeline_min": "2026-03-31T02:05:12Z",
                "timeline_max": "2026-03-31T02:18:40Z",
                "merkle_root": "4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e",
                "nodes": [
                    {"id": "192.168.10.84", "label": "wkst-12-qa", "entity_type": "DEVICE", "is_malicious": True, "centrality": 0.28, "log_ids": ["KRB-001"], "mitre_tags": ["T1558.003"], "color": "#34D399"},
                    {"id": "CORP-DC-01", "label": "CORP-DC-01 (DC)", "entity_type": "DEVICE", "is_malicious": True, "centrality": 0.42, "log_ids": ["KRB-001", "KRB-002"], "mitre_tags": ["T1558.003"], "color": "#38BDF8"},
                    {"id": "svc_sql_admin", "label": "svc_sql_admin", "entity_type": "SERVICE", "is_malicious": True, "centrality": 0.35, "log_ids": ["KRB-002", "KRB-003"], "mitre_tags": ["T1078.002"], "color": "#818CF8"},
                    {"id": "db-cluster-01", "label": "db-cluster-01", "entity_type": "DEVICE", "is_malicious": True, "centrality": 0.25, "log_ids": ["KRB-003", "KRB-004"], "mitre_tags": ["T1021.002"], "color": "#EC4899"},
                    {"id": "app-server-02", "label": "app-server-02", "entity_type": "DEVICE", "is_malicious": True, "centrality": 0.15, "log_ids": ["KRB-004"], "mitre_tags": ["T1053.005"], "color": "#F59E0B"}
                ],
                "edges": [
                    {"id": "e0", "source": "192.168.10.84", "target": "CORP-DC-01", "action": "KERBEROS_TGS_REQ", "confidence": 0.94, "is_inferred": False, "is_malicious": True, "mitre_tag": "T1558.003"},
                    {"id": "e1", "source": "CORP-DC-01", "target": "svc_sql_admin", "action": "RC4_DOWNGRADE", "confidence": 0.92, "is_inferred": False, "is_malicious": True, "mitre_tag": "T1558.003"},
                    {"id": "e2", "source": "svc_sql_admin", "target": "db-cluster-01", "action": "MSSQL_AUTH", "confidence": 0.89, "is_inferred": False, "is_malicious": True, "mitre_tag": "T1078.002"},
                    {"id": "e3", "source": "db-cluster-01", "target": "app-server-02", "action": "PERSISTENCE_TASK", "confidence": 0.85, "is_inferred": False, "is_malicious": True, "mitre_tag": "T1053.005"}
                ],
                "xai_report": [
                    {"step": 1, "title": "Kerberoasting: RC4 SPN Request", "entity": "192.168.10.84", "target": "CORP-DC-01", "action": "KERBEROS_TGS_REQ", "mitre": "T1558.003", "severity": "HIGH", "confidence": 0.94, "why_suspicious": "Anomalous TGS-REQ ticket requested for svc_sql_admin with weak encryption.", "time": "02:05:12 UTC", "log_citations": ["KRB-001"], "is_inferred": False},
                    {"step": 2, "title": "Credential Access: RC4 Downgrade Extraction", "entity": "CORP-DC-01", "target": "svc_sql_admin", "action": "RC4_DOWNGRADE", "mitre": "T1558.003", "severity": "HIGH", "confidence": 0.92, "why_suspicious": "RC4 Kerberos ticket granted for offline hashcat cracking.", "time": "02:07:30 UTC", "log_citations": ["KRB-002"], "is_inferred": False},
                    {"step": 3, "title": "Lateral Movement: Database Cluster Ingress", "entity": "svc_sql_admin", "target": "db-cluster-01", "action": "MSSQL_AUTH", "mitre": "T1078.002", "severity": "HIGH", "confidence": 0.89, "why_suspicious": "Privileged MSSQL authentication using cracked service account ticket.", "time": "02:12:45 UTC", "log_citations": ["KRB-003"], "is_inferred": False},
                    {"step": 4, "title": "Persistence: Scheduled Task Registration", "entity": "db-cluster-01", "target": "app-server-02", "action": "PERSISTENCE_TASK", "mitre": "T1053.005", "severity": "HIGH", "confidence": 0.85, "why_suspicious": "Hidden persistence task scheduled across internal application server.", "time": "02:18:40 UTC", "log_citations": ["KRB-004"], "is_inferred": False}
                ]
            }

            inv3_analysis = {
                "raw_log_count": 280,
                "malicious_signal_count": 6,
                "snr": "280 Raw Logs → 6 Malicious Signals",
                "initial_access": {
                    "entity": "wkst-09-fin",
                    "target": "vssadmin.exe",
                    "mitre_tactic": "Defense Evasion",
                    "mitre_id": "T1490",
                    "timestamp": "2026-03-31T03:30:15Z",
                    "confidence": 0.965,
                    "why_suspicious": "Volume Shadow Copy deletion initiated silently via vssadmin.exe."
                },
                "blast_radius": {
                    "count": 12,
                    "entities": ["wkst-09-fin", "vssadmin.exe", "encryptor.exe", "backup-nas-01"]
                },
                "overall_confidence": 0.965,
                "timeline_min": "2026-03-31T03:30:15Z",
                "timeline_max": "2026-03-31T03:35:50Z",
                "merkle_root": "7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b",
                "nodes": [
                    {"id": "wkst-09-fin", "label": "wkst-09-fin (Finance)", "entity_type": "DEVICE", "is_malicious": True, "centrality": 0.38, "log_ids": ["RSM-001"], "mitre_tags": ["T1566.001"], "color": "#34D399"},
                    {"id": "vssadmin.exe", "label": "vssadmin.exe", "entity_type": "PROCESS", "is_malicious": True, "centrality": 0.45, "log_ids": ["RSM-002"], "mitre_tags": ["T1490"], "color": "#F59E0B"},
                    {"id": "encryptor.exe", "label": "encryptor.exe", "entity_type": "PROCESS", "is_malicious": True, "centrality": 0.40, "log_ids": ["RSM-003"], "mitre_tags": ["T1486"], "color": "#EF4444"},
                    {"id": "backup-nas-01", "label": "backup-nas-01", "entity_type": "DEVICE", "is_malicious": True, "centrality": 0.22, "log_ids": ["RSM-004"], "mitre_tags": ["T1046"], "color": "#EC4899"}
                ],
                "edges": [
                    {"id": "e0", "source": "wkst-09-fin", "target": "vssadmin.exe", "action": "PROC_CREATE", "confidence": 0.99, "is_inferred": False, "is_malicious": True, "mitre_tag": "T1490"},
                    {"id": "e1", "source": "vssadmin.exe", "target": "encryptor.exe", "action": "PAYLOAD_STAGE", "confidence": 0.97, "is_inferred": False, "is_malicious": True, "mitre_tag": "T1486"},
                    {"id": "e2", "source": "encryptor.exe", "target": "backup-nas-01", "action": "SMB_SCAN", "confidence": 0.91, "is_inferred": False, "is_malicious": True, "mitre_tag": "T1046"}
                ],
                "xai_report": [
                    {"step": 1, "title": "Execution: Malicious Office Macro Trigger", "entity": "wkst-09-fin", "target": "vssadmin.exe", "action": "PROC_CREATE", "mitre": "T1566.001", "severity": "CRITICAL", "confidence": 0.99, "why_suspicious": "Finance user opened spoofed invoice triggering vssadmin shadow deletion.", "time": "03:30:15 UTC", "log_citations": ["RSM-001"], "is_inferred": False},
                    {"step": 2, "title": "Impact: System Recovery Sabotage", "entity": "vssadmin.exe", "target": "encryptor.exe", "action": "PAYLOAD_STAGE", "mitre": "T1490", "severity": "CRITICAL", "confidence": 0.97, "why_suspicious": "Shadow copies wiped to prevent local restoration prior to encryption.", "time": "03:32:00 UTC", "log_citations": ["RSM-002"], "is_inferred": False},
                    {"step": 3, "title": "Discovery: Network Share Probing", "entity": "encryptor.exe", "target": "backup-nas-01", "action": "SMB_SCAN", "mitre": "T1046", "severity": "HIGH", "confidence": 0.91, "why_suspicious": "Ransomware scanned for enterprise backup shares before containment isolation kicked in.", "time": "03:35:50 UTC", "log_citations": ["RSM-003"], "is_inferred": False}
                ]
            }

            inv4_analysis = {
                "raw_log_count": 142,
                "malicious_signal_count": 2,
                "snr": "142 Raw Logs → 2 Malicious Signals",
                "initial_access": {
                    "entity": "45.33.32.156",
                    "target": "cowrie-ssh-dmz",
                    "mitre_tactic": "Credential Access",
                    "mitre_id": "T1110.003",
                    "timestamp": "2026-03-31T04:10:00Z",
                    "confidence": 0.991,
                    "why_suspicious": "Distributed SSH dictionary spray targeting root/admin credentials."
                },
                "blast_radius": {
                    "count": 2,
                    "entities": ["bastion-dmz", "cowrie-ssh-dmz"]
                },
                "overall_confidence": 0.991,
                "timeline_min": "2026-03-31T04:10:00Z",
                "timeline_max": "2026-03-31T04:14:22Z",
                "merkle_root": "8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a",
                "nodes": [
                    {"id": "45.33.32.156", "label": "45.33.32.156 (Scanner)", "entity_type": "AUTH_ENDPOINT", "is_malicious": True, "centrality": 0.45, "log_ids": ["SSH-001"], "mitre_tags": ["T1110.003"], "color": "#EF4444"},
                    {"id": "cowrie-ssh-dmz", "label": "cowrie-ssh-dmz (Honeytrap)", "entity_type": "DECEPTION_SENSOR", "is_malicious": False, "centrality": 0.45, "log_ids": ["SSH-001", "SSH-002"], "mitre_tags": ["T1046"], "color": "#38BDF8"}
                ],
                "edges": [
                    {"id": "e0", "source": "45.33.32.156", "target": "cowrie-ssh-dmz", "action": "SSH_SPRAY", "confidence": 0.99, "is_inferred": False, "is_malicious": True, "mitre_tag": "T1110.003"}
                ],
                "xai_report": [
                    {"step": 1, "title": "Credential Access: Low-and-Slow Password Spray", "entity": "45.33.32.156", "target": "cowrie-ssh-dmz", "action": "SSH_SPRAY", "mitre": "T1110.003", "severity": "MEDIUM", "confidence": 0.99, "why_suspicious": "142 SSH connection attempts with dictionary passwords captured by decoy honeypot.", "time": "04:10:00 UTC", "log_citations": ["SSH-001"], "is_inferred": False}
                ]
            }

            demo_invs = [
                (
                    inv1_id, target_user_id, "Operation Red Relic (APT29 Infiltration)",
                    "Autonomous multi-stage intrusion reconstruction originating from TOR exit relay targeting CI/CD credentials and production database.",
                    "CRITICAL", "ACTIVE", "Enterprise Telemetry APT29",
                    357, 7, "185.220.101.47", "Valid Accounts (T1078)", 15, 0.944, 29, 52, json.dumps(inv1_analysis), now, now
                ),
                (
                    inv2_id, target_user_id, "Operation Velvet Typhoon (Kerberoasting Campaign)",
                    "Service Principal Name (SPN) ticket extraction attempt detected targeting Domain Controller CORP-DC-01 with RC4 downgrade requests.",
                    "HIGH", "ACTIVE", "Active Directory Kerberos Audits",
                    194, 5, "192.168.10.84", "Kerberoasting (T1558.003)", 8, 0.887, 18, 27, json.dumps(inv2_analysis), now, now
                ),
                (
                    inv3_id, target_user_id, "DarkSide Ransomware Staging (Subnet 10.0.4.0/24)",
                    "Volume Shadow Copy deletion (vssadmin delete shadows /all) and staging of encrypted archive targeting backup-nas-01. Quarantined via host firewall isolation.",
                    "CRITICAL", "CONTAINED", "Endpoint EDR & Sysmon Telemetry",
                    280, 6, "wkst-09-fin", "Inhibit System Recovery (T1490)", 12, 0.965, 22, 34, json.dumps(inv3_analysis), now, now
                ),
                (
                    inv4_id, target_user_id, "Automated Brute Force on SSH Bastion",
                    "Low-and-slow SSH password spray originating from bulletproof hosting subnet; safely isolated and absorbed by OpenCanary honeypot trap.",
                    "MEDIUM", "RESOLVED", "Auth.log / OpenCanary Decoy",
                    142, 2, "45.33.32.156", "Brute Force (T1110.003)", 2, 0.991, 6, 8, json.dumps(inv4_analysis), now, now
                )
            ]

            for inv in demo_invs:
                cursor.execute("""
                INSERT OR REPLACE INTO investigations (
                    id, user_id, name, description, severity, status,
                    dataset_name, raw_log_count, malicious_signal_count,
                    initial_access_entity, initial_access_tactic, blast_radius_count,
                    overall_confidence, nodes_count, edges_count, analysis_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, inv)

            # 2. Telemetry Files
            file1_id = f"FILE-{u_suffix}-001"
            file2_id = f"FILE-{u_suffix}-002"
            file3_id = f"FILE-{u_suffix}-003"
            file4_id = f"FILE-{u_suffix}-004"

            files = [
                (file1_id, inv1_id, target_user_id, "apt29_telemetry_batch1.csv", 48210, "CSV", 357, 350, 0, 7, now),
                (file2_id, inv2_id, target_user_id, "kerberos_event4769_dump.json", 24900, "JSON", 194, 190, 0, 4, now),
                (file3_id, inv3_id, target_user_id, "sysmon_ransomware_staging.csv", 36400, "CSV", 280, 275, 0, 5, now),
                (file4_id, inv4_id, target_user_id, "cowrie_auth_spray.log", 18200, "LOG", 142, 140, 0, 2, now)
            ]
            for f in files:
                cursor.execute("""
                INSERT OR REPLACE INTO telemetry_files (
                    id, investigation_id, user_id, filename, file_size, file_format,
                    record_count, valid_count, invalid_count, duplicate_count, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, f)

            # 3. Telemetry Events (Core Chronological Sequence)
            events = [
                (f"EVT-{u_suffix}-001", file1_id, inv1_id, target_user_id, "2026-03-31T01:14:02Z", "2026-03-31T01:14:02Z", "vpn.obsyron.corp", "AUTH_ENDPOINT", "185.220.101.47", "vpn.obsyron.corp", "EXTERNAL_INGRESS", "T1078", "CRITICAL", 0.98, 1, json.dumps({"ip": "185.220.101.47", "asn": "AS44111", "country": "NL", "auth_method": "Single-Factor Password"}), "160bce742077ef960056115f3f14a6f840de042fcbb65693cde49436d1f007e0", now),
                (f"EVT-{u_suffix}-002", file1_id, inv1_id, target_user_id, "2026-03-31T01:14:15Z", "2026-03-31T01:14:15Z", "vpn.obsyron.corp", "USER", "vpn.obsyron.corp", "emp_rohan", "CREDENTIAL_VALIDATION", "T1078.004", "CRITICAL", 0.95, 1, json.dumps({"user": "emp_rohan", "session_id": "SESS-VPN-9182", "mfa_prompted": False}), "2b8c9d1e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c", now),
                (f"EVT-{u_suffix}-003", file1_id, inv1_id, target_user_id, "2026-03-31T01:15:30Z", "2026-03-31T01:15:30Z", "wkst-04-dev", "DEVICE", "emp_rohan", "wkst-04-dev", "RDP_SESSION_START", "T1021.001", "HIGH", 0.92, 1, json.dumps({"protocol": "RDP", "source_ip": "10.0.8.24", "target_workstation": "wkst-04-dev"}), "3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d", now),
                (f"EVT-{u_suffix}-004", file1_id, inv1_id, target_user_id, "2026-03-31T01:16:04Z", "2026-03-31T01:16:04Z", "wkst-04-dev", "PROCESS", "wkst-04-dev", "powershell.exe", "PROCESS_CREATE", "T1059.001", "CRITICAL", 0.99, 1, json.dumps({"command_line": "powershell.exe -NonI -W Hidden -Enc SQBFAFgA...", "parent": "explorer.exe"}), "4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e", now),
                (f"EVT-{u_suffix}-005", file1_id, inv1_id, target_user_id, "2026-03-31T01:20:18Z", "2026-03-31T01:20:18Z", "wkst-04-dev", "SERVICE", "powershell.exe", "svc_ci_deploy", "INFERRED_PRIVILEGE_BRIDGE", "T1558", "CRITICAL", 0.91, 1, json.dumps({"impersonated_service": "svc_ci_deploy", "inferred": True, "rationale": "Missing Event 4672 bridged via gap heuristic"}), "5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f", now),
                (f"EVT-{u_suffix}-006", file1_id, inv1_id, target_user_id, "2026-03-31T01:22:45Z", "2026-03-31T01:22:45Z", "db-prod-01", "DEVICE", "svc_ci_deploy", "db-prod-01", "SMB_ACCESS", "T1021.002", "HIGH", 0.88, 1, json.dumps({"share": "\\\\db-prod-01\\c$\\Backups", "auth_user": "svc_ci_deploy"}), "6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a", now),
                (f"EVT-{u_suffix}-007", file1_id, inv1_id, target_user_id, "2026-03-31T01:25:12Z", "2026-03-31T01:25:12Z", "db-prod-01", "AUTH_ENDPOINT", "db-prod-01", "198.51.100.23", "DATA_EXFILTRATION", "T1048", "CRITICAL", 0.99, 1, json.dumps({"dest_ip": "198.51.100.23", "bytes_sent": 84200000, "protocol": "HTTPS (Encrypted)"}), "7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b", now),
                (f"EVT-{u_suffix}-008", file2_id, inv2_id, target_user_id, "2026-03-31T02:10:00Z", "2026-03-31T02:10:00Z", "CORP-DC-01", "DEVICE", "192.168.10.84", "CORP-DC-01", "KERBEROS_TGS_REQ", "T1558.003", "HIGH", 0.89, 1, json.dumps({"spn": "MSSQLSvc/db-prod-01.corp", "ticket_encryption": "0x17 (RC4-HMAC)"}), "8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c", now),
                (f"EVT-{u_suffix}-009", file3_id, inv3_id, target_user_id, "2026-03-31T03:00:15Z", "2026-03-31T03:00:15Z", "wkst-09-fin", "PROCESS", "wkst-09-fin", "vssadmin.exe", "DELETE_SHADOWS", "T1490", "CRITICAL", 0.98, 1, json.dumps({"command": "vssadmin delete shadows /all /quiet", "status": "BLOCKED"}), "9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d", now),
                (f"EVT-{u_suffix}-010", file4_id, inv4_id, target_user_id, "2026-03-31T03:45:00Z", "2026-03-31T03:45:00Z", "bastion-dmz-01", "DECEPTION_SENSOR", "45.33.32.156", "cowrie-ssh-dmz", "SSH_AUTH_FAIL", "T1110.003", "MEDIUM", 0.99, 1, json.dumps({"user_attempt": "root", "honeypot": "cowrie-ssh-dmz"}), "0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e", now)
            ]

            for e in events:
                cursor.execute("""
                INSERT OR REPLACE INTO telemetry_events (
                    id, file_id, investigation_id, user_id, raw_timestamp, normalized_timestamp,
                    host, entity_type, source, target, action, mitre_tag, severity,
                    confidence, is_malicious, raw_payload, sha256_hash, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, e)

            # 4. Attack Nodes (Rectangular Visual Graph Nodes)
            nodes = [
                (f"NODE-{u_suffix}-01", inv1_id, target_user_id, "185.220.101.47", "AUTH_ENDPOINT", "185.220.101.47 (TOR C2)", "CRITICAL", 1, 0.354, json.dumps(["T1078"])),
                (f"NODE-{u_suffix}-02", inv1_id, target_user_id, "vpn.obsyron.corp", "GATEWAY", "vpn.obsyron.corp", "HIGH", 1, 0.281, json.dumps(["T1078"])),
                (f"NODE-{u_suffix}-03", inv1_id, target_user_id, "emp_rohan", "USER", "emp_rohan (Identity)", "HIGH", 1, 0.291, json.dumps(["T1078.004"])),
                (f"NODE-{u_suffix}-04", inv1_id, target_user_id, "wkst-04-dev", "DEVICE", "wkst-04-dev (Endpoint)", "HIGH", 1, 0.482, json.dumps(["T1021.001"])),
                (f"NODE-{u_suffix}-05", inv1_id, target_user_id, "powershell.exe", "PROCESS", "powershell.exe", "CRITICAL", 1, 0.412, json.dumps(["T1059.001"])),
                (f"NODE-{u_suffix}-06", inv1_id, target_user_id, "svc_ci_deploy", "SERVICE", "svc_ci_deploy (Service)", "CRITICAL", 1, 0.228, json.dumps(["T1558"])),
                (f"NODE-{u_suffix}-07", inv1_id, target_user_id, "db-prod-01", "DEVICE", "db-prod-01 (Database)", "CRITICAL", 1, 0.186, json.dumps(["T1021.002"])),
                (f"NODE-{u_suffix}-08", inv1_id, target_user_id, "198.51.100.23", "AUTH_ENDPOINT", "198.51.100.23 (Drop Server)", "CRITICAL", 1, 0.125, json.dumps(["T1048"])),
                (f"NODE-{u_suffix}-09", inv1_id, target_user_id, "cowrie-ssh-dmz", "DECEPTION_SENSOR", "cowrie-ssh-dmz (Honeytrap)", "LOW", 0, 0.05, json.dumps(["T1046"]))
            ]
            for n in nodes:
                cursor.execute("""
                INSERT OR REPLACE INTO attack_nodes (
                    id, investigation_id, user_id, entity_id, entity_type, label,
                    severity, is_malicious, centrality, mitre_tags
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, n)

            # 5. Attack Edges
            edges = [
                (f"EDGE-{u_suffix}-01", inv1_id, target_user_id, "185.220.101.47", "vpn.obsyron.corp", "EXTERNAL_AUTH", "T1078", "CRITICAL", 0.98, 0, "TOR ingress authenticated against perimeter gateway"),
                (f"EDGE-{u_suffix}-02", inv1_id, target_user_id, "vpn.obsyron.corp", "emp_rohan", "VALID_CREDENTIALS", "T1078.004", "HIGH", 0.95, 0, "Single-factor session issued to stolen account"),
                (f"EDGE-{u_suffix}-03", inv1_id, target_user_id, "emp_rohan", "wkst-04-dev", "RDP_ACCESS", "T1021.001", "HIGH", 0.92, 0, "Interactive session established to developer endpoint"),
                (f"EDGE-{u_suffix}-04", inv1_id, target_user_id, "wkst-04-dev", "powershell.exe", "PROC_CREATE", "T1059.001", "CRITICAL", 0.99, 0, "Obfuscated PowerShell execution launched"),
                (f"EDGE-{u_suffix}-05", inv1_id, target_user_id, "powershell.exe", "svc_ci_deploy", "INFERRED_PRIVILEGE_BRIDGE", "T1558", "CRITICAL", 0.91, 1, "Bridged privilege escalation across telemetry gap"),
                (f"EDGE-{u_suffix}-06", inv1_id, target_user_id, "svc_ci_deploy", "db-prod-01", "SMB_LATERAL_MOVE", "T1021.002", "HIGH", 0.88, 0, "Authenticated network share mount to production SQL server"),
                (f"EDGE-{u_suffix}-07", inv1_id, target_user_id, "db-prod-01", "198.51.100.23", "C2_EXFILTRATION", "T1048", "CRITICAL", 0.99, 0, "84.2 MB archive transmitted to external listener")
            ]
            for ed in edges:
                cursor.execute("""
                INSERT OR REPLACE INTO attack_edges (
                    id, investigation_id, user_id, source, target, action,
                    mitre_tag, severity, confidence, is_inferred, causal_connection
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, ed)

            # 6. Evidence Records (Cryptographic Ledger)
            evidences = [
                (f"EVD-{u_suffix}-01", inv1_id, target_user_id, f"EVT-{u_suffix}-001", "160bce742077ef960056115f3f14a6f840de042fcbb65693cde49436d1f007e0", "160bce742077ef960056115f3f14a6f840de042fcbb65693cde49436d1f007e0", 1, "Syslog packet auth.vpn.nl ingress match", json.dumps(["Observed at 01:14:02Z", "Source ASN44111"]), json.dumps([]), now),
                (f"EVD-{u_suffix}-02", inv1_id, target_user_id, f"EVT-{u_suffix}-004", "4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e", "160bce742077ef960056115f3f14a6f840de042fcbb65693cde49436d1f007e0", 1, "Sysmon Event ID 1: Process Creation powershell.exe", json.dumps(["Parent explorer.exe", "Encoded payload"]), json.dumps([]), now),
                (f"EVD-{u_suffix}-03", inv1_id, target_user_id, f"EVT-{u_suffix}-007", "7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b", "160bce742077ef960056115f3f14a6f840de042fcbb65693cde49436d1f007e0", 1, "Palo Alto NetFlow: TCP 443 84.2MB to 198.51.100.23", json.dumps(["Volume anomaly 84.2MB", "External destination"]), json.dumps([]), now)
            ]
            for ev in evidences:
                cursor.execute("""
                INSERT OR REPLACE INTO evidence_records (
                    id, investigation_id, user_id, event_id, sha256_hash, merkle_root,
                    is_verified, raw_log, supporting_facts, contradictory_facts, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, ev)

            # 7. Investigation Notes
            notes = [
                (f"NOTE-{u_suffix}-01", inv1_id, target_user_id, "Cmdr. Maya Thorne", "Initial Ingress Triage & Patient Zero Identification", "Observed external IP 185.220.101.47 authenticating via employee portal from known TOR exit relay. Active session issued to emp_rohan without MFA challenge.", now),
                (f"NOTE-{u_suffix}-02", inv1_id, target_user_id, "Lt. Alex Chen", "Host Subnet Isolation for wkst-04-dev", "Developer host wkst-04-dev spawned encoded PowerShell script executing Invoke-Mimikatz against LSASS memory. Isolated host subnet egress.", now),
                (f"NOTE-{u_suffix}-03", inv1_id, target_user_id, "Sgt. Elena Rostova", "Perimeter Firewall Block Applied for 185.220.101.47", "Outbound TCP connection to 198.51.100.23 on port 443 blocked at perimeter firewall. Stolen database dump contained in quarantine zone.", now)
            ]
            for n in notes:
                cursor.execute("""
                INSERT OR REPLACE INTO investigation_notes (
                    id, investigation_id, user_id, author_name, title, content, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """, n)

            # 8. Deception Events
            deceptions = [
                (f"DEC-{u_suffix}-01", inv1_id, target_user_id, "Cowrie SSH Decoy", "185.220.101.47", "cowrie-ssh-dmz", "2026-03-31T01:14:12Z", "uname -a", "CRITICAL", now),
                (f"DEC-{u_suffix}-02", inv1_id, target_user_id, "Cowrie SSH Decoy", "185.220.101.47", "cowrie-ssh-dmz", "2026-03-31T01:14:38Z", "cat /etc/shadow", "CRITICAL", now),
                (f"DEC-{u_suffix}-03", inv1_id, target_user_id, "OpenCanary MySQL", "10.0.8.24", "db-canary-01", "2026-03-31T01:18:22Z", "SELECT * FROM users_admin", "HIGH", now),
                (f"DEC-{u_suffix}-04", inv1_id, target_user_id, "OpenCanary AWS Bait", "185.220.101.47", "aws-decoy-bucket", "2026-03-31T01:21:05Z", "GET /credentials/backup.enc", "CRITICAL", now)
            ]
            for d in deceptions:
                cursor.execute("""
                INSERT OR REPLACE INTO deception_events (
                    id, investigation_id, user_id, sensor_type, src_ip, target_decoy,
                    trigger_timestamp, payload, severity, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, d)

            # 9. Investigation Reports
            reports = [
                (f"REP-{u_suffix}-01", inv1_id, target_user_id, "markdown", "Executive Cyber Incident Briefing (NIST SP 800-61 Rev 2)", "# NIST SP 800-61 Rev 2 Incident Briefing\n\n## Summary\nCritical unauthorized external ingress detected from 185.220.101.47 targeting production database cluster.\n\n## Recommendations\n1. Enforce FIDO2 WebAuthn MFA\n2. Block IP 185.220.101.47\n3. Rotate CI/CD deploy tokens.", now),
                (f"REP-{u_suffix}-02", inv1_id, target_user_id, "json", "Technical Incident Data Exchange (OASIS STIX 2.1)", json.dumps({"spec_version": "2.1", "type": "bundle", "id": "bundle--8f7a8b9c", "objects_count": 230}), now),
                (f"REP-{u_suffix}-03", inv1_id, target_user_id, "csv", "Full CIRT Forensic Evidence Ledger Export", "event_id,timestamp,source,target,action,mitre_tag,severity,sha256\nEVT-001,2026-03-31T01:14:02Z,185.220.101.47,vpn.obsyron.corp,EXTERNAL_INGRESS,T1078,CRITICAL,160bce742077ef960056115f3f14a6f840de042fcbb65693cde49436d1f007e0\n", now)
            ]
            for rep in reports:
                cursor.execute("""
                INSERT OR REPLACE INTO investigation_reports (
                    id, investigation_id, user_id, format, title, content, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """, rep)

            conn.commit()

        return {
            "success": True,
            "message": "Forensic demo dataset seeded successfully!",
            "target_user_id": target_user_id,
            "investigations_count": len(demo_invs),
            "telemetry_files_count": len(files),
            "telemetry_events_count": len(events),
            "attack_nodes_count": len(nodes),
            "attack_edges_count": len(edges),
            "evidence_records_count": len(evidences),
            "investigation_notes_count": len(notes),
            "deception_events_count": len(deceptions),
            "investigation_reports_count": len(reports)
        }

    # ── 1. PROFILES & AUTHENTICATION CRUD ─────────────────────────────────────

    def create_profile(self, email: str, password: str, full_name: str,
                       username: Optional[str] = None, role: str = "Forensic Investigator",
                       department: str = "Threat Intelligence CIRT", clearance: str = "Level 3 (Secret)",
                       clearance_code: str = "L3") -> Dict[str, Any]:
        """Creates a new user profile with cryptographically hashed password."""
        email_clean = email.strip().lower()
        uname = (username or email_clean.split("@")[0]).strip().lower()
        now = datetime.now(timezone.utc).isoformat()
        user_id = f"usr_{secrets.token_hex(8)}"
        pwd_hash = hash_password(password)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            # Check duplicate email
            cursor.execute("SELECT id FROM profiles WHERE email = ?", (email_clean,))
            if cursor.fetchone():
                raise ValueError("An operator account with this email address already exists.")

            # Check duplicate username
            cursor.execute("SELECT id FROM profiles WHERE username = ?", (uname,))
            if cursor.fetchone():
                uname = f"{uname}_{secrets.token_hex(3)}"

            cursor.execute("""
            INSERT INTO profiles (
                id, email, username, password_hash, full_name, role,
                department, clearance, clearance_code, avatar, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                user_id, email_clean, uname, pwd_hash, full_name.strip(),
                role, department, clearance, clearance_code, "🛡️", now, now
            ))

            # Seed an active default investigation for the new user
            inv_id = f"OBS-INV-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{secrets.token_hex(3)}"
            cursor.execute("""
            INSERT INTO investigations (
                id, user_id, name, description, severity, status,
                dataset_name, raw_log_count, malicious_signal_count,
                initial_access_entity, initial_access_tactic, blast_radius_count,
                overall_confidence, nodes_count, edges_count, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                inv_id,
                user_id,
                f"Incident Triage #{secrets.token_hex(2).upper()}",
                "Initial investigation container initialized for operator evidence capture.",
                "HIGH",
                "ACTIVE",
                "Baseline Ingestion Stream",
                0, 0, "Unknown", "Awaiting Ingestion", 0, 0.95, 0, 0, now, now
            ))

            conn.commit()

        # Seed full realistic forensic demo dataset for new operator
        self.seed_complete_forensic_demo_data(user_id)

        return self.get_profile_by_id(user_id)

    def authenticate_user(self, email_or_username: str, password: str) -> Optional[Dict[str, Any]]:
        """Verifies credentials and returns user profile if valid."""
        ident = email_or_username.strip().lower()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT * FROM profiles WHERE email = ? OR username = ?
            """, (ident, ident))
            row = cursor.fetchone()
            if not row:
                return None
            profile = dict(row)
            if verify_password(password, profile["password_hash"]):
                profile.pop("password_hash", None)
                return profile
            return None

    def get_profile_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Fetches profile by user ID without password hash."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM profiles WHERE id = ?", (user_id,))
            row = cursor.fetchone()
            if not row:
                return None
            res = dict(row)
            res.pop("password_hash", None)
            return res

    def get_profile_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Fetches profile by email."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM profiles WHERE email = ?", (email.strip().lower(),))
            row = cursor.fetchone()
            if not row:
                return None
            res = dict(row)
            res.pop("password_hash", None)
            return res

    def update_profile(self, user_id: str, full_name: Optional[str] = None,
                       role: Optional[str] = None, department: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Updates user profile information."""
        now = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            updates = []
            params = []
            if full_name:
                updates.append("full_name = ?")
                params.append(full_name.strip())
            if role:
                updates.append("role = ?")
                params.append(role.strip())
            if department:
                updates.append("department = ?")
                params.append(department.strip())

            if not updates:
                return self.get_profile_by_id(user_id)

            updates.append("updated_at = ?")
            params.append(now)
            params.append(user_id)

            cursor.execute(f"UPDATE profiles SET {', '.join(updates)} WHERE id = ?", params)
            conn.commit()
        return self.get_profile_by_id(user_id)

    def update_password(self, user_id: str, old_password: str, new_password: str) -> bool:
        """Verifies old password and changes to new password."""
        if not new_password or len(new_password) < 6:
            raise ValueError("New password must be at least 6 characters.")

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT password_hash FROM profiles WHERE id = ?", (user_id,))
            row = cursor.fetchone()
            if not row:
                return False
            stored = row["password_hash"]
            if not verify_password(old_password, stored):
                raise ValueError("Incorrect current password.")

            new_hash = hash_password(new_password)
            now = datetime.now(timezone.utc).isoformat()
            cursor.execute("UPDATE profiles SET password_hash = ?, updated_at = ? WHERE id = ?", (new_hash, now, user_id))
            conn.commit()
            return True

    # ── 2. INVESTIGATION MANAGEMENT CRUD ──────────────────────────────────────

    def create_investigation(self, user_id: str, name: str, description: str = "",
                             severity: str = "HIGH", dataset_name: str = "Custom Telemetry Ingestion",
                             initial_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Creates a new isolated investigation belonging to the authenticated user."""
        inv_id = f"OBS-INV-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{secrets.token_hex(3)}"
        now = datetime.now(timezone.utc).isoformat()
        init_json = json.dumps(initial_data or {})

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO investigations (
                id, user_id, name, description, severity, status,
                dataset_name, raw_log_count, malicious_signal_count,
                initial_access_entity, initial_access_tactic, blast_radius_count,
                overall_confidence, nodes_count, edges_count, analysis_json,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                inv_id, user_id, name.strip(), description.strip(), severity.upper(),
                "ACTIVE", dataset_name,
                int((initial_data or {}).get("raw_log_count", 0)),
                int((initial_data or {}).get("malicious_signal_count", 0)),
                (initial_data or {}).get("initial_access", {}).get("entity", "Pending Detection"),
                (initial_data or {}).get("initial_access", {}).get("mitre_tactic", "Initial Access"),
                int((initial_data or {}).get("blast_radius", {}).get("count", 0)),
                float((initial_data or {}).get("overall_confidence", 0.95)),
                len((initial_data or {}).get("nodes", [])),
                len((initial_data or {}).get("edges", [])),
                init_json,
                now, now
            ))
            conn.commit()

        return self.get_investigation(inv_id, user_id)

    def list_investigations_by_user(self, user_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Lists all investigations owned by this authenticated user."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT id, user_id, name, description, severity, status, dataset_name,
                   raw_log_count, malicious_signal_count, initial_access_entity,
                   blast_radius_count, overall_confidence, nodes_count, edges_count,
                   created_at, updated_at
            FROM investigations
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT ?
            """, (user_id, limit))
            return [dict(row) for row in cursor.fetchall()]

    def get_investigation(self, investigation_id: str, user_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Retrieves investigation. If user_id provided, ensures user isolation."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if user_id:
                cursor.execute("SELECT * FROM investigations WHERE id = ? AND user_id = ?", (investigation_id, user_id))
            else:
                cursor.execute("SELECT * FROM investigations WHERE id = ?", (investigation_id,))
            row = cursor.fetchone()
            if not row:
                return None
            res = dict(row)
            if res.get("analysis_json"):
                try:
                    res["analysis_json"] = json.loads(res["analysis_json"])
                except Exception:
                    pass
            return res

    def update_investigation(self, investigation_id: str, user_id: str,
                             name: Optional[str] = None, description: Optional[str] = None,
                             severity: Optional[str] = None, status: Optional[str] = None,
                             analysis_data: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """Updates investigation metadata or latest analysis results."""
        now = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            updates = ["updated_at = ?"]
            params = [now]

            if name is not None:
                updates.append("name = ?")
                params.append(name.strip())
            if description is not None:
                updates.append("description = ?")
                params.append(description.strip())
            if severity is not None:
                updates.append("severity = ?")
                params.append(severity.upper())
            if status is not None:
                updates.append("status = ?")
                params.append(status.upper())
            if analysis_data is not None:
                updates.append("analysis_json = ?")
                params.append(json.dumps(analysis_data))
                if "raw_log_count" in analysis_data:
                    updates.append("raw_log_count = ?")
                    params.append(int(analysis_data["raw_log_count"]))
                if "malicious_signal_count" in analysis_data:
                    updates.append("malicious_signal_count = ?")
                    params.append(int(analysis_data["malicious_signal_count"]))
                if "overall_confidence" in analysis_data:
                    updates.append("overall_confidence = ?")
                    params.append(float(analysis_data["overall_confidence"]))
                if "nodes" in analysis_data:
                    updates.append("nodes_count = ?")
                    params.append(len(analysis_data["nodes"]))
                if "edges" in analysis_data:
                    updates.append("edges_count = ?")
                    params.append(len(analysis_data["edges"]))
                ia = analysis_data.get("initial_access") or {}
                if "entity" in ia:
                    updates.append("initial_access_entity = ?")
                    params.append(ia["entity"])
                br = analysis_data.get("blast_radius") or {}
                if "count" in br:
                    updates.append("blast_radius_count = ?")
                    params.append(int(br["count"]))

            params.append(investigation_id)
            params.append(user_id)

            cursor.execute(f"""
            UPDATE investigations
            SET {', '.join(updates)}
            WHERE id = ? AND user_id = ?
            """, params)
            conn.commit()

        return self.get_investigation(investigation_id, user_id)

    def delete_investigation(self, investigation_id: str, user_id: str) -> bool:
        """Deletes investigation and cascades deletion to telemetry and notes."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM investigations WHERE id = ? AND user_id = ?", (investigation_id, user_id))
            deleted = cursor.rowcount > 0
            conn.commit()
            return deleted

    # ── 3. TELEMETRY FILE & EVENT PERSISTENCE ─────────────────────────────────

    def save_telemetry_batch(self, investigation_id: str, user_id: str, filename: str,
                             file_size: int, file_format: str, events: List[Dict[str, Any]],
                             valid_count: int, invalid_count: int, duplicate_count: int) -> str:
        """Saves an uploaded telemetry file and persists all normalized events."""
        file_id = f"FILE-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(3)}"
        now = datetime.now(timezone.utc).isoformat()

        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Record file metadata
            cursor.execute("""
            INSERT INTO telemetry_files (
                id, investigation_id, user_id, filename, file_size, file_format,
                record_count, valid_count, invalid_count, duplicate_count, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                file_id, investigation_id, user_id, filename, file_size, file_format.upper(),
                len(events), valid_count, invalid_count, duplicate_count, now
            ))

            # Batch insert parsed events
            event_records = []
            for idx, e in enumerate(events):
                eid = e.get("log_id") or f"EVT-{file_id}-{idx+1}"
                event_records.append((
                    eid,
                    file_id,
                    investigation_id,
                    user_id,
                    e.get("raw_timestamp", now),
                    e.get("normalized_timestamp", now),
                    e.get("host") or e.get("source_host") or "unknown",
                    e.get("entity_type", "DEVICE"),
                    e.get("source", "unknown"),
                    e.get("target", "unknown"),
                    e.get("action", "TRAFFIC"),
                    e.get("mitre_tag", ""),
                    e.get("severity", "LOW"),
                    float(e.get("confidence", 0.7)),
                    1 if e.get("is_malicious") else 0,
                    json.dumps(e.get("raw_payload", {})),
                    e.get("sha256_hash", ""),
                    now
                ))

            cursor.executemany("""
            INSERT OR REPLACE INTO telemetry_events (
                id, file_id, investigation_id, user_id, raw_timestamp,
                normalized_timestamp, host, entity_type, source, target, action,
                mitre_tag, severity, confidence, is_malicious, raw_payload,
                sha256_hash, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, event_records)

            # Update investigation counts
            cursor.execute("""
            UPDATE investigations
            SET raw_log_count = raw_log_count + ?,
                updated_at = ?
            WHERE id = ? AND user_id = ?
            """, (valid_count, now, investigation_id, user_id))

            conn.commit()

        return file_id

    def get_investigation_events(self, investigation_id: str, user_id: Optional[str] = None,
                                 limit: int = 500) -> List[Dict[str, Any]]:
        """Retrieves raw/normalized events for an investigation."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if user_id:
                cursor.execute("""
                SELECT * FROM telemetry_events
                WHERE investigation_id = ? AND user_id = ?
                ORDER BY normalized_timestamp ASC
                LIMIT ?
                """, (investigation_id, user_id, limit))
            else:
                cursor.execute("""
                SELECT * FROM telemetry_events
                WHERE investigation_id = ?
                ORDER BY normalized_timestamp ASC
                LIMIT ?
                """, (investigation_id, limit))

            rows = cursor.fetchall()
            result = []
            for r in rows:
                item = dict(r)
                if item.get("raw_payload"):
                    try:
                        item["raw_payload"] = json.loads(item["raw_payload"])
                    except Exception:
                        pass
                result.append(item)
            return result

    # ── 4. INVESTIGATION NOTES & COLLABORATION ────────────────────────────────

    def add_investigation_note(self, investigation_id: str, user_id: str,
                               author_name: str, title: str, content: str) -> Dict[str, Any]:
        """Appends a forensic analyst note to the investigation case file."""
        note_id = f"NOTE-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(2)}"
        now = datetime.now(timezone.utc).isoformat()

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO investigation_notes (
                id, investigation_id, user_id, author_name, title, content, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (note_id, investigation_id, user_id, author_name.strip(), title.strip(), content.strip(), now))
            conn.commit()

        return {
            "id": note_id,
            "investigation_id": investigation_id,
            "author_name": author_name,
            "title": title,
            "content": content,
            "created_at": now
        }

    def get_investigation_notes(self, investigation_id: str, user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Lists all analyst notes recorded for this investigation."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if user_id:
                cursor.execute("""
                SELECT * FROM investigation_notes
                WHERE investigation_id = ? AND user_id = ?
                ORDER BY created_at DESC
                """, (investigation_id, user_id))
            else:
                cursor.execute("""
                SELECT * FROM investigation_notes
                WHERE investigation_id = ?
                ORDER BY created_at DESC
                """, (investigation_id,))
            return [dict(row) for row in cursor.fetchall()]

    # ── 5. INVESTIGATION REPORTS & EXPORTS ────────────────────────────────────

    def save_investigation_report(self, investigation_id: str, user_id: str,
                                  format_type: str, title: str, content: str) -> str:
        """Saves generated report artifact (JSON, CSV, Markdown, PDF text)."""
        report_id = f"RPT-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(2)}"
        now = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO investigation_reports (
                id, investigation_id, user_id, format, title, content, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (report_id, investigation_id, user_id, format_type.upper(), title, content, now))
            conn.commit()
        return report_id

    def get_investigation_reports(self, investigation_id: str, user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieves history of generated reports for this case."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if user_id:
                cursor.execute("""
                SELECT id, investigation_id, format, title, created_at
                FROM investigation_reports
                WHERE investigation_id = ? AND user_id = ?
                ORDER BY created_at DESC
                """, (investigation_id, user_id))
            else:
                cursor.execute("""
                SELECT id, investigation_id, format, title, created_at
                FROM investigation_reports
                WHERE investigation_id = ?
                ORDER BY created_at DESC
                """, (investigation_id,))
            return [dict(row) for row in cursor.fetchall()]

    def get_attack_nodes(self, investigation_id: str, user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieves attack nodes from database."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if user_id:
                cursor.execute("SELECT * FROM attack_nodes WHERE investigation_id = ? AND user_id = ?", (investigation_id, user_id))
            else:
                cursor.execute("SELECT * FROM attack_nodes WHERE investigation_id = ?", (investigation_id,))
            rows = [dict(r) for r in cursor.fetchall()]
            for r in rows:
                if r.get("mitre_tags"):
                    try:
                        r["mitre_tags"] = json.loads(r["mitre_tags"])
                    except Exception:
                        pass
            return rows

    def get_attack_edges(self, investigation_id: str, user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieves directed attack edges from database."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if user_id:
                cursor.execute("SELECT * FROM attack_edges WHERE investigation_id = ? AND user_id = ?", (investigation_id, user_id))
            else:
                cursor.execute("SELECT * FROM attack_edges WHERE investigation_id = ?", (investigation_id,))
            return [dict(r) for r in cursor.fetchall()]

    def get_evidence_records(self, investigation_id: str, user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieves SHA-256 Merkle evidence records from database."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if user_id:
                cursor.execute("SELECT * FROM evidence_records WHERE investigation_id = ? AND user_id = ? ORDER BY created_at ASC", (investigation_id, user_id))
            else:
                cursor.execute("SELECT * FROM evidence_records WHERE investigation_id = ? ORDER BY created_at ASC", (investigation_id,))
            rows = [dict(r) for r in cursor.fetchall()]
            for r in rows:
                for k in ("supporting_facts", "contradictory_facts"):
                    if r.get(k):
                        try:
                            r[k] = json.loads(r[k])
                        except Exception:
                            pass
            return rows

    def get_deception_events(self, investigation_id: Optional[str] = None, user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieves honeypot deception events from database."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM deception_events WHERE 1=1"
            params = []
            if investigation_id:
                query += " AND investigation_id = ?"
                params.append(investigation_id)
            if user_id:
                query += " AND user_id = ?"
                params.append(user_id)
            query += " ORDER BY trigger_timestamp DESC"
            cursor.execute(query, tuple(params))
            return [dict(r) for r in cursor.fetchall()]

    # ── 6. LIVE DASHBOARD STATISTICS (CALCULATED FROM DB) ─────────────────────

    def get_user_dashboard_stats(self, user_id: str) -> Dict[str, Any]:
        """Calculates live, non-hardcoded dashboard metrics directly from user records."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # 1. Total Investigations
            cursor.execute("SELECT count(*) as total FROM investigations WHERE user_id = ?", (user_id,))
            total_inv = cursor.fetchone()["total"]

            # 2. Total Telemetry Events (Calculated across telemetry records & investigations)
            cursor.execute("SELECT count(*) as total FROM telemetry_events WHERE user_id = ?", (user_id,))
            te_count = cursor.fetchone()["total"]
            cursor.execute("SELECT COALESCE(SUM(raw_log_count), 0) as total FROM investigations WHERE user_id = ?", (user_id,))
            inv_log_count = cursor.fetchone()["total"]
            total_events = max(te_count, inv_log_count)

            # 3. Active Incidents
            cursor.execute("SELECT count(*) as active FROM investigations WHERE user_id = ? AND status != 'RESOLVED'", (user_id,))
            active_incidents = cursor.fetchone()["active"]

            # 4. Critical Findings (Count of critical investigations or malicious signals)
            cursor.execute("""
            SELECT COALESCE(SUM(malicious_signal_count), 0) as crit_signals,
                   count(CASE WHEN severity = 'CRITICAL' THEN 1 END) as crit_invs
            FROM investigations WHERE user_id = ?
            """, (user_id,))
            crit_row = cursor.fetchone()
            crit_findings = (crit_row["crit_signals"] or 0) + (crit_row["crit_invs"] or 0)

            # 5. Recent Investigations (latest 5)
            cursor.execute("""
            SELECT id, name, description, severity, status, initial_access_entity,
                   blast_radius_count, overall_confidence, raw_log_count, created_at
            FROM investigations
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT 5
            """, (user_id,))
            recent_invs = [dict(r) for r in cursor.fetchall()]

            # 6. Recent Activity Feed
            activities = []
            for inv in recent_invs[:3]:
                activities.append({
                    "type": "INVESTIGATION",
                    "title": f"Investigation Active: {inv['name']}",
                    "detail": f"Severity {inv['severity']} • Initial Access: {inv['initial_access_entity']}",
                    "timestamp": inv["created_at"]
                })

            cursor.execute("""
            SELECT filename, file_format, record_count, created_at
            FROM telemetry_files
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT 3
            """, (user_id,))
            for f in cursor.fetchall():
                activities.append({
                    "type": "UPLOAD",
                    "title": f"Telemetry Ingestion: {f['filename']}",
                    "detail": f"{f['record_count']} events imported ({f['file_format']})",
                    "timestamp": f["created_at"]
                })

            # Notes in recent activity
            cursor.execute("""
            SELECT title, author_name, created_at
            FROM investigation_notes
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT 3
            """, (user_id,))
            for n in cursor.fetchall():
                activities.append({
                    "type": "NOTE",
                    "title": f"CIRT Note: {n['title']}",
                    "detail": f"Logged by {n['author_name']}",
                    "timestamp": n["created_at"]
                })

            # Deception alerts in recent activity
            cursor.execute("""
            SELECT sensor_type, src_ip, payload, created_at
            FROM deception_events
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT 3
            """, (user_id,))
            for d in cursor.fetchall():
                activities.append({
                    "type": "DECEPTION",
                    "title": f"Honeypot Trigger: {d['sensor_type']}",
                    "detail": f"Attacker {d['src_ip']} executed '{d['payload']}'",
                    "timestamp": d["created_at"]
                })

            activities.sort(key=lambda a: a.get("timestamp", ""), reverse=True)

            return {
                "total_investigations": total_inv,
                "total_telemetry_events": total_events,
                "active_incidents": active_incidents,
                "critical_findings": crit_findings,
                "recent_investigations": recent_invs,
                "recent_activity": activities[:6]
            }

    # ── 7. LEGACY METHODS (BACKWARD COMPATIBILITY) ────────────────────────────

    def save_investigation(self, data: Dict[str, Any], investigation_id: Optional[str] = None) -> bool:
        """Legacy helper for backward compatibility."""
        user_id = data.get("user_id") or "usr_maya_thorne"
        inv_id = investigation_id or data.get("active_investigation_id") or f"OBS-INV-{datetime.now(timezone.utc).strftime('%Y%m%d')}-001"
        ia = data.get("initial_access") or {}
        br = data.get("blast_radius") or {}
        now = datetime.now(timezone.utc).isoformat()

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO investigations (
                id, user_id, name, description, severity, status, dataset_name,
                raw_log_count, malicious_signal_count, initial_access_entity,
                initial_access_tactic, blast_radius_count, overall_confidence,
                nodes_count, edges_count, analysis_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                status = excluded.status,
                raw_log_count = excluded.raw_log_count,
                malicious_signal_count = excluded.malicious_signal_count,
                initial_access_entity = excluded.initial_access_entity,
                blast_radius_count = excluded.blast_radius_count,
                overall_confidence = excluded.overall_confidence,
                nodes_count = excluded.nodes_count,
                edges_count = excluded.edges_count,
                analysis_json = excluded.analysis_json,
                updated_at = excluded.updated_at
            """, (
                inv_id,
                user_id,
                data.get("name") or f"Investigation {inv_id}",
                data.get("description") or "Automated attack graph reconstruction.",
                data.get("severity") or "CRITICAL",
                "ACTIVE",
                data.get("dataset_name", "Enterprise Telemetry APT29"),
                int(data.get("raw_log_count", 0)),
                int(data.get("malicious_signal_count", 0)),
                ia.get("entity", "185.220.101.47"),
                ia.get("mitre_tactic", "Initial Access"),
                int(br.get("count", 0)),
                float(data.get("overall_confidence", 0.0)),
                len(data.get("nodes", [])),
                len(data.get("edges", [])),
                json.dumps(data),
                now, now
            ))
            conn.commit()
            return True

    def list_investigations(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Legacy helper."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT id, name, created_at, status, dataset_name, raw_log_count,
                   malicious_signal_count, initial_access_entity, blast_radius_count, overall_confidence
            FROM investigations
            ORDER BY created_at DESC
            LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def save_audit_logs(self, logs: List[Dict[str, Any]]) -> int:
        """Legacy audit log saver."""
        if not logs:
            return 0
        with self._get_connection() as conn:
            cursor = conn.cursor()
            now = datetime.now(timezone.utc).isoformat()
            records = [
                (
                    l.get("log_id") or f"LOG-{idx}",
                    l.get("raw_timestamp", now),
                    l.get("normalized_timestamp", now),
                    l.get("host", "unknown"),
                    l.get("entity_type", "DEVICE"),
                    l.get("source", "unknown"),
                    l.get("target", "unknown"),
                    l.get("action", "TRAFFIC"),
                    l.get("mitre_tag", ""),
                    l.get("severity", "LOW"),
                    float(l.get("confidence", 0.7)),
                    1 if l.get("is_malicious") else 0,
                    json.dumps(l.get("raw_payload", {})),
                    now
                )
                for idx, l in enumerate(logs)
            ]
            cursor.executemany("""
            INSERT OR REPLACE INTO audit_logs (
                log_id, raw_timestamp, normalized_timestamp, host, entity_type,
                source, target, action, mitre_tag, severity, confidence,
                is_malicious, raw_payload, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, records)
            conn.commit()
            return len(records)

    def save_containment_action(self, action: Dict[str, Any]) -> bool:
        """Legacy containment saver."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT OR REPLACE INTO containment_actions (
                action_id, investigation_id, entity_id, action_type,
                status, executed_at, operator, impact
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                action.get("action_id") or f"ACT-{datetime.now(timezone.utc).strftime('%H%M%S')}",
                action.get("investigation_id", "OBS-INV-20261114-001"),
                action.get("entity_id", "unknown"),
                action.get("action_type", "ISOLATION"),
                action.get("status", "EXECUTED"),
                action.get("executed_at") or datetime.now(timezone.utc).isoformat(),
                action.get("operator", "Cmdr. Maya Thorne"),
                action.get("impact", "")
            ))
            conn.commit()
            return True

    def get_containment_actions(self) -> List[Dict[str, Any]]:
        """Legacy containment retriever."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM containment_actions ORDER BY executed_at DESC")
            return [dict(row) for row in cursor.fetchall()]


# Singleton instance
sqlite_storage = SQLiteStorage()
