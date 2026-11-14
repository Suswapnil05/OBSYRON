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
        """Seeds default operator accounts with securely hashed passwords."""
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

                # Seed an initial default investigation for Maya Thorne if none exists
                cursor.execute("SELECT count(*) as cnt FROM investigations WHERE user_id = ?", (u["id"],))
                cnt = cursor.fetchone()["cnt"]
                if cnt == 0 and u["id"] == "usr_maya_thorne":
                    cursor.execute("""
                    INSERT INTO investigations (
                        id, user_id, name, description, severity, status,
                        dataset_name, raw_log_count, malicious_signal_count,
                        initial_access_entity, initial_access_tactic, blast_radius_count,
                        overall_confidence, nodes_count, edges_count, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        "OBS-INV-20261114-001",
                        u["id"],
                        "Operation Red Relic (APT29 Infiltration)",
                        "Autonomous multi-stage intrusion reconstruction originating from TOR exit relay targeting CI/CD credentials.",
                        "CRITICAL",
                        "ACTIVE",
                        "Enterprise Telemetry APT29",
                        357,
                        7,
                        "185.220.101.47",
                        "Valid Accounts (T1078)",
                        15,
                        0.944,
                        29,
                        357,
                        now,
                        now
                    ))
            conn.commit()

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

    # ── 6. LIVE DASHBOARD STATISTICS (CALCULATED FROM DB) ─────────────────────

    def get_user_dashboard_stats(self, user_id: str) -> Dict[str, Any]:
        """Calculates live, non-hardcoded dashboard metrics directly from user records."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # 1. Total Investigations
            cursor.execute("SELECT count(*) as total FROM investigations WHERE user_id = ?", (user_id,))
            total_inv = cursor.fetchone()["total"]

            # 2. Total Telemetry Events
            cursor.execute("SELECT count(*) as total FROM telemetry_events WHERE user_id = ?", (user_id,))
            total_events = cursor.fetchone()["total"]
            # Fallback if no telemetry_events yet, sum raw_log_count from investigations
            if total_events == 0:
                cursor.execute("SELECT COALESCE(SUM(raw_log_count), 0) as total FROM investigations WHERE user_id = ?", (user_id,))
                total_events = cursor.fetchone()["total"]

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
