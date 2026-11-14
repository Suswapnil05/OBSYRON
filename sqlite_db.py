"""
OBSYRON XTM 2.0 — SQLite Investigation Storage Engine
Provides zero-configuration, durable local persistence for forensic investigations,
audit logs, operator profiles, and containment action audit trails.
"""

import os
import sqlite3
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

if os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
    default_db = "/tmp/obsyron.db"
else:
    default_db = os.path.join(os.path.dirname(os.path.abspath(__file__)), "obsyron.db")

DB_FILE = os.environ.get("SQLITE_DB_PATH", default_db)


class SQLiteStorage:
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or DB_FILE
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Initializes SQLite schema for investigations, logs, operators, and containment."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # 1. Investigations Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS investigations (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                status TEXT DEFAULT 'COMPLETED',
                dataset_name TEXT DEFAULT 'Enterprise Telemetry APT29',
                raw_log_count INTEGER DEFAULT 0,
                malicious_signal_count INTEGER DEFAULT 0,
                initial_access_entity TEXT,
                initial_access_tactic TEXT,
                blast_radius_count INTEGER DEFAULT 0,
                overall_confidence REAL DEFAULT 0.0,
                nodes_count INTEGER DEFAULT 0,
                edges_count INTEGER DEFAULT 0,
                analysis_json TEXT
            )
            """)

            # 2. Audit Logs Table
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

            # 3. Operators Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS operators (
                username TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                role TEXT,
                clearance TEXT,
                clearance_code TEXT,
                mfa_verified INTEGER DEFAULT 1,
                department TEXT,
                created_at TEXT
            )
            """)

            # 4. Containment Actions Table
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

    def save_investigation(self, data: Dict[str, Any], investigation_id: Optional[str] = None) -> bool:
        """Saves or updates an investigation record in SQLite."""
        inv_id = investigation_id or data.get("active_investigation_id") or f"OBS-INV-{datetime.now(timezone.utc).strftime('%Y%m%d')}-001"
        ia = data.get("initial_access") or {}
        br = data.get("blast_radius") or {}

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO investigations (
                id, created_at, status, dataset_name, raw_log_count,
                malicious_signal_count, initial_access_entity, initial_access_tactic,
                blast_radius_count, overall_confidence, nodes_count, edges_count, analysis_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                status = excluded.status,
                raw_log_count = excluded.raw_log_count,
                malicious_signal_count = excluded.malicious_signal_count,
                initial_access_entity = excluded.initial_access_entity,
                blast_radius_count = excluded.blast_radius_count,
                overall_confidence = excluded.overall_confidence,
                nodes_count = excluded.nodes_count,
                edges_count = excluded.edges_count,
                analysis_json = excluded.analysis_json
            """, (
                inv_id,
                datetime.now(timezone.utc).isoformat(),
                "COMPLETED",
                data.get("dataset_name", "Enterprise Telemetry APT29"),
                int(data.get("raw_log_count", 0)),
                int(data.get("malicious_signal_count", 0)),
                ia.get("entity", "185.220.101.47"),
                ia.get("mitre_tactic", "Initial Access"),
                int(br.get("count", 0)),
                float(data.get("overall_confidence", 0.0)),
                len(data.get("nodes", [])),
                len(data.get("edges", [])),
                json.dumps(data)
            ))
            conn.commit()
            return True

    def get_investigation(self, investigation_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves an investigation record from SQLite by ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
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

    def list_investigations(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Lists recent investigations sorted by creation date."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, created_at, status, dataset_name, raw_log_count, malicious_signal_count, initial_access_entity, blast_radius_count, overall_confidence FROM investigations ORDER BY created_at DESC LIMIT ?", (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def save_audit_logs(self, logs: List[Dict[str, Any]]) -> int:
        """Batch saves normalized forensic logs to SQLite."""
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
        """Records an executed defensive containment action in SQLite."""
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
        """Retrieves full audit trail of containment actions from SQLite."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM containment_actions ORDER BY executed_at DESC")
            return [dict(row) for row in cursor.fetchall()]


# Singleton instance
sqlite_storage = SQLiteStorage()
