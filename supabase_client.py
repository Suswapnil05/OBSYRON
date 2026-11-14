"""
OBSYRON XTM 2.0 — Supabase PostgreSQL Integration Client
Engineered for HackInnovision 2026 (Track C)

Connects OBSYRON with Supabase (https://ugkekxiwvgsitzqduzxq.supabase.co)
Uses Python's standard library urllib + ssl to guarantee 100% dependency-free
execution in local-first, containerized, and Vercel serverless environments.
"""

import os
import json
import ssl
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import urllib.request
import urllib.error

logger = logging.getLogger("obsyron.supabase")

# Default Project Endpoint specified by operator
DEFAULT_SUPABASE_URL = "https://ugkekxiwvgsitzqduzxq.supabase.co"


class SupabaseClient:
    def __init__(self, url: Optional[str] = None, key: Optional[str] = None):
        self.url = (url or os.environ.get("SUPABASE_URL") or DEFAULT_SUPABASE_URL).rstrip("/")
        self.key = key or os.environ.get("SUPABASE_KEY") or os.environ.get("SUPABASE_ANON_KEY") or ""
        self._ctx = ssl.create_default_context()

    def set_key(self, key: str):
        """Update API key dynamically at runtime."""
        self.key = (key or "").strip()

    @property
    def is_configured(self) -> bool:
        """Returns True if both URL and Key are provided."""
        return bool(self.url and self.key)

    @property
    def project_ref(self) -> str:
        """Extracts the project reference subdomain."""
        try:
            return self.url.split("//")[1].split(".")[0]
        except Exception:
            return "ugkekxiwvgsitzqduzxq"

    def _headers(self, prefer: Optional[str] = None) -> Dict[str, str]:
        headers = {
            "apikey": self.key,
            "Authorization": f"Bearer {self.key}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        if prefer:
            headers["Prefer"] = prefer
        return headers

    def _request(self, method: str, endpoint: str, data: Optional[Any] = None, prefer: Optional[str] = None) -> Dict[str, Any]:
        """Performs an authenticated HTTPS request to Supabase PostgREST."""
        if not self.is_configured:
            return {"success": False, "status": 0, "error": "Supabase API key not configured"}

        url = f"{self.url}/rest/v1/{endpoint.lstrip('/')}"
        payload = json.dumps(data).encode("utf-8") if data is not None else None
        headers = self._headers(prefer=prefer)

        req = urllib.request.Request(url, data=payload, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, context=self._ctx, timeout=8) as response:
                status_code = response.status
                body = response.read().decode("utf-8")
                res_data = json.loads(body) if body else {}
                return {
                    "success": 200 <= status_code < 300,
                    "status": status_code,
                    "data": res_data
                }
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8") if e.fp else ""
            try:
                err_json = json.loads(err_body)
            except Exception:
                err_json = {"message": err_body}
            logger.warning(f"Supabase HTTP {e.code} on {method} {endpoint}: {err_body}")
            return {
                "success": False,
                "status": e.code,
                "error": err_json.get("message") or err_json.get("hint") or str(e),
                "details": err_json
            }
        except Exception as ex:
            logger.error(f"Supabase network error: {ex}")
            return {
                "success": False,
                "status": 500,
                "error": f"Network error connecting to Supabase: {str(ex)}"
            }

    def check_connection(self) -> Dict[str, Any]:
        """Probes Supabase project connectivity and validates authorization."""
        if not self.url:
            return {
                "connected": False,
                "configured": False,
                "url": DEFAULT_SUPABASE_URL,
                "project_ref": self.project_ref,
                "message": "Supabase URL is missing"
            }

        if not self.key:
            # Probe without key to check network reachability
            try:
                probe_req = urllib.request.Request(f"{self.url}/rest/v1/", headers={"Accept": "application/json"})
                with urllib.request.urlopen(probe_req, context=self._ctx, timeout=5) as res:
                    pass
            except urllib.error.HTTPError as he:
                if he.code == 401:
                    return {
                        "connected": True,
                        "configured": False,
                        "authenticated": False,
                        "url": self.url,
                        "project_ref": self.project_ref,
                        "message": "Supabase host reached (401). API Key (anon/service_role) required to authenticate."
                    }
            except Exception as e:
                return {
                    "connected": False,
                    "configured": False,
                    "authenticated": False,
                    "url": self.url,
                    "project_ref": self.project_ref,
                    "message": f"Host unreachable: {str(e)}"
                }

            return {
                "connected": True,
                "configured": False,
                "authenticated": False,
                "url": self.url,
                "project_ref": self.project_ref,
                "message": "Host reachable. Supabase API Key needed."
            }

        # Try fetching investigations table count with API key
        res = self._request("GET", "investigations?select=id&limit=1", prefer="count=exact")
        if res.get("success"):
            return {
                "connected": True,
                "configured": True,
                "authenticated": True,
                "url": self.url,
                "project_ref": self.project_ref,
                "message": f"Supabase live & authenticated on project [{self.project_ref}]."
            }
        elif res.get("status") == 404:
            return {
                "connected": True,
                "configured": True,
                "authenticated": True,
                "schema_missing": True,
                "url": self.url,
                "project_ref": self.project_ref,
                "message": "Authenticated successfully, but tables not yet created. Run supabase_schema.sql in SQL Editor."
            }
        else:
            return {
                "connected": False,
                "configured": True,
                "authenticated": False,
                "status": res.get("status"),
                "url": self.url,
                "project_ref": self.project_ref,
                "error": res.get("error", "Authentication error"),
                "message": f"Supabase auth rejected ({res.get('status')}): {res.get('error')}"
            }

    def save_investigation(self, data: Dict[str, Any], investigation_id: Optional[str] = None) -> Dict[str, Any]:
        """Saves or updates an investigation record in Supabase."""
        if not self.is_configured:
            return {"success": False, "error": "Supabase not configured"}

        inv_id = investigation_id or data.get("active_investigation_id") or f"OBS-INV-{datetime.now(timezone.utc).strftime('%Y%m%d')}-001"
        ia = data.get("initial_access") or {}
        br = data.get("blast_radius") or {}

        record = {
            "id": inv_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": "COMPLETED",
            "dataset_name": data.get("dataset_name", "Enterprise Telemetry APT29"),
            "raw_log_count": int(data.get("raw_log_count", 0)),
            "malicious_signal_count": int(data.get("malicious_signal_count", 0)),
            "initial_access_entity": ia.get("entity", "Unknown"),
            "initial_access_tactic": ia.get("mitre_tactic", "Initial Access"),
            "blast_radius_count": int(br.get("count", 0)),
            "overall_confidence": float(data.get("overall_confidence", 0.0)),
            "nodes_count": len(data.get("nodes", [])),
            "edges_count": len(data.get("edges", [])),
            "analysis_payload": {
                "initial_access": ia,
                "blast_radius": br,
                "xai_report": data.get("xai_report", []),
                "overall_confidence": data.get("overall_confidence", 0.0),
                "malicious_nodes": [n["id"] for n in data.get("nodes", []) if n.get("is_malicious")],
                "timeline_min": data.get("timeline_min"),
                "timeline_max": data.get("timeline_max")
            }
        }

        # Upsert into 'investigations' table
        return self._request(
            "POST",
            "investigations",
            data=record,
            prefer="resolution=merge-duplicates,return=representation"
        )

    def list_investigations(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Retrieves list of past forensic investigations from Supabase."""
        if not self.is_configured:
            return []

        res = self._request("GET", f"investigations?select=*&order=created_at.desc&limit={limit}")
        if res.get("success") and isinstance(res.get("data"), list):
            return res["data"]
        return []

    def save_audit_logs(self, logs: List[Dict[str, Any]], limit: int = 200) -> Dict[str, Any]:
        """Saves a batch of normalized audit logs to Supabase."""
        if not self.is_configured or not logs:
            return {"success": False, "count": 0}

        records = []
        for log in logs[:limit]:
            records.append({
                "log_id": log.get("log_id") or f"LOG-{datetime.now(timezone.utc).timestamp()}",
                "raw_timestamp": log.get("raw_timestamp"),
                "normalized_timestamp": log.get("normalized_timestamp"),
                "host": log.get("host", "unknown"),
                "entity_type": log.get("entity_type", "GENERIC"),
                "source": log.get("source", "unknown"),
                "target": log.get("target", "unknown"),
                "action": log.get("action", "TRAFFIC"),
                "mitre_tag": log.get("mitre_tag", ""),
                "severity": log.get("severity", "LOW"),
                "confidence": float(log.get("confidence", 0.7)),
                "is_malicious": bool(log.get("is_malicious", False)),
                "raw_payload": log.get("raw_payload", {})
            })

        return self._request(
            "POST",
            "audit_logs",
            data=records,
            prefer="resolution=merge-duplicates,return=minimal"
        )

    def save_containment_action(self, action: Dict[str, Any]) -> Dict[str, Any]:
        """Records an executed defensive containment measure to Supabase."""
        if not self.is_configured:
            return {"success": False, "error": "Supabase not configured"}

        record = {
            "action_id": action.get("action_id") or f"ACT-{datetime.now(timezone.utc).strftime('%H%M%S')}",
            "investigation_id": action.get("investigation_id", "OBS-INV-20261114-001"),
            "entity_id": action.get("entity_id", "unknown"),
            "action_type": action.get("action_type", "ISOLATION"),
            "status": action.get("status", "EXECUTED"),
            "executed_at": action.get("executed_at") or datetime.now(timezone.utc).isoformat(),
            "operator": action.get("operator", "Cmdr. Maya Thorne"),
            "impact": action.get("impact", "")
        }

        return self._request(
            "POST",
            "containment_actions",
            data=record,
            prefer="resolution=merge-duplicates,return=representation"
        )

    def sync_operator_profile(self, operator: Dict[str, Any]) -> Dict[str, Any]:
        """Synchronizes an authenticated operator's identity and clearance to Supabase."""
        if not self.is_configured:
            return {"success": False, "error": "Supabase not configured"}

        record = {
            "username": operator.get("username", "analyst_lead"),
            "name": operator.get("name", "Unknown Operator"),
            "role": operator.get("role", "Field Forensic Specialist"),
            "clearance": operator.get("clearance", "Level 3"),
            "clearance_code": operator.get("clearance_code", "L3"),
            "mfa_verified": bool(operator.get("mfa_verified", True)),
            "department": operator.get("department", "Incident Response")
        }

        return self._request(
            "POST",
            "operators",
            data=record,
            prefer="resolution=merge-duplicates,return=representation"
        )


# Singleton instance
supabase_client = SupabaseClient()

