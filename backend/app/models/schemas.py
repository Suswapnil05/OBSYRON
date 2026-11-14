"""
OBSYRON XTM 2.0 — Pydantic Schemas & Data Contracts
"""

from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List


class AnalyzeRequest(BaseModel):
    shuffle: bool = False
    inject_skew: bool = False
    drop_telemetry: bool = False
    drop_rate: float = Field(default=0.15, ge=0.0, le=1.0)


class ExportRequest(BaseModel):
    format: str = "json"  # "json", "csv", "markdown"
    investigation_id: Optional[str] = "OBS-INV-20261114-001"


class ContainmentExecuteRequest(BaseModel):
    action_type: str  # "ISOLATE_HOST", "REVOKE_TOKEN", "BLOCK_IP", "RESET_CREDENTIAL"
    target: str
    operator_name: Optional[str] = "Cmdr. Maya Thorne"
    simulation_mode: Optional[bool] = False
    notes: Optional[str] = ""


class WhatIfRequest(BaseModel):
    isolated_nodes: Optional[List[str]] = None
    severed_edges: Optional[List[Dict[str, str]]] = None


class ScenarioLoadRequest(BaseModel):
    scenario_id: str


class LoginRequest(BaseModel):
    username: str
    password: str
    clearance_override: Optional[str] = None
    mfa_code: Optional[str] = None


class SignupRequest(BaseModel):
    username: str
    password: str
    name: Optional[str] = None
    role: Optional[str] = "Forensic Analyst"
    department: Optional[str] = "Cyber Defense CIRT"
    clearance: Optional[str] = "L3"


class DatabaseConfigRequest(BaseModel):
    supabase_key: Optional[str] = None
    supabase_url: Optional[str] = None
