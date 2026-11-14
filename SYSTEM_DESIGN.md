# OBSYRON XTM 2.0 — System Design

## 1. Design Philosophy

OBSYRON is designed for high-stakes Security Operations Centers where clarity, auditability, and speed are non-negotiable. Its architecture adheres to five foundational tenets:

1. **Evidence-Driven Reasoning:** Every finding, reachability path, or risk assessment must link to an immutable raw audit record. No conclusion is drawn in a vacuum.
2. **Defensive Rigor:** Tools must aid the defender. Containment recommendations guide isolation, session revocation, and boundary firewalls without executing offensive payloads.
3. **Graceful Handling of Chaos:** Enterprise telemetry is noisy, skewed, and lossy. The system must natively reconcile clock drift, out-of-order delivery, and missing audit steps.
4. **Transparent Uncertainty:** Inferred links must be visually and statistically distinguishable from confirmed physical audit logs.
5. **Zero Cloud Lock-in:** Investigations must function in air-gapped environments without mandatory cloud API tokens or external vector databases.

---

## 2. Component Design & Responsibilities

```
                               ┌────────────────────────────────────────────────────────┐
                               │                    OBSYRON XTM 2.0                     │
                               └───────────────────────────┬────────────────────────────┘
                                                           │
               ┌───────────────────────────┬───────────────┴───────────────┬───────────────────────────┐
               │                           │                               │                           │
     ┌─────────▼─────────┐       ┌─────────▼─────────┐           ┌─────────▼─────────┐       ┌─────────▼─────────┐
     │ Ingestion Engine  │       │ Graph Core Engine │           │  Explainable AI   │       │ Incident Reporter │
     │  (ingestor.py)    │       │ (graph_engine.py) │           │ (Evidence Ledger) │       │   (reporter.py)   │
     └─────────┬─────────┘       └─────────┬─────────┘           └─────────┬─────────┘       └─────────┬─────────┘
               │                           │                               │                           │
     • Schema mapping            • MultiDiGraph assembly         • Step-by-step kill chain   • JSON audit export
     • Clock-skew normalizer     • Root cause backward trace     • MITRE ATT&CK mapping      • CSV evidence ledger
     • Out-of-order sorting      • Blast radius forward reach    • Provenance citations      • Markdown briefing
     • Timeline snapshotting     • Centrality pivot scoring      • Gap-bridge heuristics     • Voice audio debrief
```

---

## 3. Data Ingestion & Schema Normalization (`ingestor.py`)

### Canonical Event Schema
All telemetry sources (Windows Security Event Logs, Linux Syslog, Zeek/Suricata network logs, Active Directory LDAP queries, CloudTrail) are normalized into the Canonical Event Schema:

```json
{
  "log_id": "LOG-APT-001",
  "raw_timestamp": "2026-11-14T01:15:12+05:30",
  "true_timestamp": "2026-11-14T01:15:00+05:30",
  "source_host": "wkst-04-dev",
  "host_skew_sec": 12,
  "normalized_timestamp": "2026-11-14T01:15:00+05:30",
  "skew_corrected_sec": -12,
  "entity_type": "USER",
  "source": "185.220.101.47",
  "target": "emp_rohan",
  "action": "AUTH_ANOMALY",
  "protocol": "HTTPS",
  "port": 443,
  "mitre_tag": "T1078",
  "mitre_technique": "T1078 - Valid Accounts (Initial Access)",
  "severity": "CRITICAL",
  "is_malicious": true,
  "raw_payload": "{\"detail\": \"Off-hours login from external IP 185.220.101.47 to wkst-04-dev\"}"
}
```

### Schema Mapping Rules
- `log_id`: Defaults to `UPLOAD-XXXX` if absent.
- `raw_timestamp`: Accepts ISO 8601 strings; defaults to UTC now.
- `source_host` / `host`: Maps from `host`, `hostname`, `source_host`, or `device_name`.
- `source` / `target`: Maps from `src`/`dst`, `source`/`target`, `user`/`host`.
- `entity_type`: Categorized into `USER`, `DEVICE`, `SERVICE`, or `EXTERNAL_ENDPOINT`.

---

## 4. Graph Construction & Multi-Stage Correlation (`graph_engine.py`)

OBSYRON models the enterprise network as a directed multigraph $G = (V, E)$ where:
- $V$ is the set of entities (Users, Workstations, Domain Controllers, Service Accounts, External IPs).
- $E$ is the set of directed edges representing observable interactions (logins, LDAP queries, privilege escalation, SMB sessions, TCP egress).
- Multiple edges can exist between the same pair of nodes (e.g., initial LDAP discovery followed by SMB admin share mounting), preserving temporal fidelity.

### Node Attributes
- `entity_type`: `USER`, `DEVICE`, `SERVICE`, or `EXTERNAL_ENDPOINT`.
- `risk_score`: Privilege-weighted metric ($0.0 \le R \le 1.0$).
- `evidence_count`: Total number of associated raw logs.
- `centrality`: Betweenness centrality score representing pivot criticality.

### Edge Attributes
- `action`: Specific interaction (`AUTH_ANOMALY`, `SESSION_START`, `PRIV_ESC`, `LATERAL_MOVE`, `DATA_EXFIL`, `INFERRED_HOP`).
- `timestamp`: Normalized chronological timestamp $t_{\text{norm}}$.
- `confidence`: Mathematical confidence ($0.0 \le C \le 1.0$).
- `is_inferred`: Boolean flag indicating if edge was observed directly or bridged heuristically.
- `evidence_ids`: List of exact supporting log citations.

---

## 5. Security Architecture & Threat Boundary

- **Air-Gapped Operation:** The platform runs entirely in-memory on the operator's workstation. No log content or metadata is transmitted to external telemetry servers.
- **Role-Based Clearance:** Built-in operator authorization supports multi-level clearance tiers:
  - **L4 (Lead Forensic Director):** Full administrative access, containment simulation, chaos telemetry injection, raw evidence export.
  - **L3 (Senior Incident Responder):** Graph reconstruction, containment execution, chaos simulation.
  - **L2 (Threat Auditor):** Read-only graph analysis, MITRE technique audit, evidence verification.
- **Immutable Provenance:** Investigation findings reference cryptographic SHA-256 digests and audit IDs minted at session initialization.

