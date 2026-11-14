# OBSYRON XTM 2.0 — API Documentation & Reference

All endpoints are dual-bound (`/api/...` and `/...`) to ensure full compatibility across local and serverless reverse proxies.

---

## 1. Primary Investigation Endpoints

### `POST /api/analyze` (and `/analyze`)
Executes full forensic correlation pipeline across logs and generates attack graph, root cause, blast radius, and XAI report.

**Request Body (JSON):**
```json
{
  "shuffle": true,
  "inject_skew": true,
  "drop_telemetry": false,
  "drop_rate": 0.15
}
```

**Response (200 OK):**
```json
{
  "raw_log_count": 356,
  "malicious_signal_count": 6,
  "nodes": [
    {
      "id": "185.220.101.47",
      "label": "185.220.101.47",
      "type": "EXTERNAL_ENDPOINT",
      "centrality": 0.045,
      "log_count": 3
    }
  ],
  "edges": [
    {
      "id": "e_0_185.220.101.47_emp_rohan",
      "source": "185.220.101.47",
      "target": "emp_rohan",
      "action": "AUTH_ANOMALY",
      "protocol": "HTTPS",
      "port": 443,
      "mitre_tag": "T1078",
      "confidence": 0.96,
      "is_inferred": false,
      "timestamp": "2026-11-14T01:15:00+05:30",
      "evidence_id": "LOG-APT-001"
    }
  ],
  "initial_access": {
    "entity": "185.220.101.47",
    "action": "AUTH_ANOMALY",
    "timestamp": "2026-11-14T01:15:00+05:30",
    "evidence_id": "LOG-APT-001"
  },
  "blast_radius": {
    "count": 14,
    "descendants": ["emp_rohan", "wkst-04-dev", "svc_ci_deploy", "db-prod-01"],
    "pivot_entity": "wkst-04-dev"
  },
  "overall_confidence": 0.951,
  "timeline_min": "2026-11-14T01:00:00+05:30",
  "timeline_max": "2026-11-14T01:45:00+05:30",
  "xai_report": [...],
  "snr": "356 Raw Logs → 6 Malicious Signals"
}
```

---

### `GET /api/graph/snapshot` (and `/graph/snapshot`)
Retrieves chronological sub-graph state sliced up to a specific ISO 8601 timestamp.

**Query Parameters:**
- `timestamp` (string, required): ISO 8601 formatted timestamp (e.g., `2026-11-14T01:17:00+05:30`).

**Response (200 OK):**
Returns the complete graph structure and KPIs representing only the events that occurred on or prior to the specified timestamp.

---

### `GET /api/evidence/{log_id}` (and `/evidence/{log_id}`)
Fetches complete Evidence DNA provenance record for a specific log citation.

**Path Parameters:**
- `log_id` (string, required): e.g., `LOG-APT-001` or `INFERRED`.

**Response (200 OK):**
```json
{
  "log_id": "LOG-APT-001",
  "raw_timestamp": "2026-11-14T01:15:12+05:30",
  "normalized_timestamp": "2026-11-14T01:15:00+05:30",
  "skew_corrected_sec": -12,
  "source_host": "wkst-04-dev",
  "host_skew_sec": 12,
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
  "raw_payload": "{\"detail\": \"Off-hours login from external IP 185.220.101.47 to wkst-04-dev\"}",
  "confidence": 0.96,
  "is_inferred": false
}
```

---

### `POST /api/upload` (and `/upload`)
Accepts multi-part file upload of `.json` or `.csv` custom telemetry logs, normalizes them, and runs analysis.

**Form Data:**
- `file` (binary, required): JSON or CSV formatted log file.

---

## 2. Operator Authorization Endpoints

### `GET /api/auth/operators` (and `/auth/operators`)
Lists available pre-configured operator roles and clearance tiers.

### `POST /api/auth/login` (and `/auth/login`)
Authenticates an operator and issues a cryptographic session token.

**Request Body:**
```json
{
  "username": "analyst_lead",
  "password": "obsyron2026",
  "clearance_override": "L4"
}
```

### `POST /api/auth/signup` (and `/auth/signup`)
Registers a new incident responder into the security directory.

### `GET /api/auth/me` (and `/auth/me`)
Validates `Authorization: Bearer <token>` and returns current operator profile.

### `POST /api/auth/logout` (and `/auth/logout`)
Revokes session token and logs terminal disconnect.

---

## 3. Reporting & Export Endpoints

### `GET /api/health` (and `/health`)
Returns service health, version, runtime mode, and cached record counts.

### `GET /api/investigations` (and `/investigations`)
Returns directory of active and historical investigation records.

### `GET /api/investigations/{id}/report` (and `/investigations/{id}/report`)
Generates structured NIST SP 800-61 JSON forensic investigation report.

### `POST /api/reports/export` (and `/reports/export`)
Generates downloadable files in `json`, `csv`, or `markdown` format.

**Request Body:**
```json
{
  "format": "csv",
  "investigation_id": "OBS-INV-20261114-001"
}
```

### `POST /api/briefing/audio` (and `/briefing/audio`)
Returns structured audio debrief script for voice synthesis.

### `POST /api/simulation/reset` (and `/simulation/reset`)
Purges memory cache and restores baseline zero state.
