# OBSYRON XTM 2.0 — Dataset Documentation & Scenarios

## 1. Overview of Included Datasets

OBSYRON provides 6 pre-configured synthetic scenario datasets located in `sample-data/`:

| Dataset Filename | Records | Malicious Signals | Description | Primary Objective |
|---|---|---|---|---|
| `normal_enterprise_traffic.json` | 200 | 0 | Pure benign enterprise traffic (DNS, HTTPS, internal SMB, mail). | Validates zero-false-positive baseline. |
| `credential_access_t1078.json` | 52 | 2 | T1078 valid accounts anomaly + T1087 account discovery. | Tests early-stage detection & Patient Zero isolation. |
| `privilege_escalation_t1558.json` | 53 | 3 | Ingress + discovery + service account SeDebugPrivilege elevation. | Tests privilege elevation detection. |
| `lateral_movement_t1021.json` | 54 | 4 | Ingress to lateral SMB pivot to database tier. | Evaluates betweenness centrality pivot detection. |
| `exfiltration_c2_t1048.json` | 56 | 6 | Full 6-step APT kill chain through database egress and C2. | Comprehensive end-to-end investigation verification. |
| `dropped_telemetry_gap.json` | 55 | 5 | Kill chain missing `LOG-APT-003` (privilege escalation). | Verifies heuristic gap-bridging and confidence penalty. |

---

## 2. Canonical Schema Field Definitions

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
  "raw_payload": "{...}"
}
```

- **`log_id` (string):** Unique identifier (`LOG-APT-XXX` or `UPLOAD-XXXX`).
- **`raw_timestamp` (string):** ISO 8601 timestamp with clock skew applied.
- **`source_host` (string):** Generating machine identifier (`wkst-04-dev`, `dc-01`, `db-prod-01`).
- **`host_skew_sec` (integer):** Skew delta offset in seconds ($\Delta t_{\text{host}}$).
- **`entity_type` (string):** `USER`, `DEVICE`, `SERVICE`, or `EXTERNAL_ENDPOINT`.
- **`source` / `target` (string):** Directed interaction endpoints.
- **`action` (string):** Event classification token.
- **`protocol` / `port` (string / int):** Network transport metadata.
- **`mitre_tag` (string):** MITRE technique code (`T1078`, `T1087`, `T1558`, `T1021`, `T1048`).
- **`severity` (string):** `INFO`, `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`.
- **`is_malicious` (boolean):** Ground-truth label for evaluation.
- **`raw_payload` (string):** JSON-encoded raw event dictionary.

