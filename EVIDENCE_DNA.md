# OBSYRON XTM 2.0 — Evidence DNA Provenance Ledger

## 1. Provenance Ledger Concept

**Evidence DNA** is OBSYRON's immutable verification mechanism that prevents hallucinations and ensures zero-gap provenance. Every node, path, metric, or statement rendered in the application must cite a verifiable source record in the Evidence DNA ledger.

An Evidence DNA record represents a cryptographic unit of proof:

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
  "raw_payload": "{\"detail\": \"Off-hours login from external IP 185.220.101.47 to wkst-04-dev\", \"geo\": \"TOR exit node\", \"user_agent\": \"Mozilla/5.0\"}",
  "confidence": 0.96,
  "is_inferred": false
}
```

---

## 2. Inferred Gap-Bridge Evidence DNA

When telemetry is dropped due to network partitioning or log evasion, OBSYRON synthesizes an explicit `INFERRED` Evidence DNA record:

```json
{
  "log_id": "INFERRED",
  "raw_timestamp": "2026-11-14T01:18:12+05:30 (Reconstructed from host drift)",
  "normalized_timestamp": "2026-11-14T01:18:00+05:30 (Master Timeline)",
  "skew_corrected_sec": -12,
  "source_host": "wkst-04-dev",
  "host_skew_sec": 12,
  "entity_type": "SERVICE",
  "source": "wkst-04-dev",
  "target": "svc_ci_deploy",
  "action": "INFERRED_LATERAL_BRIDGE",
  "protocol": "RPC / IPC$",
  "port": 135,
  "mitre_tag": "T1558",
  "mitre_technique": "T1558 - Inferred Privilege Escalation Bridge",
  "severity": "HIGH",
  "is_malicious": true,
  "raw_payload": "{\"event\": \"INFERRED_LATERAL_BRIDGE\", \"missing_telemetry\": \"LOG-APT-003 dropped by simulated network congestion / log evasion\", \"heuristic_basis\": \"Adversary LDAP account discovery on wkst-04-dev at 01:16 is followed by svc_ci_deploy lateral movement to db-prod-01 at 01:20. Inferred privilege escalation bridge spans 4-minute window.\", \"confidence_score\": 0.61, \"confidence_penalty\": \"Confidence penalized -34% due to absence of direct OS event audit log.\"}",
  "confidence": 0.61,
  "is_inferred": true
}
```

---

## 3. Evidence Inspection & Audit Export

- **Slide-out Evidence Drawer:** Accessible from any node click, edge selection, or narrative citation badge.
- **Copy JSON:** Exports single evidence record to system clipboard.
- **Export Full CSV:** Downloads RFC 4180 compliant CSV ledger containing every verified event and skew offset.

