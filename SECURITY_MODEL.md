# OBSYRON XTM 2.0 — Security Model & Defensive Posture

## 1. Defensive-Only Architectural Scope

OBSYRON is explicitly designed as a **defensive forensic analysis platform**.
- **No Weaponized Payloads:** The software contains no exploits, shellcode, payload generators, network scanners, credential dumpers, or denial-of-service triggers.
- **Simulated Containment Only:** Remediation actions (e.g., host isolation, credential rotation, BGP firewall blackholing) are presented as structured analyst recommendations and simulated playbooks. They do not execute unauthorized changes against production infrastructure.
- **Controlled Telemetry Ingestion:** The system only processes passive event logs. It does not initiate unauthorized port scans or active probes against remote systems.

---

## 2. Threat Boundary & Privacy Guarantees

```
┌────────────────────────────────────────────────────────────────────────┐
│                        DEFENSIVE AIR-GAP BOUNDARY                      │
│                                                                        │
│   ┌─────────────────────┐                   ┌──────────────────────┐   │
│   │   Enterprise Logs   │  ── Ingest ──>   │   OBSYRON Engine     │   │
│   │ (Auth, Syslog, Net) │                   │  (In-Memory NetworkX)│   │
│   └─────────────────────┘                   └──────────┬───────────┘   │
│                                                        │               │
│                                                 CIRT Forensic Findings │
│                                                        ▼               │
│                                             ┌──────────────────────┐   │
│                                             │  SOC Command Cockpit │   │
│                                             │   (Local Viewport)   │   │
│                                             └──────────────────────┘   │
│                                                                        │
│   ❌ ZERO External Telemetry Callbacks                                 │
│   ❌ ZERO Cloud LLM API Exfiltration                                  │
│   ❌ ZERO Third-Party Analytics Tracking                               │
└────────────────────────────────────────────────────────────────────────┘
```

1. **Air-Gapped Operation:** All multigraph calculations, centrality evaluations, and XAI narratives are evaluated locally inside the Python process.
2. **Zero Cloud Telemetry Leakage:** Highly sensitive enterprise data (usernames, internal IP schemes, active directory account names) never leaves the host running the application.
3. **No External LLM Dependencies:** Narrative reasoning is produced through deterministic semantic provenance synthesis anchored to immutable log records, preventing both data exfiltration to cloud AI providers and hallucinations.

---

## 3. Role-Based Access Control (NIST SP 800-61 Aligned)

The platform enforces three operational clearance tiers:

| Clearance Level | Title | Permissions |
|---|---|---|
| **Level 4 (L4)** | Lead Forensic Director / CIRT Lead | Full graph reconstruction, simulated containment execution, telemetry injection, raw evidence export, chaos simulation. |
| **Level 3 (L3)** | Senior Incident Responder | Attack graph reconstruction, simulated containment execution, chaos toggle analysis. |
| **Level 2 (L2)** | Threat Auditor / Compliance Officer | Read-only graph analysis, MITRE ATT&CK technique verification, Evidence DNA inspection. |

---

## 4. Evidence Provenance & Cryptographic Verification

Every log ingested into the Evidence DNA ledger is assigned:
- An immutable `log_id` (e.g., `LOG-APT-001`).
- A recorded host clock skew delta ($\Delta t_{\text{host}}$).
- A normalized ISO 8601 master timestamp.
- Verified MITRE ATT&CK technique tags.

Any attempt to forge or alter records invalidates the graph's internal causality check, which requires that child nodes have normalized timestamps greater than or equal to their parent causal triggers.
