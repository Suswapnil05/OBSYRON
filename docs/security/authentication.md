# OBSYRON Security — Operator Authentication & RBAC

## 1. Authentication Scheme
OBSYRON provides a dedicated operator authorization system:
- **Transport Security:** Bearer token authorization via `Authorization: Bearer OBSYRON-SEC-...`.
- **Token Generation:** 128-bit cryptographic pseudo-random tokens generated via `secrets.token_hex(16)`.
- **Session Audit Logging:** Every login and logout records an immutable audit log entry with timestamp and clearance tier.

## 2. Role-Based Access Control (RBAC)
- **L4 (Lead Forensic Director):** Full administrative access, containment simulation, chaos telemetry injection, raw evidence export.
- **L3 (Senior Incident Responder):** Attack graph reconstruction, containment execution, chaos simulation.
- **L2 (Threat Auditor):** Read-only graph analysis, MITRE technique audit, evidence verification.
