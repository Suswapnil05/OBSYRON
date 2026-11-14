# OBSYRON API — Response Examples

## 1. `/api/health` Response
```json
{
  "status": "healthy",
  "service": "OBSYRON XTM 2.0",
  "version": "2.0.0-CIRT",
  "timestamp": "2026-11-14T01:30:00Z",
  "runtime_mode": "local-first",
  "cached_logs": 356,
  "active_investigation_id": "OBS-INV-20261114-001"
}
```

## 2. `/api/auth/login` Response
```json
{
  "success": true,
  "token": "OBSYRON-SEC-1821f887926edfa986cae712f35d36f1",
  "operator": {
    "username": "analyst_lead",
    "name": "Cmdr. Maya Thorne",
    "role": "Lead Forensic Director",
    "clearance": "Level 4 (Top Secret / SCI)",
    "clearance_code": "L4",
    "badge_color": "critical",
    "mfa_verified": true,
    "department": "Global Threat Intel & Forensic CIRT"
  },
  "audit_id": "AUDIT-AUTH-4819",
  "login_at": "2026-11-14T01:30:00Z",
  "message": "Authorization Granted. Security Clearance: Level 4 (Top Secret / SCI)"
}
```
