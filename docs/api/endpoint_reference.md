# OBSYRON API — Endpoint Reference

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/analyze` | Ingests telemetry, corrects clock skew, and reconstructs attack graph |
| `GET` | `/api/graph/snapshot` | Returns chronological sub-graph sliced up to timestamp `timestamp` |
| `GET` | `/api/evidence/{log_id}` | Retrieves complete Evidence DNA record for a given log ID |
| `POST` | `/api/upload` | Multipart upload for custom JSON or CSV telemetry files |
| `GET` | `/api/auth/operators` | Lists available pre-configured operator roles |
| `POST` | `/api/auth/login` | Authenticates operator credentials and issues session token |
| `POST` | `/api/auth/signup` | Registers a new operator with defense clearance level |
| `GET` | `/api/auth/me` | Validates active operator session |
| `POST` | `/api/auth/logout` | Revokes operator session token |
| `GET` | `/api/health` | Health check, runtime mode, and cached record counts |
| `GET` | `/api/investigations` | Lists active and historical investigation records |
| `GET` | `/api/investigations/{id}` | Retrieves specific investigation details |
| `GET` | `/api/investigations/{id}/report` | Generates NIST SP 800-61 JSON forensic report |
| `GET` | `/api/investigations/{id}/evidence` | Extracts full evidence ledger |
| `POST` | `/api/reports/export` | Exports report as JSON, CSV ledger, or Markdown briefing |
| `POST` | `/api/briefing/audio` | Generates structured voice debrief speech script |
| `POST` | `/api/simulation/reset` | Purges memory cache and restores baseline zero |

