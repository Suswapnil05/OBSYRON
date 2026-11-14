# OBSYRON API — Request Examples

## 1. Trigger Full Analysis
```bash
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "shuffle": true,
    "inject_skew": true,
    "drop_telemetry": false,
    "drop_rate": 0.15
  }'
```

## 2. Retrieve Graph Snapshot
```bash
curl -X GET "http://localhost:8000/api/graph/snapshot?timestamp=2026-11-14T01:17:00%2B05:30"
```

## 3. Operator Login
```bash
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "analyst_lead",
    "password": "obsyron2026",
    "clearance_override": "L4"
  }'
```

## 4. Export CSV Evidence Ledger
```bash
curl -X POST http://localhost:8000/api/reports/export \
  -H "Content-Type: application/json" \
  -d '{
    "format": "csv",
    "investigation_id": "OBS-INV-20261114-001"
  }' \
  --output obsyron-evidence-ledger.csv
```

