# OBSYRON XTM 2.0 — Backend Service Architecture
**Track C: Cyber Investigation & Attack Graph Reconstruction (Project CHIMERA)**  
**HackInnovision 2026, NIT Rourkela**

---

## 1. Directory Structure

```
backend/
├── app/
│   ├── main.py                     # FastAPI application entrypoint
│   ├── api/
│   │   └── routes/                 # Modular API route controllers
│   │       ├── analyze.py          # /api/analyze, /api/upload
│   │       ├── graph.py            # /api/graph/snapshot, /api/graph/metrics
│   │       ├── evidence.py         # /api/evidence/{log_id}, /api/evidence/merkle
│   │       ├── reports.py          # /api/reports/export, /api/export/stix
│   │       ├── briefing.py         # /api/briefing/audio
│   │       ├── auth.py             # /api/auth/login, /api/auth/register, /api/auth/me
│   │       ├── investigations.py   # /api/investigations/{id}/*
│   │       └── chaos.py            # /api/simulate/chaos, /api/simulation/reset
│   ├── services/                   # Business logic and forensic algorithms
│   │   ├── ingestion_service.py    # Log decoding, synthetic generator
│   │   ├── normalization_service.py# Schema canonicalization
│   │   ├── temporal_service.py     # Clock-skew reconciliation & timeline snapshots
│   │   ├── graph_service.py        # NetworkX MultiDiGraph reconstruction
│   │   ├── correlation_service.py  # Multi-signal corroboration & event chaining
│   │   ├── root_cause_service.py   # Backward reachability & Patient Zero
│   │   ├── blast_radius_service.py # Forward reachability & asset exposure
│   │   ├── pivot_service.py        # Betweenness centrality calculation
│   │   ├── evidence_service.py     # Immutable provenance & Merkle trees
│   │   ├── confidence_service.py   # Corroboration scoring & gap penalties
│   │   └── mitre_service.py        # ATT&CK taxonomy, Sigma rules, STIX 2.1
│   ├── models/
│   │   └── schemas.py              # Pydantic request/response contracts
│   ├── engines/                    # Core mathematical graph algorithms
│   ├── datasets/                   # APT scenarios and baseline logs
│   └── tests/                      # Pytest and HTTPX integration tests
├── requirements.txt                # Python package specifications
└── README.md                       # Architecture documentation
```

---

## 2. Running the Backend

### Local Launch
```bash
python app.py
# or
python backend/app/main.py
```
Default URL: `http://localhost:8000` or `http://127.0.0.1:8001` (dynamic fallback).

### Direct Test Execution
```bash
python test_direct_endpoints.py
```
Executes all 7 direct validation test suites with 100% assertions passing.
