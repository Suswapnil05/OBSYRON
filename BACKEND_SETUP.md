# OBSYRON XTM 2.0 — Backend Setup & Architecture Guide
**HackInnovision 2026 (Track C: Cyber Investigation & Attack Graph Reconstruction)**  
**Platform Reference:** [https://obsyron.vercel.app](https://obsyron.vercel.app)  

---

## 1. System Overview

OBSYRON's backend is a high-performance cyber-forensic correlation engine built with **Python 3.11+**, **FastAPI**, **NetworkX**, and **Pydantic**. It reconstructs multi-stage attack multigraphs from enterprise telemetry logs, models host clock drift and out-of-order packet delivery, computes root cause and blast radius, provides Explainable AI (XAI) attack narratives, and enforces cryptographic evidence provenance via SHA-256 Merkle trees.

The platform provides dual runtime compatibility:
- **Local-First Standalone Engine:** Zero external dependencies; uses in-memory graph processing and local SQLite persistence (`obsyron.db`).
- **Cloud / Serverless Engine:** Compatible with Vercel Serverless Functions (`api/index.py`) and hosted Supabase PostgreSQL storage.

---

## 2. Directory Architecture

```
HACK INNOVISION/
├── app.py                      # Primary unified FastAPI application entrypoint (Local & Vercel)
├── api/
│   └── index.py                # Vercel serverless routing handler
├── backend/                    # Modularized backend package
│   ├── app/
│   │   ├── main.py             # Modular FastAPI application instance
│   │   ├── models/             # Pydantic data validation schemas
│   │   │   └── schemas.py
│   │   └── services/           # Reusable forensic domain services
│   │       ├── ingestion_service.py
│   │       ├── temporal_service.py
│   │       ├── graph_service.py
│   │       ├── evidence_service.py
│   │       └── mitre_service.py
│   ├── requirements.txt
│   └── README.md
├── graph_engine.py             # NetworkX MultiDiGraph reconstruction & centrality metrics
├── temporal_engine.py          # Clock drift compensation & out-of-order event sorting
├── chaos_engine.py             # Deterministic ingestion chaos benchmarks & telemetry loss
├── merkle_engine.py            # SHA-256 Merkle Tree cryptographic integrity verification
├── containment_engine.py       # Defensive containment playbook execution & rollback
├── reporter.py                 # NIST SP 800-61 JSON, CSV ledger, and Markdown generator
├── stix_exporter.py            # OASIS STIX 2.1 Threat Intelligence Bundle generator
├── sigma_engine.py             # Splunk / Elastic / Sentinel Sigma YAML detection generator
├── sqlite_db.py                # Local SQLite storage engine (investigations, logs, operators)
├── supabase_client.py          # Supabase PostgreSQL client integration
├── supabase_schema.sql         # Supabase PostgreSQL DDL and RLS policies
├── log_generator.py            # Synthetic enterprise background traffic & APT kill chain generator
├── static/                     # Frontend web application assets (HTML, CSS, Cytoscape JS)
├── docs/                       # Project specifications, technical documentation, and rubrics
└── test_direct_endpoints.py    # Automated test suite for FastAPI route verification
```

---

## 3. Prerequisites

- **Python 3.11** or higher.
- `pip` package manager.
- Git.

---

## 4. Quickstart Local Installation

### Step 1: Clone Repository & Create Virtual Environment
```bash
git clone https://github.com/Suswapnil05/OBSYRON.git
cd OBSYRON

# Create Python virtual environment
python -m venv venv

# Activate on Windows:
.\venv\Scripts\activate
# Activate on Linux / macOS:
source venv/bin/activate
```

### Step 2: Install Python Dependencies
```bash
pip install -r requirements.txt
```

Core dependencies installed:
```
fastapi>=0.110.0
uvicorn>=0.28.0
networkx>=3.2.1
pydantic>=2.6.4
pandas>=2.2.1
httpx>=0.27.0
pytest>=8.1.1
python-multipart>=0.0.9
```

### Step 3: Run the Application Server

Start the primary server using Python directly:
```bash
python app.py
```
Or run with Uvicorn:
```bash
uvicorn app:app --host 127.0.0.1 --port 8000 --reload
```

The SOC Command Center interface will be available at:
`http://127.0.0.1:8000`

---

## 5. Environment Variables Configuration

Create a `.env` file in the project root to customize runtime parameters:

```env
# Server Networking
HOST=127.0.0.1
PORT=8000
LOG_LEVEL=info

# SQLite Local Database
SQLITE_DB_PATH=obsyron.db

# Supabase Cloud Database (Optional)
SUPABASE_URL=https://ugkekxiwvgsitzqduzxq.supabase.co
SUPABASE_KEY=your_supabase_anon_or_service_role_key
```

*Note: If `SUPABASE_KEY` is not provided, OBSYRON operates in local-first offline mode using SQLite without any degraded functionality.*

---

## 6. Complete API Endpoint Reference

| HTTP Method | Route Path | Description |
|---|---|---|
| `POST` | `/api/analyze` | Ingests logs, runs temporal normalization, and reconstructs attack graph |
| `POST` | `/api/simulate/chaos` | Executes deterministic ingestion chaos benchmark with clock drift and packet jitter |
| `GET` | `/api/graph/snapshot` | Slices attack graph at given timestamp for chronological investigation replay |
| `GET` | `/api/evidence/{log_id}` | Retrieves full Evidence DNA, clock skew offset, raw payload, and SHA-256 hash |
| `POST` | `/api/upload` | Ingests user-uploaded custom JSON or CSV telemetry logs |
| `GET` | `/api/investigations` | Lists active and historical forensic investigations |
| `GET` | `/api/investigations/{id}` | Retrieves complete investigation state, metadata, and graph |
| `GET` | `/api/investigations/{id}/root-cause` | Pinpoints verified Patient Zero initial access entity and tactic |
| `GET` | `/api/investigations/{id}/blast-radius` | Traverses downstream descendants to calculate reachability blast radius |
| `GET` | `/api/investigations/{id}/pivots` | Calculates topological betweenness centrality to rank intermediate pivots |
| `GET` | `/api/graph/metrics` | Returns deep topological metrics (centrality, degrees, shortest paths) |
| `POST` | `/api/reports/export` | Exports forensic report as NIST JSON, CSV evidence ledger, or Markdown |
| `POST` | `/api/briefing/audio` | Generates structured narrative for autonomous audio speech debrief |
| `POST` | `/api/auth/login` | Authenticates SOC operator and issues cryptographic session token |
| `POST` | `/api/auth/register` | Registers new SOC operator with defense clearance credentials |
| `GET` | `/api/auth/me` | Validates session token and returns active operator clearance profile |
| `POST` | `/api/containment/execute` | Simulates or executes defensive playbook containment action |
| `GET` | `/api/merkle` | Generates SHA-256 Merkle tree root and leaf hashes across ingested logs |
| `GET` | `/api/export/stix` | Exports reconstructed attack graph as OASIS STIX 2.1 JSON bundle |
| `GET` | `/api/export/sigma` | Generates production Sigma YAML detection rules for SIEM deployment |
| `GET` | `/api/health` | System health check, cached record count, and runtime mode |

---

## 7. Running Verification Tests

Run the complete endpoint verification test suite:

```bash
python test_direct_endpoints.py
```

Expected output:
```
============================================================
  OBSYRON DIRECT ENDPOINT VERIFICATION
============================================================
[TEST 1] Executing analyze() handler... ✓ PASS
[TEST 2] Executing graph_snapshot() handler... ✓ PASS
[TEST 3] Executing get_evidence() handler... ✓ PASS
[TEST 4] Executing analyze() with drop_telemetry=True... ✓ PASS
[TEST 5] Executing health_check() and auth_login()... ✓ PASS
[TEST 6] Testing NIST Report & Multi-format Exports... ✓ PASS
[TEST 7] Testing Supabase PostgreSQL Integration... ✓ PASS
[TEST 8] Testing Root Cause, Blast Radius, Pivots & Chaos... ✓ PASS
[TEST 9] Testing Operator Registration & SQLite Local Persistence... ✓ PASS
============================================================
  ALL DIRECT ENDPOINT TESTS PASSED WITH 100% SUCCESS!
============================================================
```

---

## 8. Vercel Serverless Deployment Architecture

For hosted cloud deployment (e.g. `https://obsyron.vercel.app`), Vercel routes traffic using `vercel.json`:
- All frontend static assets are served directly from `/static/` and `index.html`.
- All `/api/*` and dynamic routes are dispatched to the serverless function handler in `api/index.py`.
- `api/index.py` imports `app` from `app.py`.
- The SQLite persistence engine automatically detects the serverless environment (`VERCEL=1`) and defaults storage to `/tmp/obsyron.db`, ensuring non-blocking execution in ephemeral serverless runtimes.
