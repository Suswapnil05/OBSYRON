# OBSYRON XTM 2.0 — Database & Storage Architecture

## 1. Storage Architecture Overview

OBSYRON utilizes a **hybrid storage architecture**:
1. **Volatile In-Memory Multigraphs:** High-performance NetworkX graphs held in memory during the active session for sub-millisecond graph traversals.
2. **Deterministic Re-computability:** Given a raw or synthetic log dataset, the entire graph, betweenness centrality, root cause, and blast radius can be reconstructed deterministically in under 15 milliseconds.
3. **Stateless Serverless Compatibility:** On platforms like Vercel, serverless lambdas instantiate the graph on demand without requiring persistent connection pools or database migrations.
4. **Structured File Artifacts:** Exportable JSON reports, CSV evidence ledgers, and Markdown files serve as durable audit records.
5. **Supabase PostgreSQL Cloud Integration:** Optional persistent storage layer backed by Supabase PostgREST for storing multi-analyst case histories, audit logs, operator clearances, and containment actions.

---

## 2. In-Memory Session Cache Structure

In `app.py`, the active investigation state is maintained in a thread-safe in-memory cache:

```python
_cache: Dict[str, Any] = {
    "normalized_logs": [],   # Master chronological list of normalized log dicts
    "analysis_result": {},   # Complete serialized graph and analytics output
    "last_settings":   {},   # Chaos simulation toggles used for current analysis
}
```

### Cache Lifecycle
- **Initialization:** When `/api/analyze` or `/api/upload` is invoked, `_cache` is populated with normalized logs and the full analysis dictionary.
- **Scrubbing:** When `/api/graph/snapshot` is called, `_cache["normalized_logs"]` is queried and sliced without re-reading the filesystem.
- **Evidence Lookup:** `/api/evidence/{log_id}` scans `_cache["normalized_logs"]` in $O(N)$ time (typically $N < 1000$, sub-millisecond lookup).
- **Purge:** `/api/simulation/reset` empties `_cache`, guaranteeing a pristine state for the next scenario.

---

## 3. Supabase PostgreSQL Integration

OBSYRON natively connects to Supabase at:
**Project URL:** `https://ugkekxiwvgsitzqduzxq.supabase.co`  
**Project Reference:** `ugkekxiwvgsitzqduzxq`

### Architecture & Connection Model
- **Zero Heavy Dependencies:** The client (`supabase_client.py`) utilizes Python's built-in `urllib.request` and `ssl` modules to interact directly with Supabase's PostgREST v1 API. This eliminates package bloat and works reliably across Windows, Linux, Docker, and Vercel Serverless.
- **Graceful Fallback:** If the Supabase API key is not yet configured or the cloud is unreachable, OBSYRON seamlessly operates in local-first mode without raising errors or halting investigation workflows.
- **Auto-Sync Hooks:**
  - **Investigations:** Completed attack graphs, patient zero determinations, and blast radius metrics are persisted to `public.investigations`.
  - **Audit Logs:** Ingested normalized telemetry is batched and archived in `public.audit_logs`.
  - **Operators:** Authenticated operator callsigns and clearance levels are synced to `public.operators`.
  - **Containment Actions:** Defensive isolation, token revocation, and IP blocks are recorded in `public.containment_actions`.

### Database Schema Reference

The complete database schema is defined in [supabase_schema.sql](file:///d:/HACK%20INNOVISION/supabase_schema.sql):

```sql
-- 1. Investigations Table
CREATE TABLE IF NOT EXISTS public.investigations (
    id TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    status TEXT DEFAULT 'COMPLETED',
    dataset_name TEXT DEFAULT 'Enterprise Telemetry APT29',
    raw_log_count INT DEFAULT 0,
    malicious_signal_count INT DEFAULT 0,
    initial_access_entity TEXT,
    initial_access_tactic TEXT,
    blast_radius_count INT DEFAULT 0,
    overall_confidence NUMERIC(5, 4) DEFAULT 0.0,
    nodes_count INT DEFAULT 0,
    edges_count INT DEFAULT 0,
    analysis_payload JSONB DEFAULT '{}'::jsonb
);

-- 2. Audit Logs Table
CREATE TABLE IF NOT EXISTS public.audit_logs (
    log_id TEXT PRIMARY KEY,
    raw_timestamp TIMESTAMPTZ,
    normalized_timestamp TIMESTAMPTZ,
    host TEXT,
    entity_type TEXT DEFAULT 'GENERIC',
    source TEXT,
    target TEXT,
    action TEXT,
    mitre_tag TEXT,
    severity TEXT DEFAULT 'LOW',
    confidence NUMERIC(5, 4) DEFAULT 0.7,
    is_malicious BOOLEAN DEFAULT FALSE,
    raw_payload JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 3. Operators Table
CREATE TABLE IF NOT EXISTS public.operators (
    username TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    role TEXT DEFAULT 'Forensic Investigator',
    clearance TEXT DEFAULT 'Level 3',
    clearance_code TEXT DEFAULT 'L3',
    mfa_verified BOOLEAN DEFAULT TRUE,
    department TEXT DEFAULT 'Threat Intelligence & Forensic CIRT',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 4. Containment Actions Table
CREATE TABLE IF NOT EXISTS public.containment_actions (
    action_id TEXT PRIMARY KEY,
    investigation_id TEXT REFERENCES public.investigations(id) ON DELETE SET NULL,
    entity_id TEXT NOT NULL,
    action_type TEXT NOT NULL,
    status TEXT DEFAULT 'EXECUTED',
    executed_at TIMESTAMPTZ DEFAULT NOW(),
    operator TEXT DEFAULT 'Cmdr. Maya Thorne',
    impact TEXT DEFAULT ''
);
```

### Environment Configuration

In `.env`:
```env
SUPABASE_URL=https://ugkekxiwvgsitzqduzxq.supabase.co
SUPABASE_KEY=your_supabase_anon_or_service_role_key
```

### Linking Your Supabase Instance
1. Open the [Supabase Dashboard](https://supabase.com/dashboard/project/ugkekxiwvgsitzqduzxq).
2. Go to **SQL Editor** &rarr; paste the contents of `supabase_schema.sql` &rarr; click **Run**.
3. Go to **Project Settings** &rarr; **API** &rarr; copy the `anon public` key.
4. In OBSYRON, click the top **Supabase (ugkekxiwvgsitzqduzxq)** button in the Cockpit header, paste your key, and click **Save & Connect**.
