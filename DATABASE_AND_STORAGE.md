# OBSYRON XTM 2.0 — Database & Storage Architecture

## 1. Storage Architecture Overview

OBSYRON is deliberately engineered as a **zero-external-database platform**. Traditional SIEMs and SOAR platforms require complex PostgreSQL, Elasticsearch, Neo4j, or Redis clusters, introducing administrative overhead, potential attack surface, and deployment friction.

Instead, OBSYRON leverages:
1. **Volatile In-Memory Multigraphs:** High-performance NetworkX graphs held in memory during the active session.
2. **Deterministic Re-computability:** Given a raw or synthetic log dataset, the entire graph, betweenness centrality, root cause, and blast radius can be reconstructed deterministically in under 15 milliseconds.
3. **Stateless Serverless Compatibility:** On platforms like Vercel, serverless lambdas instantiate the graph on demand without requiring persistent connection pools or database migrations.
4. **Structured File Artifacts:** Exportable JSON reports, CSV evidence ledgers, and Markdown files serve as durable audit records.

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

## 3. Operator Session Directory

Operator authorization sessions are managed in an in-memory session table:

```python
_active_sessions: Dict[str, Any] = {
    "OBSYRON-SEC-3f1a...": {
        "token": "OBSYRON-SEC-3f1a...",
        "operator": {
            "username": "analyst_lead",
            "name": "Cmdr. Maya Thorne",
            "role": "Lead Forensic Director",
            "clearance": "Level 4 (Top Secret / SCI)",
            "clearance_code": "L4",
            "badge_color": "critical",
            "department": "Global Threat Intel & Forensic CIRT"
        },
        "login_at": "2026-11-14T01:00:00Z",
        "audit_id": "AUDIT-AUTH-8421"
    }
}
```

Tokens are generated using Python's cryptographically secure `secrets.token_hex(16)` and verified on protected actions.

---

## 4. Local File Persistence (Optional Extensions)

While OBSYRON operates out-of-the-box with zero database configuration, local file outputs are generated into the following directories:
- `sample-data/`: Pre-staged synthetic investigation datasets.
- Export Downloads: Streamed directly to client browsers with RFC 6266 `Content-Disposition: attachment` headers.

