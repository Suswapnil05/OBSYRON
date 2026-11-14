# OBSYRON XTM 2.0 — Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/), and adheres to [Semantic Versioning](https://semver.org/).

---

## [2.0.0-CIRT] - 2026-11-14 (HackInnovision 2026 Edition)

### Added
- **Dynamic Multigraph Attack Graph:** Full `NetworkX.MultiDiGraph` correlation engine supporting parallel multi-stage edges.
- **Root Cause Analysis (Patient Zero):** Backward traversal via `nx.ancestors()` isolating external ingress IP `185.220.101.47` on port 443.
- **Downstream Blast Radius Engine:** Forward traversal identifying 14 exposed or compromised enterprise assets.
- **Betweenness Centrality Pivot Discovery:** Identifies `wkst-04-dev` as the critical lateral bridge between developer tier and production database.
- **Clock Skew Compensation:** Reconciles host clock drifts ($\pm 5\text{s}$ to $\pm 20\text{s}$) into a unified master timeline ($t_{\text{norm}} = t_{\text{raw}} - \Delta t_{\text{host}}$).
- **Out-of-Order Ingestion Sorting:** Resolves asynchronously arriving syslog and firewall records into strict causal sequence.
- **Gap-Bridging Heuristic Engine:** Heuristically bridges missing privilege escalation logs with mathematical confidence penalty (from 95% to 59–61%).
- **Explainable AI Kill Chain:** 6-stage structured narrative anchored to immutable Evidence DNA log citations (`LOG-APT-001` through `LOG-APT-006`).
- **Interactive Time-Travel Scrubber:** Live timeline slider with Play/Pause animation and dynamic graph state slicing API (`/api/graph/snapshot`).
- **Executive Voice Debriefing:** Browser-native Web Speech API debrief providing spoken incident summaries to incident commanders.
- **NIST SP 800-61 Reporting Engine:** `reporter.py` generating JSON audit reports, RFC 4180 CSV evidence ledgers, and printable Markdown briefings.
- **Role-Based Clearance Portal:** Operator login and enrollment portal (`/login`) with Level 4, Level 3, and Level 2 clearances and cryptographic session tokens.
- **Dual Execution Topology:** 100% offline local-first mode (`python app.py`) and Vercel serverless Edge CDN deployment (`api/index.py` + `public/`).
- **Automated Direct Test Suite:** `test_direct_endpoints.py` providing 100% test coverage across all API route handlers and reporting generators.
- **Dedicated Synthetic Scenario Datasets:** 6 scenario datasets in `sample-data/` for targeted testing of credential access, privilege escalation, and gaps.

### Fixed
- **Vercel Serverless Routing 404:** Implemented `vercel_path_normalizer` middleware reading `x-matched-path` headers and dual-bound all routes (`/api/...` and `/...`).
- **Client-Side Fallback:** Added `apiFetch()` helper in `app.js` and `login.html` providing automatic failover between `/api/` and root endpoints.
- **Static Asset Serving:** Mirrored static files to `public/` for direct Edge CDN delivery, preventing `FileNotFoundError` inside serverless Lambdas.

