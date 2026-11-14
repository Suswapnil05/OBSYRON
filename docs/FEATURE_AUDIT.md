# OBSYRON XTM 2.0 — Comprehensive Feature & Interactive Element Audit
**HackInnovision 2026 (Track C: Cyber Forensic Graph Reconstruction)**  
**Platform Reference:** https://obsyron.vercel.app  
**Audit Timestamp:** 2026-11-14T07:10:00Z  

---

## 1. Executive Summary

This document provides an exhaustive audit of every interactive component, control surface, input form, data visualization element, and API interaction across the **OBSYRON** cybersecurity forensic investigation platform.

OBSYRON is a specialized defensive cyber-forensic platform designed to ingest inconsistent, noisy, and delayed enterprise telemetry, reconstruct multi-stage attack graphs using NetworkX multigraph algorithms, pinpoint Patient Zero (initial access), compute blast radius, identify intermediate pivot nodes via betweenness centrality, bridge telemetry gaps with uncertainty penalties, and present findings in an interactive Cytoscape.js command-center cockpit.

---

## 2. Interactive Element Catalog & Functionality Matrix

### Section A: Global Navigation Header
| ID / Selector | Element Type | Visual Label | Event Trigger | Expected Functionality | API Endpoint / Hook | Audit Status |
|---|---|---|---|---|---|---|
| `#header a.brand-section` | Link | `OBSYRON` | `click` | Scrolls viewport to top / landing view | Client navigation | ✓ Verified |
| `.header-nav a[href="#cockpit"]` | Nav Link | `Live Cockpit` | `click` | Smooth scrolls directly to `#cockpit` | Client viewport | ✓ Verified |
| `.header-nav a[href="#separate-signal-noise"]` | Nav Link | `Signal vs Noise` | `click` | Smooth scrolls to Signal vs Noise KPI section | Client viewport | ✓ Verified |
| `.header-nav a[href="#capabilities"]` | Nav Link | `Capabilities` | `click` | Smooth scrolls to Platform Capabilities | Client viewport | ✓ Verified |
| `.header-nav a[href="#mitre-alliances"]` | Nav Link | `MITRE Alliances` | `click` | Smooth scrolls to MITRE ATT&CK Alliance section | Client viewport | ✓ Verified |
| `#nav-link-auth` | Nav Link / Button | `Log In / Sign Up` | `click` | If guest, navigates to `/login`; if authenticated, opens active operator clearance modal | Client / `localStorage` | ✓ Verified |
| `#btn-theme` | Icon Button | `🌙` / `☀️` | `click` | Toggles Dark mode (`#0B0F19`) and Light mode (`#F8FAFC`); adjusts Cytoscape canvas colors | `toggleTheme()` | ✓ Verified |
| `a.btn-filigran-gradient` | CTA Button | `Launch Investigation ⚡` | `click` | Triggers full forensic ingestion & scrolls to cockpit | `POST /api/analyze` | ✓ Verified |
| `#btn-hamburger` | Mobile Button | `☰` | `click` | Toggles animated mobile navigation drawer | `toggleMobileMenu()` | ✓ Verified |

---

### Section B: Hero & Landing Interaction Surface
| ID / Selector | Element Type | Visual Label | Event Trigger | Expected Functionality | API Endpoint / Hook | Audit Status |
|---|---|---|---|---|---|---|
| `a.hero-btn-primary` | Hero Button | `Launch Investigation ⚡` | `click` | Ingests baseline dataset, computes attack graph, scrolls to `#cockpit` | `POST /api/analyze` | ✓ Verified |
| `a.hero-btn-secondary` | Hero Button | `Simulate Ingestion Chaos` | `click` | Toggles telemetry loss checkbox (`#tog-drop`) and runs chaos analysis | `POST /api/analyze` | ✓ Verified |

---

### Section C: Cockpit Header & Export Control Bar
| ID / Selector | Element Type | Visual Label | Event Trigger | Expected Functionality | API Endpoint / Hook | Audit Status |
|---|---|---|---|---|---|---|
| `#btn-supabase-status` | Header Pill | `⚡ Supabase (ugkekxiwvgsitzqduzxq)` | `click` | Opens Supabase Database Integration Modal for status inspection & API key configuration | `GET /api/database/status` | ✓ Verified |
| `button:contains("JSON Report")` | Action Button | `📥 JSON Report` | `click` | Downloads NIST SP 800-61 compliant forensic investigation report | `POST /api/reports/export` (`json`) | ✓ Verified |
| `button:contains("Evidence CSV")` | Action Button | `📊 Evidence CSV` | `click` | Downloads RFC 4180 immutable evidence ledger CSV | `POST /api/reports/export` (`csv`) | ✓ Verified |
| `button:contains("Markdown Brief")` | Action Button | `📄 Markdown Brief` | `click` | Downloads executive markdown incident debrief | `POST /api/reports/export` (`markdown`) | ✓ Verified |

---

### Section D: Top Forensic KPI Strip
| ID / Selector | Component | Visual Value | Expected Data Source | Audit Status |
|---|---|---|---|---|
| `#kpi-snr` | Signal-to-Noise Ratio | `356 → 6` | Calculated dynamically from `raw_log_count` and `malicious_signal_count` | ✓ Verified (Zero Hallucination) |
| `#kpi-pz` | Patient Zero Identity | `185.220.101.47` | Backwards graph traversal root cause entity | ✓ Verified |
| `#kpi-pz-sub` | Initial Access Context | `Initial Access @ 01:15` | Timestamp & MITRE tactic of initial correlated entry event | ✓ Verified |
| `#kpi-br` | Blast Radius Reach | `14 Assets` | Forward reachability `nx.descendants` count | ✓ Verified |
| `#kpi-conf` | Graph Confidence | `95.8%` (or `89.4%` under chaos) | Corroborated multi-signal weight with gap-bridging penalty | ✓ Verified |
| `#kpi-conf-chip` | Confidence Chip | `CORROBORATED` / `INFERRED` | Switches badge color & text based on telemetry gap presence | ✓ Verified |

---

### Section E: Left Control Rail (Dataset & Chaos Simulator)
| ID / Selector | Element Type | Visual Label | Event Trigger | Expected Functionality | API Endpoint / Hook | Audit Status |
|---|---|---|---|---|---|---|
| `#btn-builtin` | Rail Tab Button | `Built-in APT Kill Chain` | `click` | Resets to synthetic baseline APT scenario and invokes analysis | `selectDataset('builtin')` | ✓ Verified |
| `#btn-upload` | Rail Tab Button | `Upload Custom JSON/CSV` | `click` | Opens custom telemetry upload modal / triggers file input | `selectDataset('upload')` | ✓ Verified |
| `#file-input` | Hidden Input | `[File Picker]` | `change` | Accepts `.json` and `.csv` forensic logs; validates schema and triggers analysis | `POST /api/upload` | ✓ Verified |
| `#tog-shuffle` | Checkbox Toggle | `Shuffle Ingestion Order` | `change` | Randomizes ingestion order of raw logs; tests ingestor timestamp sorting | `onToggleChange()` | ✓ Verified |
| `#tog-skew` | Checkbox Toggle | `Compensate Clock Skew` | `change` | Injects $\pm 5\text{s}$ to $\pm 20\text{s}$ host drift; evaluates normalizer algorithm | `onToggleChange()` | ✓ Verified |
| `#tog-drop` | Checkbox Toggle | `Inject Telemetry Loss` | `change` | Drops Step 3 (`LOG-APT-003`); tests heuristic gap bridging & confidence penalty | `onToggleChange()` | ✓ Verified |
| `#btn-run-analysis` | Action Button | `⚡ Run Ingestion & Reconstruct` | `click` | Dispatches user chaos parameters to backend; reconstructs graph | `POST /api/analyze` | ✓ Verified |
| `#btn-reset-chaos` | Action Button | `↺ Reset Telemetry Cache` | `click` | Purges server-side session cache; resets controls to pristine baseline | `POST /api/simulation/reset` | ✓ Verified |
| `.scenario-btn` (Catalog) | Button List | `Scenario 1`–`Scenario 6` | `click` | Loads scenario dataset (`T1078`, `T1558`, `T1021`, `T1048`, `Normal Traffic`) | `POST /api/scenarios/load` | ✓ Verified |

---

### Section F: Cytoscape.js Attack Graph Canvas
| ID / Selector | Element Type | Visual Label | Event Trigger | Expected Functionality | Audit Status |
|---|---|---|---|---|---|
| `#btn-view-threat` | Toggle Button | `🎯 Threat Path` | `click` | Filters canvas strictly to the 5 core attack nodes and 6 sequential kill chain edges | ✓ Verified |
| `#btn-view-all` | Toggle Button | `🌐 All Assets` | `click` | Renders the complete 23-node corporate enterprise topology | ✓ Verified |
| `#graph-search` | Text Input | `🔍 Search entity...` | `input` | Live filters nodes by identifier, label, or entity type; dims non-matches | ✓ Verified |
| `.clear-search-btn` | Button | `✕` | `click` | Clears search query and restores full graph visibility | ✓ Verified |
| `#sel-graph-layout` | Select Dropdown | `Layout Selector` | `change` | Dynamically switches between `breadthfirst`, `concentric`, `cose`, and `circle` | ✓ Verified |
| `button:contains("+")` | Toolbar Button | `+` | `click` | Smoothly zooms in by $1.25\times$ | ✓ Verified |
| `button:contains("−")` | Toolbar Button | `−` | `click` | Smoothly zooms out by $0.8\times$ | ✓ Verified |
| `button:contains("⛶ FIT")` | Toolbar Button | `⛶ FIT` | `click` | Centers and fits all elements within the viewport | ✓ Verified |
| `button:contains("↺ RESET")` | Toolbar Button | `↺ RESET` | `click` | Resets dimming, clears highlights, and refits canvas | ✓ Verified |
| Cytoscape Node | Graph Element | Node rectangle/hexagon | `tap` / `click` | Fetches Evidence DNA; highlights upstream cause (sky-blue) & downstream blast (crimson) | ✓ Verified |
| Cytoscape Edge | Graph Element | Directed edge arrow | `tap` / `click` | Fetches edge evidence DNA; highlights source & target entities | ✓ Verified |
| Cytoscape Canvas | Container Canvas | Background | `tap` | Deselects elements, removes dimming, and closes evidence drawer | ✓ Verified |

---

### Section G: Right Forensic Intelligence Surface
| Tab Identifier | Visual Label | Key Components | Action Handlers | Audit Status |
|---|---|---|---|---|
| `xai` | `Root Cause AI` | 6 Sequential Step Cards with MITRE tags, log citations, certainty scores | Clicking any step card centers graph on the corresponding edge via `focusAttackStep(n)` | ✓ Verified |
| `playbook` | `Containment Playbook` | Recommended isolation checklist (Host isolation, Token revocation, IP firewall block) | `[Execute]` executes defense measure with Merkle signature; `[Undo]` performs rollback | ✓ Verified |
| `matrix` | `MITRE Matrix` | Tactics breakdown: Initial Access, Recon, Priv Esc, Lateral Move, Exfil | Includes `[Export STIX 2.1]` and `[Generate Sigma Rules]` buttons | ✓ Verified |
| `evidence` | `Evidence DNA` | Slide-over drawer with raw JSON payload, clock skew, SHA-256 hash, Merkle root | `fetchEvidence(logId)` loads immutable forensic provenance | ✓ Verified |

---

### Section H: Time-Travel Investigation Scrubber
| ID / Selector | Element Type | Visual Label | Event Trigger | Expected Functionality | API Endpoint | Audit Status |
|---|---|---|---|---|---|---|
| `#timeline-slider` | Range Slider | `0% – 100%` | `input` | Slices chronological timeline at target timestamp; dynamically updates graph | `GET /api/graph/snapshot?timestamp=...` | ✓ Verified |
| `#btn-play-pause` | Media Button | `▶` / `⏸` | `click` | Starts/stops automated 1.2-second interval timeline replay | Client interval + snapshot API | ✓ Verified |
| `#btn-timeline-reset` | Media Button | `⏮` | `click` | Resets scrubber to $t_0$ (earliest normalized event) | Client scrubber | ✓ Verified |
| `#timeline-display` | Text Readout | Date & Time IST | Dynamic | Displays exact normalized timestamp corresponding to scrubber position | Localized formatter | ✓ Verified |

---

### Section I: Authentication & Operator Access Portal (`/login`)
| Component | Functionality | Implementation Detail | Audit Status |
|---|---|---|---|
| Quick Role Switcher | 1-Click Login for Lead Analyst (`L4`), Senior IR (`L3`), Auditor (`L2`) | Fills credentials and logs in instantaneously | ✓ Verified |
| Custom Operator Login | Custom callsign + security passcode authentication | Verifies against operator database; issues signed token | ✓ Verified |
| Operator Registration | New operator callsign creation with role & clearance tier | Dynamic operator onboarding; syncs to Supabase | ✓ Verified |
| Session Token Storage | `localStorage` persistent bearer token (`OBSYRON-SEC-...`) | Attached to `Authorization: Bearer` on protected requests | ✓ Verified |
| Operator Clearance Badge | Topbar pill updating from `GUEST` to `L4 (Top Secret / SCI)` | Live reactive clearance level reflection across all views | ✓ Verified |

---

### Section J: Supabase PostgreSQL Cloud Integration
| Component | Functionality | Implementation Detail | Audit Status |
|---|---|---|---|
| Connection Status Probe | Queries `GET /api/database/status` | Live connection health probe to `ugkekxiwvgsitzqduzxq.supabase.co` | ✓ Verified |
| Database Modal | Status banner, Project Ref display, API key input, Table status | Allows configuring `anon` or `service_role` key from browser | ✓ Verified |
| Manual Sync Action | `[ ⚡ Sync Active Investigation Now ]` | Dispatches `POST /api/database/sync` to archive case & logs | ✓ Verified |
| Schema Download | Link to `supabase_schema.sql` | 1-click download of PostgreSQL table definitions and RLS policies | ✓ Verified |
