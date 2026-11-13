# OBSYRON: Autonomous Cyber Forensic Investigation & Dynamic Attack Graph Reconstruction

**Event:** HackInnovision 2026 (NIT Rourkela)  
**Track:** Track C — Cyber Investigation & Attack Graph Reconstruction (CHIMERA)  
**Execution Mode:** 100% Standalone Localhost Application (Zero external database or cloud dependency)  
**Architecture:** Python + FastAPI + NetworkX MultiDiGraph + Cytoscape.js Dark SOC Command Interface  

---

## 1. Executive Summary & Scenario

Inside modern enterprise networks, advanced persistent threats (APTs) unfold silently without triggering isolated high-severity SIEM alarms:
1. **Initial Access:** An external adversary IP (`185.220.101.47`, TOR exit relay) authenticates off-hours to employee account `emp_rohan` on developer workstation `wkst-04-dev` (`T1078`).
2. **Reconnaissance:** The compromised identity runs Active Directory account discovery (`net user /domain`) over LDAP port 389 (`T1087`).
3. **Privilege Escalation:** Service account `svc_ci_deploy` is silently granted `SeDebugPrivilege` to enable token impersonation and ticket theft (`T1558`).
4. **Lateral Movement:** The adversary pivots laterally to production database host `db-prod-01` via SMB port 445 (`ADMIN$` share) using NTLM pass-the-hash (`T1021`).
5. **Data Exfiltration:** Production database `db-prod-01` opens an outbound TCP flow on non-standard port 4444 to `185.220.101.47`, exfiltrating 2.45 MB of production data (`T1048`).
6. **Command & Control:** An encrypted C2 beacon with 30-second heartbeats is established from `db-prod-01` to `185.220.101.47` (`T1048`).

**OBSYRON** ingests noisy (~350 benign logs), delayed, out-of-order, and fragmented enterprise telemetry, reconciles host clock skews, reconstructs the multi-entity directed attack graph, detects compromised internal pivot hosts via betweenness centrality, isolates the initial access vector (Patient Zero), calculates the downstream blast radius, bridges telemetry gaps with confidence-penalized heuristics, and grounds every forensic conclusion in immutable log citations.

---

## 2. Core Pillars & Capabilities

| Module | Forensic Capability | Implementation Detail |
|---|---|---|
| **1. Chaos Ingestor & Clock-Skew Correlator** | Re-orders shuffled logs and eliminates host clock skew ($\Delta t \in [\pm 5\text{s}, \pm 20\text{s}]$) | $t_{\text{norm}} = t_{\text{raw}} - \Delta t_{\text{host}}$ across all sources into a synchronized master timeline |
| **2. Dynamic MultiDiGraph Engine** | Models parallel interactions across the 4 core entities: **Users**, **Devices**, **Services**, and **External Endpoints** | Built using `nx.MultiDiGraph` with betweenness centrality pivot scoring |
| **3. Uncertainty & Gap-Bridging Heuristic** | Recovers disconnected attack paths when intermediate logs (e.g. privilege escalation) are dropped | Synthesizes an `INFERRED_LATERAL_BRIDGE` edge (dashed amber line) with penalized confidence (58%–65%) vs solid red edges (90%–98%) |
| **4. Root-Cause Analysis (Patient Zero)** | Backward graph traversal (`nx.ancestors` + zero in-degree root detection) | Pinpoints initial entry vector `185.220.101.47` -> `emp_rohan` at 01:15 IST |
| **5. Blast-Radius Calculator** | Forward reachability analysis (`nx.descendants` + shortest paths) | Discovers all exposed downstream assets (`emp_rohan`, `wkst-04-dev`, `svc_ci_deploy`, `db-prod-01`) and outputs a prioritized containment checklist |
| **6. Evidence DNA Inspector** | Zero-hallucination explainability | Immutable JSON provenance ledger attached to every node, edge, and XAI claim |
| **7. SOC Audio Briefing** | Offline executive voice debrief | Web Speech API synthesis summarizing the incident and response actions |

---

## 3. Quick Start (1-Click Run)

### Prerequisites
- Python 3.10+ (Standard Python installation)
- Modern web browser (Chrome, Edge, Firefox)

### Option A: 1-Click Launch (Windows)
Double click `start_obsyron.bat` or run:
```cmd
start_obsyron.bat
```

### Option B: Command Line Launch
```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Launch FastAPI server
python app.py
```
Then navigate to: **`http://localhost:8000`**

---

## 4. UI/UX Architecture (Single-Viewport SOC Dashboard)

The UI is built with a deep slate palette (`#0B0F19` canvas, `#111827` cards) formatted for a single `100vh` zero-scroll command dashboard:

```text
+---------------------------------------------------------------------------------------------------+
| ⬡ OBSYRON // Forensic Attack Graph Engine   [Track C: HackInnovision 2026]   [▶ Play Audio Brief] |
+------------------------+--------------------------------------------------------------------------+
| KPI TRIAGE STRIP       | [Signal-to-Noise: 356 -> 6]       [Patient Zero: 185.220.101.47 (T1078)] |
|                        | [Blast Radius: 4 Assets Exposed]  [Graph Confidence: 94.8%]              |
+------------------------+------------------------------------+-------------------------------------+
| LEFT CONTROL RAIL      | CENTER ATTACK GRAPH (Cytoscape.js) | RIGHT PANEL: XAI & CONTAINMENT      |
|                        |                                    |                                     |
| [Dataset Selector]     |     [EXT_IP: 185.220.101.47]       | ── Root Cause AI Narrative ──────── |
|  • Built-in APT        |                | 96% (Solid Red)   | 1. Initial Access [LOG-APT-001]     |
|  • Upload JSON / CSV   |         [USER: emp_rohan]          | 2. Discovery      [LOG-APT-002]     |
|                        |                | 93% (Solid Red)   | 3. Priv Esc       [LOG-APT-003]     |
| [Chaos Simulator]      |        [DEVICE: wkst-04-dev]       | 4. Lateral Move   [LOG-APT-004]     |
|  [x] Shuffle Logs      |                : 61% (Dashed Amber)| 5. Exfiltration   [LOG-APT-005]     |
|  [x] Clock Skew        |       [SERVICE: svc_ci_deploy]     | 6. C2 Beacon      [LOG-APT-006]     |
|  [ ] Drop 15% Logs     |                | 95% (Solid Red)   |                                     |
|                        |        [DEVICE: db-prod-01]        | ── Actionable Playbook ──────────── |
| [Time-Travel Scrubber] |                | 97% (Solid Red)   | [x] Lock emp_rohan                  |
|  01:15 ━━━━●━━━ 01:25  |     [EXT_IP: 185.220.101.47]       | [x] Block IP 185.220.101.47         |
+------------------------+------------------------------------+-------------------------------------+
| BOTTOM DRAWER: EVIDENCE DNA INSPECTOR (Raw Telemetry, Clock Skew Math, MITRE Tags & Payloads)     |
+---------------------------------------------------------------------------------------------------+
```

---

## 5. REST API Documentation

### `POST /api/analyze`
Ingests log telemetry with simulation flags and returns reconstructed attack graph, XAI report, and containment data.
- **Request Body:**
  ```json
  {
    "shuffle": true,
    "inject_skew": true,
    "drop_telemetry": false,
    "drop_rate": 0.15
  }
  ```
- **Response:**
  ```json
  {
    "raw_log_count": 356,
    "malicious_signal_count": 6,
    "nodes": [...],
    "edges": [...],
    "initial_access": {
      "entity": "185.220.101.47",
      "timestamp": "2026-11-14T01:15:00+05:30",
      "mitre_tactic": "T1078",
      "log_id": "LOG-APT-001"
    },
    "blast_radius": {
      "affected_nodes": ["185.220.101.47", "emp_rohan", "wkst-04-dev", "svc_ci_deploy", "db-prod-01"],
      "count": 5,
      "containment_checklist": [...]
    },
    "overall_confidence": 0.948,
    "xai_report": [...]
  }
  ```

### `GET /api/graph/snapshot?timestamp={ISO_TIMESTAMP}`
Returns graph state up to timestamp $T$ for time-travel investigation scrubber.

### `GET /api/evidence/{log_id}`
Returns complete Evidence DNA record (raw telemetry, host clock skew offset, normalized timestamp, MITRE technique, and raw payload).

### `POST /api/upload`
Uploads custom `.json` or `.csv` log file and generates attack graph in real time.

---

## 6. Directory Structure

```text
d:\HACK INNOVISION\
├── app.py                     # FastAPI application server & REST routes
├── graph_engine.py            # NetworkX MultiDiGraph engine, centrality, root-cause & blast radius
├── ingestor.py                # Temporal normalizer, clock skew correction, file parser
├── log_generator.py           # Synthetic enterprise log & 6-step APT generator with chaos simulation
├── requirements.txt           # Python package requirements
├── sample_attack_logs.json    # Sample forensic dataset for custom upload verification
├── start_obsyron.bat          # 1-click startup batch script
├── README.md                  # Comprehensive project documentation
└── static/
    ├── index.html             # Single-viewport Dark Mode SOC Command Dashboard
    └── app.js                 # Cytoscape.js visualization, time-travel scrubber, Evidence DNA & audio briefing
```

---

## 7. Compliance with HackInnovision 2026 Track C Evaluation Criteria

- **Technical Sophistication:** Native `NetworkX MultiDiGraph` modeling with betweenness centrality and forward/backward reachability.
- **Temporal Resilience:** Re-sequences scrambled out-of-order logs and eliminates host clock skews onto a synchronized master timeline.
- **Uncertainty Quantification:** Detects missing telemetry gaps and renders inferred lateral bridges with explicit confidence penalties.
- **Evidence Provenance:** Zero-hallucination Explainable AI with clickable `[LOG-XXXX]` citations backed by raw JSON logs.
- **Modern SOC Usability:** Single-viewport dark mode dashboard, interactive timeline scrubber, and offline executive audio briefing.

