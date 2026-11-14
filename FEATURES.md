# OBSYRON XTM 2.0 — Feature Catalog

## 1. Executive Forensic Capabilities

### Dynamic Attack Graph Reconstruction
- **Interactive Cytoscape.js Canvas:** Renders directed multigraphs with hardware-accelerated pan, zoom, fit, and force-directed concentric layouts.
- **Entity Classification:** Distinct visual tokens and color codings for `USER` (cyan), `DEVICE` (green/emerald), `SERVICE` (amber/gold), and `EXTERNAL_ENDPOINT` (crimson/red).
- **Edge Highlighting:** Direct corroboration paths rendered in solid red; inferred gap-bridged hops rendered in dashed amber with warning markers.
- **Interactive Highlighting:** Selecting any node dynamically illuminates its backward causal ancestors (ingress path) and forward descendants (blast radius).

### Temporal Chaos Normalization
- **Clock Skew Compensation:** Reconciles disparate clock drift offsets ($\pm 5\text{s}$ to $\pm 20\text{s}$) across enterprise nodes into a single ground-truth timeline.
- **Out-of-Order Packet Sorting:** Automatically sorts shuffled event streams chronologically using normalized timestamps.
- **Ingestion Chaos Simulator:** Toggles for on-the-fly demonstration of clock drift correction, log order shuffling, and simulated telemetry packet drops.

### Root Cause Analysis (Patient Zero)
- **Reverse Reachability Traversal:** Automatically evaluates node in-degrees and ancestral paths to pinpoint the earliest uncorroborated ingress vector.
- **Attribution & Anomaly Detection:** Identifies anomalous off-hours logins, TOR exit relays, and credential bypass attempts.

### Downstream Blast Radius Quantification
- **Forward Impact Analysis:** Traverses all outgoing paths from the initial access point to identify exposed workstations, domain controllers, service accounts, and database assets.
- **Asset Criticality Ranking:** Privilege-weighted evaluation sorting downstream assets by vulnerability and risk profile.

### Pivot Entity Identification
- **Betweenness Centrality Computation:** Evaluates the proportion of shortest paths passing through each node using Brandes' algorithm, pinpointing critical pivot bridges like `wkst-04-dev`.
- **Targeted Containment Isolation:** Highlights single points of failure in the lateral movement chain for surgical network segmentation.

### Gap-Bridging & Missing Telemetry Heuristics
- **Temporal Proximity Inference:** Synthesizes missing intermediate hops (e.g., cleared privilege escalation logs) when consecutive steps occur across the same host within a tight temporal window.
- **Confidence Penalty Algorithm:** Explicitly discounts confidence scores (e.g., from 95% to 59–61%) for all inferred bridges to prevent analyst over-confidence.

### Explainable AI (XAI) Kill-Chain Narrative
- **Structured 6-Stage Narrative:** Explains each phase from Initial Access (T1078) to Command & Control Callback (T1048).
- **Immutable Log Citations:** Clickable tags (`[LOG: LOG-APT-001]`) open the underlying Evidence DNA record in the slide-out inspector.

### Interactive Time-Travel Incident Scrubber
- **Timeline Slider:** Scrub through the incident second-by-second from $t_0$ to final egress.
- **Automated Playback:** Play/Pause controls with speed adjustment (1x) animating the progressive compromise of enterprise assets.
- **Snapshot Slicing API:** Slices graph state up to any arbitrary timestamp $T$ on demand.

### Autonomous Executive Audio Debrief
- **Spoken Forensic Briefing:** Browser-native Web Speech API and backend script generator providing a clear, professional incident debrief to incident commanders.
- **Real-Time Speech Synthesis:** Outlines Patient Zero, affected assets, confidence scores, and recommended containment steps.

### Multi-Format Forensic Report Generation
- **NIST SP 800-61 JSON Reports:** Detailed machine-readable incident handling reports.
- **RFC 4180 CSV Evidence Ledgers:** Complete tabular audit ledgers containing skew corrections, MITRE tags, and raw payloads.
- **Printable Markdown Briefings:** Formatted executive summaries ready for PDF rendering or board presentation.

### Role-Based Operator Clearance & Login Portal
- **Clearance Tiers:** Level 4 (Top Secret / SCI), Level 3 (Secret / OpSec), Level 2 (Confidential).
- **Pre-Configured Call-signs:** Quick 1-click access for Lead Directors, Incident Responders, and Compliance Auditors.
- **Dynamic Enrollment:** Operator signup portal generating cryptographic session tokens (`OBSYRON-SEC-...`) and session audit logs.
