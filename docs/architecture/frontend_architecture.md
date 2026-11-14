# OBSYRON Architecture — Frontend Architecture

## 1. Design System & Layout
The frontend interface is engineered as a single-viewport SOC Command Center adhering to the Filigran XTM cyber design language:
- **Base Canvas:** `#0B0F19` deep midnight slate.
- **Card Panels:** `#111827` high-contrast panel containers with `1px solid #1E293B` borders.
- **Color Accents:** Critical Red (`#EF4444`), Uncertainty Amber (`#F59E0B`), Entity Cyan (`#38BDF8`), Muted Slate (`#475569`).

## 2. Component Structure
- **Global Header:** Identity branding, live investigation identifier, NIST 800-61 operator profile, theme toggle (`🌙` / `☀️`), and Web Speech audio briefing control.
- **KPI Metrics Strip:** Live Signal-to-Noise Ratio (SNR), Patient Zero Ingress Vector, Blast Radius scope, and Graph Corroboration score.
- **Left Control Rail:** Dataset switcher, scenario presets (`sample-data/`), drag-and-drop file upload, ingestion chaos controls (`Shuffle`, `Clock Skew`, `Drop Telemetry`), and time-travel replay controls.
- **Center Canvas:** Hardware-accelerated Cytoscape.js attack graph with interactive zoom, pan, fit, and node/edge selection.
- **Right Panel:** Tabbed interface for Explainable AI (XAI) narrative, Containment Playbook, and Pivot Centrality matrix.
- **Bottom Slide-out Drawer:** Immutable Evidence DNA ledger inspector with 1-click JSON and CSV export actions.

