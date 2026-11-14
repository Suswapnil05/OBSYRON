# OBSYRON Architecture — Investigation Pipeline

## 1. 5-Stage Investigation Lifecycle

```
[Stage 1: Ingestion & Parsing]
  ├─ Multi-format ingestion (JSON, CSV)
  └─ Canonical schema mapping

[Stage 2: Temporal Normalization]
  ├─ Host clock-skew correction: t_norm = t_raw - host_skew
  └─ Master timeline sorting

[Stage 3: Graph Reconstruction]
  ├─ MultiDiGraph node and edge insertion
  └─ Pivot calculation via Betweenness Centrality

[Stage 4: Causal & Reachability Reasoning]
  ├─ Backward traversal -> Patient Zero (Root Cause)
  ├─ Forward reachability -> Blast Radius
  └─ Gap bridging for dropped telemetry with confidence penalty

[Stage 5: Forensic Output & Reporting]
  ├─ Evidence DNA citation linking
  ├─ Explainable AI (XAI) narrative generation
  └─ Multi-format export (JSON, CSV, Markdown, Audio)
```
