# OBSYRON XTM 2.0 — Testing & Verification Guide

## 1. Automated Test Suite Structure

OBSYRON includes two automated test suites:
1. `test_direct_endpoints.py`: End-to-end Python async verification of all FastAPI route handlers and responses.
2. `test_obsyron.py`: Algorithmic unit tests verifying clock skew correction, multigraph assembly, betweenness centrality, and gap bridging.

---

## 2. Running Automated Tests

To execute the test suites from the project root:

```bash
# Run direct endpoint tests
python test_direct_endpoints.py

# Run algorithmic unit tests
python test_obsyron.py
```

### Expected Output (`test_direct_endpoints.py`)

```text
============================================================
  OBSYRON DIRECT ENDPOINT VERIFICATION
============================================================

[TEST 1] Executing analyze() handler...
  + Signal Reduction: 356 Raw Logs → 6 Malicious Signals
  + Patient Zero Entity: 185.220.101.47
  + Blast Radius Count: 14
  + Overall Confidence: 95.1%
  + XAI Report Steps: 6
  ✓ PASS: analyze() endpoint returns complete attack graph & XAI narrative.

[TEST 2] Executing graph_snapshot() handler...
  + Snapshot at 2026-11-14T01:17:00+05:30: 22 nodes, 105 edges
  ✓ PASS: graph_snapshot() handler slices timeline cleanly.

[TEST 3] Executing get_evidence() handler...
  + Evidence for LOG-APT-001: Action=AUTH_ANOMALY, MITRE=T1078, Skew=12s
  + Inferred Gap Bridge Evidence: Action=INFERRED_LATERAL_BRIDGE, Conf=61.0%
  ✓ PASS: get_evidence() handler serves both verified and inferred evidence DNA.

[TEST 4] Executing analyze() with drop_telemetry=True...
  + Inferred Gap Bridge Edges: 1
  + Inferred edge: wkst-04-dev -> svc_ci_deploy (59.1%)
  + Graph Confidence with Telemetry Gap: 88.9%
  ✓ PASS: Dropped telemetry triggers gap-bridging and updates graph confidence.

[TEST 5] Executing health_check() and auth_login()...
  + Health status: healthy, service: OBSYRON XTM 2.0
  + Operator login: Cmdr. Maya Thorne, clearance: Level 4 (Top Secret / SCI)
  ✓ PASS: health_check() and operator authorization functioning.

[TEST 6] Testing NIST Report & Multi-format Exports...
  + Investigation report generated: OBS-INV-20261114-001
  + CSV Evidence Ledger export verified.
  + Markdown executive brief export verified.
  + Audio debrief script synthesized (1138 chars).
  ✓ PASS: Full reporting, multi-format export, and audio brief verified.

============================================================
  ALL DIRECT ENDPOINT TESTS PASSED WITH 100% SUCCESS!
============================================================
```

---

## 3. Manual Web Verification Checklist

1. **Dashboard Load:** Open `http://localhost:8000` (or `https://obsyron.vercel.app/`). Verify single-viewport layout, Filigran dark styling, and official metallic shield logo.
2. **Attack Graph Reconstruction:** Click `Reconstruct Attack Graph`. Confirm 23+ nodes and 350+ edges render in Cytoscape.js.
3. **Evidence DNA Drawer:** Click on node `wkst-04-dev` or edge `e_0_185.220.101.47_emp_rohan`. Confirm the bottom evidence drawer slides up with complete raw event JSON.
4. **Time-Travel Replay:** Click the `▶` play button. Verify the timeline slider advances chronologically, progressively illuminating nodes.
5. **Chaos Controls:** Toggle `Drop Telemetry (Gap Bridge)`. Verify dashed amber inferred edge appears and graph confidence score drops.
6. **Report Exports:** Click `📥 JSON Report`, `📊 Evidence CSV`, or `📄 Markdown Brief` in the top bar. Verify real files download to disk.
7. **Operator Portal:** Navigate to `/login`. Log in with username `analyst_lead` and passcode `obsyron2026`. Verify Level 4 clearance badge displays.

