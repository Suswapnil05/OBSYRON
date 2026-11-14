"""
OBSYRON – Direct Endpoint Execution Test Suite
Tests FastAPI route handler functions directly in Python with full payload validation.
"""
import os, sys, asyncio, json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from app import (
    analyze, graph_snapshot, get_evidence, AnalyzeRequest,
    health_check, list_investigations, get_investigation_report,
    export_report, ExportRequest, get_audio_briefing,
    auth_login, LoginRequest, simulation_reset,
    get_database_status, update_database_config, DatabaseConfigRequest
)

print("=" * 60)
print("  OBSYRON DIRECT ENDPOINT VERIFICATION")
print("=" * 60)

async def run_tests():
    # ── 1. POST /api/analyze ────────────────────────────────────────────────
    print("\n[TEST 1] Executing analyze() handler...")
    req = AnalyzeRequest(shuffle=True, inject_skew=True, drop_telemetry=False, drop_rate=0.15)
    res = await analyze(req)
    assert res.status_code == 200, f"Expected 200, got {res.status_code}"
    data = json.loads(res.body.decode("utf-8"))

    print(f"  + Signal Reduction: {data['snr']}")
    print(f"  + Patient Zero Entity: {data['initial_access']['entity']}")
    print(f"  + Blast Radius Count: {data['blast_radius']['count']}")
    print(f"  + Overall Confidence: {data['overall_confidence'] * 100:.1f}%")
    print(f"  + XAI Report Steps: {len(data['xai_report'])}")
    assert data["raw_log_count"] >= 350
    assert data["malicious_signal_count"] == 6
    assert len(data["xai_report"]) == 6
    print("  ✓ PASS: analyze() endpoint returns complete attack graph & XAI narrative.")

    # ── 2. GET /api/graph/snapshot ──────────────────────────────────────────
    print("\n[TEST 2] Executing graph_snapshot() handler...")
    ts = "2026-11-14T01:17:00+05:30"
    res_snap = await graph_snapshot(timestamp=ts)
    assert res_snap.status_code == 200
    snap_data = json.loads(res_snap.body.decode("utf-8"))
    print(f"  + Snapshot at {ts}: {len(snap_data['nodes'])} nodes, {len(snap_data['edges'])} edges")
    print("  ✓ PASS: graph_snapshot() handler slices timeline cleanly.")

    # ── 3. GET /api/evidence/{log_id} ───────────────────────────────────────
    print("\n[TEST 3] Executing get_evidence() handler...")
    res_ev = await get_evidence(log_id="LOG-APT-001")
    assert res_ev.status_code == 200
    ev_data = json.loads(res_ev.body.decode("utf-8"))
    print(f"  + Evidence for LOG-APT-001: Action={ev_data['action']}, MITRE={ev_data['mitre_tag']}, Skew={ev_data['host_skew_sec']}s")
    assert ev_data["log_id"] == "LOG-APT-001"
    assert ev_data["mitre_tag"] == "T1078"

    res_inf = await get_evidence(log_id="INFERRED")
    assert res_inf.status_code == 200
    ev_inf = json.loads(res_inf.body.decode("utf-8"))
    print(f"  + Inferred Gap Bridge Evidence: Action={ev_inf['action']}, Conf={ev_inf['confidence']*100:.1f}%")
    assert ev_inf["is_inferred"] is True
    print("  ✓ PASS: get_evidence() handler serves both verified and inferred evidence DNA.")

    # ── 4. Dropped Telemetry Chaos Mode ─────────────────────────────────────
    print("\n[TEST 4] Executing analyze() with drop_telemetry=True...")
    req_drop = AnalyzeRequest(shuffle=True, inject_skew=True, drop_telemetry=True, drop_rate=0.15)
    res_drop = await analyze(req_drop)
    assert res_drop.status_code == 200
    drop_data = json.loads(res_drop.body.decode("utf-8"))

    inferred_edges = [e for e in drop_data["edges"] if e.get("is_inferred")]
    print(f"  + Inferred Gap Bridge Edges: {len(inferred_edges)}")
    assert len(inferred_edges) >= 1
    print(f"  + Inferred edge: {inferred_edges[0]['source']} -> {inferred_edges[0]['target']} ({inferred_edges[0]['confidence']*100:.1f}%)")
    print(f"  + Graph Confidence with Telemetry Gap: {drop_data['overall_confidence']*100:.1f}%")
    assert drop_data["overall_confidence"] < data["overall_confidence"]
    print("  ✓ PASS: Dropped telemetry triggers gap-bridging and updates graph confidence.")

    # ── 5. Health Check & Operator Auth ─────────────────────────────────────
    print("\n[TEST 5] Executing health_check() and auth_login()...")
    res_health = await health_check()
    assert res_health.status_code == 200
    health_data = json.loads(res_health.body.decode("utf-8"))
    assert health_data["status"] == "healthy"
    print(f"  + Health status: {health_data['status']}, service: {health_data['service']}")

    res_auth = await auth_login(LoginRequest(username="analyst_lead", password="obsyron2026"))
    assert res_auth.status_code == 200
    auth_data = json.loads(res_auth.body.decode("utf-8"))
    assert auth_data["success"] is True
    assert "token" in auth_data
    print(f"  + Operator login: {auth_data['operator']['name']}, clearance: {auth_data['operator']['clearance']}")
    print("  ✓ PASS: health_check() and operator authorization functioning.")

    # ── 6. Forensic Reports & Multi-format Export ───────────────────────────
    print("\n[TEST 6] Testing NIST Report & Multi-format Exports...")
    res_inv = await list_investigations()
    assert res_inv.status_code == 200
    inv_data = json.loads(res_inv.body.decode("utf-8"))
    assert len(inv_data["investigations"]) >= 1

    res_rep = await get_investigation_report("OBS-INV-20261114-001")
    assert res_rep.status_code == 200
    rep_data = json.loads(res_rep.body.decode("utf-8"))
    assert "executive_summary" in rep_data
    assert "defensive_containment_plan" in rep_data
    print(f"  + Investigation report generated: {rep_data['report_metadata']['investigation_id']}")

    # JSON export
    exp_json = await export_report(ExportRequest(format="json"))
    assert exp_json.status_code == 200

    # CSV export
    exp_csv = await export_report(ExportRequest(format="csv"))
    assert exp_csv.status_code == 200
    assert "log_id,raw_timestamp,normalized_timestamp" in exp_csv.body.decode("utf-8")
    print("  + CSV Evidence Ledger export verified.")

    # Markdown export
    exp_md = await export_report(ExportRequest(format="markdown"))
    assert exp_md.status_code == 200
    assert "# OBSYRON FORENSIC INCIDENT BRIEFING" in exp_md.body.decode("utf-8")
    print("  + Markdown executive brief export verified.")

    # Audio briefing
    audio_res = await get_audio_briefing()
    assert audio_res.status_code == 200
    audio_data = json.loads(audio_res.body.decode("utf-8"))
    assert len(audio_data["script"]) > 100
    print(f"  + Audio debrief script synthesized ({len(audio_data['script'])} chars).")

    # Simulation reset
    res_reset = await simulation_reset()
    assert res_reset.status_code == 200
    print("  ✓ PASS: Full reporting, multi-format export, and audio brief verified.")

    # ── 7. Supabase Database Integration ────────────────────────────────────
    print("\n[TEST 7] Testing Supabase PostgreSQL Integration...")
    db_res = await get_database_status()
    assert db_res.status_code == 200
    db_data = json.loads(db_res.body.decode("utf-8"))
    print(f"  + Database URL: {db_data['url']}")
    print(f"  + Project Ref: {db_data['project_ref']}")
    print(f"  + Connection Status: {db_data['message']}")
    assert db_data["project_ref"] == "ugkekxiwvgsitzqduzxq"
    assert db_data["connected"] == True
    print("  ✓ PASS: Supabase database connection probe and endpoint verified.")

    print("\n" + "=" * 60)
    print("  ALL DIRECT ENDPOINT TESTS PASSED WITH 100% SUCCESS!")
    print("=" * 60)

asyncio.run(run_tests())

