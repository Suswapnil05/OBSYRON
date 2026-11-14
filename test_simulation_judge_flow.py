#!/usr/bin/env python3
"""
OBSYRON — Simulation Lab & Judge Demonstration Mode E2E Test Suite
Verifies:
1. Scenario catalog retrieval (7 safe + APT29)
2. Safe scenario execution with telemetry generation & dynamic graph reconstruction
3. Atomic Red Team lab test harness script downloads (.ps1 and .sh)
4. Out-of-order and clock skew reconstruction diff matrix
5. Simulation session persistence in SQLite / Supabase schema
6. Multi-format report preview (Markdown and JSON)
"""

import json
import urllib.request
import urllib.parse
import sys

BASE_URL = "http://127.0.0.1:8000"

def request(method, path, body=None, headers=None):
    url = f"{BASE_URL}{path}"
    h = headers or {}
    data = None
    if body is not None:
        if isinstance(body, dict):
            data = json.dumps(body).encode("utf-8")
            h["Content-Type"] = "application/json"
        elif isinstance(body, (bytes, str)):
            data = body if isinstance(body, bytes) else body.encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    with urllib.request.urlopen(req, timeout=10) as resp:
        content = resp.read()
        try:
            return resp.status, json.loads(content.decode("utf-8"))
        except Exception:
            return resp.status, content.decode("utf-8", errors="replace")

def test_all():
    print("=" * 60)
    print("  RUNNING OBSYRON SIMULATION LAB & RECONSTRUCTION TEST SUITE")
    print("=" * 60)

    # 1. Scenarios Catalog
    print("\n[Step 1] Fetching Simulation Scenarios catalog...")
    st, res = request("GET", "/api/simulation/scenarios")
    assert st == 200, f"Expected 200, got {st}"
    scenarios = res.get("scenarios", [])
    print(f"  ✓ Retrieved {len(scenarios)} scenarios from catalog.")
    assert len(scenarios) >= 8, f"Expected at least 8 scenarios, got {len(scenarios)}"
    scenario_ids = [s["id"] for s in scenarios]
    for expected in ["powershell_exec", "failed_auth_spray", "process_masquerade", "credential_access", "lateral_movement", "c2_network_beacon", "data_exfil", "apt29_stealth_exfil"]:
        assert expected in scenario_ids, f"Scenario '{expected}' missing from catalog"
    print(f"  ✓ All 7 predefined safe scenarios + APT29 verified.")

    # 2. Execute PowerShell Execution Simulation
    print("\n[Step 2] Executing Safe Scenario: powershell_exec (T1059.001)...")
    st, res = request("POST", "/api/simulation/execute", {
        "scenario_id": "powershell_exec",
        "provenance": "CONTROLLED_SIMULATION"
    })
    assert st == 200, f"Expected 200, got {st}"
    assert res.get("success") is True
    assert res.get("events_count") > 0
    diff = res.get("reconstruction_diff", {})
    assert "comparison_table" in diff
    print(f"  ✓ Session ID: {res.get('session_id')}")
    print(f"  ✓ Ingested {res.get('events_count')} normalized events.")
    print(f"  ✓ Reconstruction Engine: {diff.get('out_of_order_count')} OOO resolved | {diff.get('skew_compensated_count')} clock drifts compensated.")

    # 3. Execute Failed Auth Spray Simulation
    print("\n[Step 3] Executing Safe Scenario: failed_auth_spray (T1110.003)...")
    st, res = request("POST", "/api/simulation/execute", {
        "scenario_id": "failed_auth_spray",
        "provenance": "CONTROLLED_SIMULATION"
    })
    assert st == 200 and res.get("success") is True
    print(f"  ✓ Ingested {res.get('events_count')} auth log events.")

    # 4. Download Lab Test Scripts
    print("\n[Step 4] Downloading Atomic Red Team Lab Test Harness scripts...")
    st, ps1 = request("GET", "/api/simulation/download-script/powershell_exec?platform=powershell")
    assert st == 200 and "OBSYRON Lab Test Kit" in ps1
    print(f"  ✓ Downloaded PowerShell (.ps1) script: {len(ps1)} bytes")

    st, sh = request("GET", "/api/simulation/download-script/failed_auth_spray?platform=bash")
    assert st == 200 and "OBSYRON Lab Test Kit" in sh
    print(f"  ✓ Downloaded Linux Bash (.sh) script: {len(sh)} bytes")

    # 5. Check Reconstruction Diff Matrix
    print("\n[Step 5] Checking Event Reconstruction Diff Matrix...")
    st, res = request("GET", "/api/simulation/reconstruction-diff")
    assert st == 200
    rows = res.get("comparison_table", [])
    print(f"  ✓ Reconstruction audit matrix contains {len(rows)} before-and-after rows.")
    assert len(rows) > 0
    sample = rows[0]
    for key in ["raw_order", "calibrated_order", "order_shift", "is_out_of_order", "source_host", "raw_timestamp", "normalized_timestamp", "host_skew_sec"]:
        assert key in sample, f"Key '{key}' missing from comparison row"
    print(f"  ✓ Sample row: #{sample['raw_order']} -> #{sample['calibrated_order']} | Shift: {sample['order_shift']} | Skew: {sample['skew_direction']}")

    # 6. Verify Simulation Sessions
    print("\n[Step 6] Retrieving Simulation Sessions audit log...")
    st, res = request("GET", "/api/simulation/sessions")
    assert st == 200
    sessions = res.get("sessions", [])
    print(f"  ✓ Found {len(sessions)} recorded simulation sessions in SQLite storage.")
    assert len(sessions) >= 2

    # 7. Multi-Format Report Preview
    print("\n[Step 7] Generating Forensic Incident Reports (Markdown & JSON)...")
    st, md = request("GET", "/api/reports/preview?format=markdown")
    assert st == 200 and "OBSYRON" in md
    print(f"  ✓ Generated Markdown report: {len(md)} bytes")

    st, rep_json = request("GET", "/api/reports/preview?format=json")
    assert st == 200 and isinstance(rep_json, dict)
    print(f"  ✓ Generated JSON report: {list(rep_json.keys())}")

    print("\n" + "=" * 60)
    print("  ALL 7 SIMULATION & RECONSTRUCTION TESTS PASSED (100% OK)!")
    print("=" * 60)

if __name__ == "__main__":
    test_all()
