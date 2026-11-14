"""
test_forensic_tools.py
Automated test suite verifying OBSYRON Forensic Capabilities Tools backend suite (/api/tools/*).
"""
import urllib.request
import json
import sys

BASE_URL = "http://127.0.0.1:8000"

def get(path):
    req = urllib.request.Request(f"{BASE_URL}{path}")
    with urllib.request.urlopen(req) as resp:
        return resp.status, json.loads(resp.read().decode())

def post(path, payload=None):
    data = json.dumps(payload or {}).encode('utf-8')
    req = urllib.request.Request(
        f"{BASE_URL}{path}",
        data=data,
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req) as resp:
        return resp.status, json.loads(resp.read().decode())

def run_tests():
    print("==================================================")
    print("OBSYRON FORENSIC TOOLS BACKEND SUITE VERIFICATION")
    print("==================================================")

    # 1. Catalog test
    status, catalog = get("/api/tools")
    assert status == 200, f"Expected 200, got {status}"
    assert catalog.get("success") is True
    assert catalog.get("tools_count") == 8
    tools = catalog.get("tools", [])
    assert len(tools) == 8
    print(f"✓ GET /api/tools: 8 tools registered in catalog")

    # 2. Clock skew correlator
    status, res = post("/api/tools/clock-skew-correlator", {})
    assert status == 200 and res.get("tool_id") == "clock-skew"
    assert "incoming_raw_packets" in res["metrics"]
    assert "drift_analysis" in res
    print(f"✓ POST /api/tools/clock-skew-correlator: metrics={res['metrics']['clock_drifts_compensated']} drifts compensated")

    # 3. MultiDiGraph analyzer
    status, res = post("/api/tools/multidigraph-analyzer", {})
    assert status == 200 and res.get("tool_id") == "multidigraph"
    assert "total_nodes" in res["topology_metrics"]
    assert len(res.get("shortest_attack_path", [])) > 0
    print(f"✓ POST /api/tools/multidigraph-analyzer: nodes={res['topology_metrics']['total_nodes']} density={res['topology_metrics']['density']}")

    # 4. Gap bridge detector
    status, res = post("/api/tools/gap-bridge-detector", {})
    assert status == 200 and res.get("tool_id") == "gap-bridge"
    assert "synthesized_bridge" in res
    print(f"✓ POST /api/tools/gap-bridge-detector: gap_warnings={res.get('telemetry_gaps_identified')}")

    # 5. Merkle integrity verifier
    status, res = post("/api/tools/merkle-integrity-verifier", {})
    assert status == 200 and res.get("tool_id") == "merkle-proof"
    assert res.get("merkle_root") is not None
    assert "sample_leaf_proof" in res
    print(f"✓ POST /api/tools/merkle-integrity-verifier: root={res.get('merkle_root')[:16]}... leaves={res.get('total_leaves')}")

    # 6. Sigma rule generator
    status, res = post("/api/tools/sigma-rule-generator", {})
    assert status == 200 and res.get("tool_id") == "sigma-gen"
    assert res.get("rules_count", 0) > 0
    assert "yaml_export" in res
    print(f"✓ POST /api/tools/sigma-rule-generator: generated {res.get('rules_count')} rules, YAML size={len(res.get('yaml_export'))} bytes")

    # 7. STIX threat exporter
    status, res = post("/api/tools/stix-threat-exporter", {})
    assert status == 200 and res.get("tool_id") == "stix-bundle"
    assert res.get("bundle", {}).get("type") == "bundle"
    assert res.get("stix_objects_count", 0) > 0
    print(f"✓ POST /api/tools/stix-threat-exporter: {res.get('stix_objects_count')} STIX 2.1 objects exported")

    # 8. Containment simulator
    status, res = post("/api/tools/containment-simulator", {"target_nodes": ["185.220.101.47"]})
    assert status == 200 and res.get("tool_id") == "containment-sim"
    assert "simulation_result" in res
    assert "recommended_playbook" in res
    print(f"✓ POST /api/tools/containment-simulator: blast reduction={res['simulation_result'].get('reduction_pct', 0)}%")

    # 9. Deception correlator
    status, res = post("/api/tools/deception-correlator", {})
    assert status == 200 and res.get("tool_id") == "deception-traps"
    assert "canary_triggers" in res
    print(f"✓ POST /api/tools/deception-correlator: correlated decoys={res.get('active_decoys_count')} attribution={res.get('attacker_attribution')}")

    print("==================================================")
    print("ALL 9 FORENSIC TOOL BACKEND CHECKS PASSED (100% OK)")
    print("==================================================")

if __name__ == "__main__":
    try:
        run_tests()
    except Exception as e:
        print(f"TEST FAILED: {e}")
        sys.exit(1)
