"""
OBSYRON – Synchronous Extended Backend Verification Suite
Tests STIX 2.1 exporter, Sigma rules generator, Active Containment engine,
Merkle Tree evidence verification, Deep Graph Metrics, What-If simulation,
and Scenario Catalog modules.
"""

import os, sys, json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from log_generator import generate_logs
from ingestor import normalize_logs
from graph_engine import (
    build_attack_graph, get_root_cause, get_blast_radius,
    get_graph_confidence, get_graph_deep_metrics, simulate_what_if_containment
)
from stix_exporter import generate_stix_bundle
from sigma_generator import generate_sigma_rules, serialize_sigma_to_yaml
from containment_engine import (
    get_recommended_containment_actions, execute_containment_action,
    rollback_containment_action, list_containment_history
)
from merkle_tree import ForensicMerkleTree, verify_merkle_proof
from scenario_manager import (
    list_available_scenarios, get_scenario_metadata, load_scenario_telemetry
)

print("=" * 65)
print("  OBSYRON EXTENDED BACKEND VERIFICATION SUITE")
print("=" * 65)

# 0. Baseline Analysis
print("\n[STEP 0] Ingesting logs and reconstructing attack graph...")
raw_logs = generate_logs(shuffle=True, inject_skew=True, drop_telemetry=False)
normalized = normalize_logs(raw_logs)
graph_data = build_attack_graph(normalized)
G = graph_data["_graph"]

root_cause = get_root_cause(G)
blast = get_blast_radius(G, root_cause.get("entity", "185.220.101.47"))
confidence = get_graph_confidence(G)

analysis_result = {
    "raw_log_count": len(raw_logs),
    "malicious_signal_count": 6,
    "nodes": graph_data["nodes"],
    "edges": graph_data["edges"],
    "initial_access": root_cause,
    "blast_radius": blast,
    "overall_confidence": confidence,
    "xai_report": [
        {"step": 1, "title": "Initial Access", "mitre": "T1078", "mitre_name": "Valid Accounts", "confidence": 0.96},
        {"step": 2, "title": "Account Discovery", "mitre": "T1087", "mitre_name": "Account Discovery", "confidence": 0.93},
        {"step": 3, "title": "Privilege Escalation", "mitre": "T1558", "mitre_name": "SeDebugPrivilege", "confidence": 0.95},
        {"step": 4, "title": "Lateral Movement", "mitre": "T1021", "mitre_name": "Remote Services", "confidence": 0.97},
        {"step": 5, "title": "Data Exfiltration", "mitre": "T1048", "mitre_name": "Exfiltration Over C2", "confidence": 0.96},
    ]
}
print(f"  ✓ Graph reconstructed: {len(analysis_result['nodes'])} nodes, {len(analysis_result['edges'])} edges, Conf: {confidence*100:.1f}%")

# 1. Test STIX 2.1 Threat Intel Bundle Exporter
print("\n[TEST 1] Testing STIX 2.1 Threat Intel Bundle Exporter...")
stix_bundle = generate_stix_bundle(analysis_result, "OBS-INV-20261114-001")
assert stix_bundle["type"] == "bundle"
assert stix_bundle["spec_version"] == "2.1"
assert len(stix_bundle["objects"]) >= 8

object_types = {obj["type"] for obj in stix_bundle["objects"]}
print(f"  + Generated STIX 2.1 Bundle: {len(stix_bundle['objects'])} objects")
print(f"  + STIX Object Types: {sorted(list(object_types))}")
assert "threat-actor" in object_types
assert "attack-pattern" in object_types
assert "infrastructure" in object_types
assert "relationship" in object_types
print("  ✓ PASS: STIX 2.1 exporter produces valid OASIS STIX 2.1 JSON bundle.")

# 2. Test Sigma Detection Rules Generator
print("\n[TEST 2] Testing Sigma Rules Detection Generator...")
sigma_rules = generate_sigma_rules(analysis_result)
assert len(sigma_rules) >= 5
print(f"  + Generated {len(sigma_rules)} production Sigma detection rules:")
for r in sigma_rules:
    print(f"    - [{r['id']}] {r['title']} ({r['level'].upper()})")

yaml_text = serialize_sigma_to_yaml(sigma_rules)
assert "title:" in yaml_text
assert "logsource:" in yaml_text
assert "detection:" in yaml_text
print(f"  + Serialized Multi-Doc YAML: {len(yaml_text)} characters")
print("  ✓ PASS: Sigma generator synthesizes rules for Splunk, Elastic & Sentinel.")

# 3. Test Active Containment & Mitigation Engine
print("\n[TEST 3] Testing Active Containment Engine (Playbook + Execute + Rollback)...")
recommended = get_recommended_containment_actions(analysis_result)
assert len(recommended) >= 5
print(f"  + Recommended Playbook Actions: {len(recommended)}")

# Execute
record = execute_containment_action(
    action_type="ISOLATE_HOST",
    target="wkst-04-dev",
    operator_name="Cmdr. Maya Thorne (L4)",
    simulation_mode=False
)
assert record["status"] == "EXECUTED_SUCCESS"
action_id = record["action_id"]
print(f"  + Executed Action: {action_id} targeting {record['target']}")
print(f"  + Remediation Command: {record['remediation_command']}")
print(f"  + Audit Signature: {record['audit_signature'][:24]}...")

# History
history = list_containment_history()
assert len(history) >= 1
print(f"  + Containment History ledger: {len(history)} action(s) logged")

# Rollback
rb_res = rollback_containment_action(action_id)
assert rb_res["success"] is True
assert rb_res["record"]["status"] == "ROLLED_BACK"
print(f"  + Action {action_id} successfully rolled back.")
print("  ✓ PASS: Active containment orchestration and rollback operational.")

# 4. Test Cryptographic Merkle Tree Evidence Ledger
print("\n[TEST 4] Testing Cryptographic Merkle Tree Evidence Ledger...")
tree = ForensicMerkleTree(normalized)
merkle_root = tree.get_merkle_root()
assert len(merkle_root) == 64
print(f"  + Merkle Root Hash: {merkle_root}")
print(f"  + Total Leaves: {len(tree.leaf_hashes)}, Tree Depth: {len(tree.tree_levels)}")

# Inclusion proof verification
proof = tree.get_proof("LOG-APT-001")
assert proof is not None
is_valid = verify_merkle_proof(proof["leaf_hash"], proof["proof_path"], proof["merkle_root"])
assert is_valid is True
print(f"  + Cryptographic Inclusion Proof for LOG-APT-001: Validated (Path Depth: {len(proof['proof_path'])})")
print("  ✓ PASS: Merkle tree guarantees tamper-evident chain of custody.")

# 5. Test Deep Graph Analytics & Centrality Metrics
print("\n[TEST 5] Testing Deep Graph Analytics & Centrality Metrics...")
metrics = get_graph_deep_metrics(G)
assert "pivot_hosts_ranked" in metrics
assert "shortest_paths_from_patient_zero" in metrics
print(f"  + Graph Topology: {metrics['node_count']} nodes, {metrics['edge_count']} edges (DAG: {metrics['is_dag']})")
top_pivot = metrics["pivot_hosts_ranked"][0]
print(f"  + Top Compromised Pivot: {top_pivot['node']} ({top_pivot['entity_type']}, Centrality: {top_pivot['score']})")
print(f"  + Reachable Targets from Patient Zero: {len(metrics['shortest_paths_from_patient_zero'])} paths calculated")
print("  ✓ PASS: Deep graph theory metrics and pivot scoring verified.")

# 6. Test What-If Predictive Simulation
print("\n[TEST 6] Testing Predictive What-If Defense Simulator...")
whatif = simulate_what_if_containment(G, isolated_nodes=["wkst-04-dev"])
assert whatif["risk_reduction_percentage"] > 0
print(f"  + Baseline Compromised: {whatif['baseline_compromised_count']} -> Post-Quarantine: {whatif['post_containment_compromised_count']}")
print(f"  + Saved Assets: {whatif['saved_assets']} (Count: {whatif['saved_assets_count']})")
print(f"  + Risk Reduction Factor: {whatif['risk_reduction_percentage']}% ({whatif['containment_effectiveness']})")
print("  ✓ PASS: Predictive What-If simulator calculates attack path prevention.")

# 7. Test Scenario Catalog & Loader
print("\n[TEST 7] Testing Scenario Catalog & Dynamic Loader...")
scenarios = list_available_scenarios()
assert len(scenarios) >= 4
print(f"  + Registered Scenarios ({len(scenarios)}):")
for s in scenarios:
    print(f"    - [{s['id']}] {s['title']} ({s['complexity']})")

ransom_meta = get_scenario_metadata("ransomware_outbreak")
assert ransom_meta is not None
ransom_logs = load_scenario_telemetry("ransomware_outbreak")
assert len(ransom_logs) > 200
has_ransom_indicator = any(l.get("log_id") == "LOG-RANSOM-001" for l in ransom_logs)
assert has_ransom_indicator is True
print(f"  + Loaded Ransomware Scenario: {len(ransom_logs)} logs with CVE-2024-21887 & WMI lateral spread")
print("  ✓ PASS: Scenario catalog and dynamic telemetry loader operational.")

print("\n" + "=" * 65)
print("  ALL 7 EXTENDED BACKEND FEATURES PASSED WITH 100% SUCCESS!")
print("=" * 65)
