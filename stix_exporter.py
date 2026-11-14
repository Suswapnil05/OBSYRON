"""
OBSYRON – OASIS STIX 2.1 Threat Intelligence Bundle Exporter
Converts reconstructed MultiDiGraph and forensic kill-chain analysis
into standards-compliant OASIS STIX 2.1 JSON Bundles for interoperability
with OpenCTI, Filigran XTM, MISP, and enterprise TIPs.
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


def _generate_stix_id(type_name: str) -> str:
    """Generates deterministic or random STIX 2.1 format identifier: <type>--<UUIDv4>."""
    return f"{type_name}--{uuid.uuid4()}"


def generate_stix_bundle(analysis_result: Dict[str, Any], investigation_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Constructs an official OASIS STIX 2.1 bundle from the OBSYRON reconstructed attack graph.
    Produces STIX domain objects (ThreatActor, Identity, Infrastructure, AttackPattern, ObservedData)
    and STIX relationship objects (uses, targets, compromises, communicates-with).
    """
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    inv_id = investigation_id or "OBS-INV-20261114-001"
    
    stix_objects = []

    # 1. Threat Actor (The Adversary / TOR Relay Ingress)
    initial_access = analysis_result.get("initial_access", {})
    actor_entity = initial_access.get("entity", "185.220.101.47")
    
    threat_actor_id = _generate_stix_id("threat-actor")
    threat_actor = {
        "type": "threat-actor",
        "spec_version": "2.1",
        "id": threat_actor_id,
        "created": now_iso,
        "modified": now_iso,
        "name": f"Adversary Cluster ({actor_entity})",
        "threat_actor_types": ["hostile-actor", "advanced-persistent-threat"],
        "description": f"External adversary operating through TOR exit relay {actor_entity}. Identified via off-hours valid account compromise.",
        "sophistication": "advanced",
        "resource_level": "organization",
        "primary_motivation": "espionage",
        "confidence": int((analysis_result.get("overall_confidence", 0.95) if isinstance(analysis_result.get("overall_confidence"), (int, float)) else 0.95) * 100),
        "external_references": [
            {
                "source_name": "obsyron-forensic-engine",
                "description": f"Initial Access Root Cause for {inv_id}",
                "external_id": actor_entity
            }
        ]
    }
    stix_objects.append(threat_actor)

    # 2. Attack Patterns (MITRE ATT&CK Techniques)
    technique_to_stix_id = {}
    xai_steps = analysis_result.get("xai_report", [])

    for step in xai_steps:
        mitre_id = step.get("mitre", "T1078")
        if mitre_id not in technique_to_stix_id:
            ap_id = _generate_stix_id("attack-pattern")
            technique_to_stix_id[mitre_id] = ap_id
            attack_pattern = {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": ap_id,
                "created": now_iso,
                "modified": now_iso,
                "name": step.get("mitre_name", f"MITRE Technique {mitre_id}"),
                "description": step.get("narrative", ""),
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": mitre_id,
                        "url": f"https://attack.mitre.org/techniques/{mitre_id.replace('.', '/')}/"
                    }
                ],
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": step.get("title", "execution").lower().replace(" ", "-")
                    }
                ]
            }
            stix_objects.append(attack_pattern)

            # Relationship: ThreatActor uses AttackPattern
            stix_objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": _generate_stix_id("relationship"),
                "created": now_iso,
                "modified": now_iso,
                "relationship_type": "uses",
                "source_ref": threat_actor_id,
                "target_ref": ap_id,
                "description": f"Adversary executed technique {mitre_id} ({step.get('mitre_name')}) during Stage {step.get('step')}"
            })

    # 3. Identities (Compromised User and Service Accounts)
    nodes = analysis_result.get("nodes", [])
    node_to_stix_id = {}

    for node in nodes:
        node_id = node.get("id")
        etype = node.get("entity_type", "DEVICE")

        if etype in ("USER", "SERVICE"):
            identity_stix_id = _generate_stix_id("identity")
            node_to_stix_id[node_id] = identity_stix_id
            stix_objects.append({
                "type": "identity",
                "spec_version": "2.1",
                "id": identity_stix_id,
                "created": now_iso,
                "modified": now_iso,
                "name": node.get("label", node_id),
                "identity_class": "individual" if etype == "USER" else "system",
                "description": f"Enterprise identity target: {node_id} (Centrality: {node.get('centrality', 0.0)})",
                "labels": ["compromised-identity" if node.get("is_malicious") else "monitored-account"]
            })
            # Relationship: ThreatActor compromises Identity
            if node.get("is_malicious"):
                stix_objects.append({
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": _generate_stix_id("relationship"),
                    "created": now_iso,
                    "modified": now_iso,
                    "relationship_type": "compromises",
                    "source_ref": threat_actor_id,
                    "target_ref": identity_stix_id,
                    "description": f"Adversary compromised credentials of account {node_id}"
                })

        elif etype in ("DEVICE", "AUTH_ENDPOINT"):
            infra_stix_id = _generate_stix_id("infrastructure")
            node_to_stix_id[node_id] = infra_stix_id
            stix_objects.append({
                "type": "infrastructure",
                "spec_version": "2.1",
                "id": infra_stix_id,
                "created": now_iso,
                "modified": now_iso,
                "name": node.get("label", node_id),
                "infrastructure_types": ["command-and-control"] if etype == "AUTH_ENDPOINT" else ["workstation", "server"],
                "description": f"Network asset {node_id} (Centrality Pivot Score: {node.get('centrality', 0.0)})"
            })
            if node.get("is_malicious") and etype != "AUTH_ENDPOINT":
                stix_objects.append({
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": _generate_stix_id("relationship"),
                    "created": now_iso,
                    "modified": now_iso,
                    "relationship_type": "compromises",
                    "source_ref": threat_actor_id,
                    "target_ref": infra_stix_id,
                    "description": f"Host asset {node_id} impacted within intrusion blast radius"
                })

    # 4. Inter-Entity Lateral & Exfiltration Relationships
    edges = analysis_result.get("edges", [])
    for edge in edges:
        src = edge.get("source")
        tgt = edge.get("target")
        src_stix = node_to_stix_id.get(src)
        tgt_stix = node_to_stix_id.get(tgt)
        if src_stix and tgt_stix:
            rel_type = "communicates-with"
            if edge.get("is_inferred"):
                rel_type = "inferred-lateral-bridge"
            elif edge.get("mitre_tag") == "T1048":
                rel_type = "exfiltrates-to"

            stix_objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": _generate_stix_id("relationship"),
                "created": now_iso,
                "modified": now_iso,
                "relationship_type": rel_type,
                "source_ref": src_stix,
                "target_ref": tgt_stix,
                "confidence": int(edge.get("confidence", 0.90) * 100),
                "description": f"Observed action: {edge.get('action')} [MITRE {edge.get('mitre_tag', 'N/A')}] (Inferred: {edge.get('is_inferred', False)})"
            })

    # Assemble complete STIX 2.1 Bundle
    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": stix_objects
    }
    return bundle
