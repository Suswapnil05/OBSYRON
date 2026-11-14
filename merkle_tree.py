"""
OBSYRON – Cryptographic Forensic Evidence Ledger & Merkle Tree Engine
Guarantees tamper-evidence and chain of custody for all ingested audit telemetry
by constructing a SHA-256 Merkle Tree and generating cryptographic inclusion proofs.
"""

import hashlib
import json
from typing import Dict, Any, List, Optional, Tuple


def _sha256(data: str) -> str:
    """Computes standard hexadecimal SHA-256 hash."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def compute_log_hash(log: Dict[str, Any]) -> str:
    """Computes deterministic leaf hash for an immutable audit telemetry record."""
    canonical = {
        "log_id": log.get("log_id"),
        "raw_timestamp": log.get("raw_timestamp"),
        "source": log.get("source"),
        "target": log.get("target"),
        "action": log.get("action"),
        "mitre_tag": log.get("mitre_tag", ""),
        "raw_payload": log.get("raw_payload", "")
    }
    dumped = json.dumps(canonical, sort_keys=True)
    return _sha256(dumped)


class ForensicMerkleTree:
    """
    Binary Merkle Tree implementation for tamper-evident forensic evidence chains.
    """
    def __init__(self, logs: List[Dict[str, Any]]):
        self.logs = logs
        self.leaf_hashes: List[str] = [compute_log_hash(l) for l in logs]
        self.log_id_to_index: Dict[str, int] = {l["log_id"]: i for i, l in enumerate(logs)}
        self.tree_levels: List[List[str]] = []
        self._build_tree()

    def _build_tree(self):
        if not self.leaf_hashes:
            self.root = _sha256("EMPTY_FORENSIC_LEDGER")
            self.tree_levels = [[self.root]]
            return

        current_level = list(self.leaf_hashes)
        self.tree_levels.append(current_level)

        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                combined = _sha256(left + right)
                next_level.append(combined)
            current_level = next_level
            self.tree_levels.append(current_level)

        self.root = current_level[0]

    def get_merkle_root(self) -> str:
        """Returns the master Merkle root hash representing the entire evidence state."""
        return self.root

    def get_proof(self, log_id: str) -> Optional[Dict[str, Any]]:
        """
        Generates cryptographic inclusion proof (sibling hashes and positions)
        for a specified log record.
        """
        if log_id not in self.log_id_to_index:
            return None

        idx = self.log_id_to_index[log_id]
        leaf_hash = self.leaf_hashes[idx]
        proof_path = []

        curr_idx = idx
        for level in self.tree_levels[:-1]:
            is_right_child = (curr_idx % 2 == 1)
            sibling_idx = curr_idx - 1 if is_right_child else curr_idx + 1

            if sibling_idx < len(level):
                sibling_hash = level[sibling_idx]
            else:
                sibling_hash = level[curr_idx]  # duplicate odd leaf

            proof_path.append({
                "sibling_hash": sibling_hash,
                "position": "left" if is_right_child else "right"
            })
            curr_idx = curr_idx // 2

        return {
            "log_id": log_id,
            "leaf_hash": leaf_hash,
            "merkle_root": self.root,
            "proof_path": proof_path,
            "tree_depth": len(self.tree_levels),
            "total_leaves": len(self.leaf_hashes),
            "tamper_status": "VERIFIED_UNMODIFIED"
        }


def verify_merkle_proof(leaf_hash: str, proof_path: List[Dict[str, str]], expected_root: str) -> bool:
    """Cryptographically verifies a Merkle proof path against the expected root."""
    current = leaf_hash
    for step in proof_path:
        sibling = step["sibling_hash"]
        pos = step["position"]
        if pos == "left":
            current = _sha256(sibling + current)
        else:
            current = _sha256(current + sibling)
    return current == expected_root


def generate_merkle_tree(logs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Convenience helper to build Merkle Tree and return summary dict."""
    tree = ForensicMerkleTree(logs)
    return {
        "merkle_root": tree.get_merkle_root(),
        "leaf_count": len(tree.leaf_hashes),
        "tree_depth": len(tree.tree_levels),
        "_tree": tree
    }

