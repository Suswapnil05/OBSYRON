"""
OBSYRON Evidence Service — Immutable JSON Provenance, Merkle tree verification, and evidence DNA.
"""

import sys, os
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from merkle_tree import ForensicMerkleTree, verify_merkle_proof, generate_merkle_tree

class EvidenceService:
    @staticmethod
    def build_merkle_tree(normalized_logs):
        return ForensicMerkleTree(normalized_logs)

    @staticmethod
    def verify_proof(leaf_hash: str, proof: list, root_hash: str) -> bool:
        return verify_merkle_proof(leaf_hash, proof, root_hash)

    @staticmethod
    def get_audit_summary(normalized_logs):
        return generate_merkle_tree(normalized_logs)
