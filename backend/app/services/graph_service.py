"""
OBSYRON Graph Service — NetworkX MultiDiGraph reconstruction and graph-theoretic metrics.
"""

import sys, os
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from graph_engine import (
    build_attack_graph,
    get_root_cause,
    get_blast_radius,
    get_graph_confidence,
    get_graph_deep_metrics,
    simulate_what_if_containment,
    get_explainable_confidence_breakdown
)

class GraphService:
    @staticmethod
    def reconstruct_graph(normalized_logs):
        return build_attack_graph(normalized_logs)

    @staticmethod
    def identify_root_cause(G):
        return get_root_cause(G)

    @staticmethod
    def calculate_blast_radius(G, root_cause_entity: str):
        return get_blast_radius(G, root_cause_entity)

    @staticmethod
    def calculate_confidence(G):
        return get_graph_confidence(G)

    @staticmethod
    def compute_metrics(G):
        return get_graph_deep_metrics(G)

    @staticmethod
    def what_if(G, isolated_nodes=None, severed_edges=None):
        return simulate_what_if_containment(G, isolated_nodes, severed_edges)
