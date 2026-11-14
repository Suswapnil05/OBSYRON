"""
OBSYRON Temporal Service — Clock skew reconciliation and timeline snapshot slicing.
"""

import sys, os
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from ingestor import normalize_logs, get_timeline_snapshot, HOST_CLOCK_SKEW_MAP

class TemporalService:
    @staticmethod
    def normalize(raw_logs):
        return normalize_logs(raw_logs)

    @staticmethod
    def slice_snapshot(normalized_logs, target_timestamp: str):
        return get_timeline_snapshot(normalized_logs, target_timestamp)

    @staticmethod
    def get_host_skew_map():
        return dict(HOST_CLOCK_SKEW_MAP)
