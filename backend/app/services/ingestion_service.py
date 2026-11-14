"""
OBSYRON Ingestion Service — Telemetry parsing, CSV/JSON decoding, and synthetic generation.
"""

import sys, os
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from log_generator import generate_logs
from ingestor import parse_uploaded_file, parse_json_logs, parse_csv_logs

class IngestionService:
    @staticmethod
    def generate_synthetic_telemetry(shuffle=False, inject_skew=False, drop_telemetry=False, drop_rate=0.15):
        return generate_logs(shuffle=shuffle, inject_skew=inject_skew, drop_telemetry=drop_telemetry, drop_rate=drop_rate)

    @staticmethod
    def parse_file(file_path: str):
        return parse_uploaded_file(file_path)

    @staticmethod
    def parse_json(raw_text: str):
        return parse_json_logs(raw_text)

    @staticmethod
    def parse_csv(raw_text: str):
        return parse_csv_logs(raw_text)
