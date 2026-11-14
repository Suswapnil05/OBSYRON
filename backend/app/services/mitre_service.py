"""
OBSYRON MITRE Service — MITRE ATT&CK taxonomy mapping, Sigma rule generation, STIX 2.1 bundles.
"""

import sys, os
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from stix_exporter import generate_stix_bundle
from sigma_generator import generate_sigma_rules, serialize_sigma_to_yaml

class MitreService:
    @staticmethod
    def export_stix(analysis_result, investigation_id="OBS-INV-20261114-001"):
        return generate_stix_bundle(analysis_result, investigation_id=investigation_id)

    @staticmethod
    def export_sigma(analysis_result, investigation_id="OBS-INV-20261114-001", as_yaml=True):
        rules = generate_sigma_rules(analysis_result, investigation_id=investigation_id)
        if as_yaml:
            return serialize_sigma_to_yaml(rules)
        return rules
