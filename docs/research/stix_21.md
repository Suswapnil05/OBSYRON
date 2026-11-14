# OBSYRON Research — STIX 2.1 Threat Standards Alignment

OBSYRON's entity and relationship taxonomy maps to the OASIS STIX 2.1 Cyber Threat Intelligence standard:
- **`USER`:** Maps to STIX `user-account` Cyber Observable Object (SCO).
- **`DEVICE`:** Maps to STIX `system` and `ipv4-addr` SCOs.
- **`SERVICE`:** Maps to STIX `process` / `service-account` SCOs.
- **`EXTERNAL_ENDPOINT`:** Maps to STIX `ipv4-addr` with `is_tor_exit: true` indicator.
- **Edges (`AUTH_ANOMALY`, `LATERAL_MOVE`, etc.):** Map to STIX Relationship Objects (SROs) with `relationship_type: "related-to"` and MITRE technique extensions.
