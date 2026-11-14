# OBSYRON Security — Evidence Integrity & Chain of Custody

## 1. Immutability Principle
In forensic investigations, evidence integrity must be mathematically verifiable:
- **Zero In-Place Mutation:** Uploaded or generated raw logs are treated as read-only.
- **Explicit Drift Logging:** When clock drift is reconciled, both `raw_timestamp` and `normalized_timestamp` are preserved side-by-side, along with the exact `skew_corrected_sec` offset.
- **Traceable Identifiers:** Each event retains its source `log_id`. Heuristic inferences are assigned unique synthetic keys (`INFERRED`) with full disclosure of the reasoning heuristic.

## 2. Chain of Custody in Exports
Every exported NIST SP 800-61 JSON report and CSV evidence ledger includes:
- Active investigation ID (`OBS-INV-...`).
- Investigating operator callsign and clearance level.
- Cryptographic session audit ID (`AUDIT-AUTH-...`).
- Exact UTC generation timestamp.
