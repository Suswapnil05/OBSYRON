# OBSYRON Security — Defensive Operational Scope

OBSYRON is intentionally constrained to defensive post-incident analysis and simulated response planning.

## Defensive Guardrails
1. **No Weaponized Action Execution:** Containment recommendations (e.g., host isolation, credential cycling) remain strictly advisory or simulated. The software does not execute unverified commands against Active Directory or border routers.
2. **Passive Ingestion Only:** Telemetry is processed from historical or synthetic log files. The system does not conduct intrusive port scans or active probes.
3. **Controlled Synthetic Scenarios:** Pre-packaged datasets model enterprise incidents for training, evaluation, and algorithmic validation without accessing unauthorized live networks.

