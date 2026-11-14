# OBSYRON XTM 2.0 — MITRE ATT&CK Mapping Matrix

OBSYRON maps all observed and inferred enterprise signals to the **MITRE ATT&CK Enterprise Framework (v14)**.

---

## 1. Mapped Techniques Matrix

| Step | MITRE ID | Tactic | Technique Name | Evidence Citation | Confidence | Inferred? |
|---|---|---|---|---|---|---|
| **1** | **T1078** | Initial Access | Valid Accounts | `LOG-APT-001` | 96% | No |
| **2** | **T1087** | Discovery | Account Discovery | `LOG-APT-002` | 93% | No |
| **3** | **T1558** | Privilege Escalation | Steal or Forge Kerberos Tickets | `LOG-APT-003` (or `INFERRED`) | 91% (59% if inferred) | Conditional |
| **4** | **T1021** | Lateral Movement | Remote Services (SMB / RPC) | `LOG-APT-004` | 95% | No |
| **5** | **T1048** | Exfiltration | Exfiltration Over Alternative Protocol | `LOG-APT-005` | 97% | No |
| **6** | **T1048** | Command & Control | C2 Callback & Heartbeat | `LOG-APT-006` | 94% | No |

---

## 2. Detailed Technique Analysis

### Phase 1: T1078 — Valid Accounts (Initial Access)
- **Tactic:** Initial Access / Defense Evasion
- **Evidence Citation:** `LOG-APT-001`
- **Observed Activity:** External IP `185.220.101.47` (TOR exit node) authenticated to identity `emp_rohan` on developer workstation `wkst-04-dev` via HTTPS:443 at 01:15 IST.
- **Defensive Significance:** Legitimate credentials were used outside regular working hours without prior brute-force alert spikes, indicating pre-compromised credentials or spear-phishing.

### Phase 2: T1087 — Account Discovery (Reconnaissance)
- **Tactic:** Discovery
- **Evidence Citation:** `LOG-APT-002`
- **Observed Activity:** Post-login execution of `net user /domain` on `wkst-04-dev`, generating 42 LDAP queries to Active Directory domain controller `dc-01` over TCP:389 at 01:16 IST.
- **Defensive Significance:** Rapid directory enumeration immediately following off-hours external login is a high-fidelity indicator of interactive human adversary behavior.

### Phase 3: T1558 — Steal or Forge Kerberos Tickets / Privilege Escalation
- **Tactic:** Privilege Escalation / Credential Access
- **Evidence Citation:** `LOG-APT-003` (or synthesized `INFERRED` bridge)
- **Observed Activity:** Service account `svc_ci_deploy` silently granted `SeDebugPrivilege` on `wkst-04-dev` at 01:18 IST.
- **Defensive Significance:** `SeDebugPrivilege` allows token manipulation and reading memory from LSASS to acquire ticket-granting tokens (TGTs).
- **Missing Telemetry Handling:** If `LOG-APT-003` is dropped from telemetry, OBSYRON infers this step between T1087 and T1021, penalizing confidence from 91% to 59–61%.

### Phase 4: T1021.002 — Remote Services: SMB / Windows Admin Shares
- **Tactic:** Lateral Movement
- **Evidence Citation:** `LOG-APT-004`
- **Observed Activity:** Adversary used elevated token under `svc_ci_deploy` to authenticate to `db-prod-01` via SMB port 445 (`ADMIN$` share) at 01:20 IST.
- **Defensive Significance:** Exploits trusted service account privileges to bypass network segmentation and MFA requirements.

### Phase 5: T1048.003 — Exfiltration Over Alternative Protocol
- **Tactic:** Exfiltration
- **Evidence Citation:** `LOG-APT-005`
- **Observed Activity:** Host `db-prod-01` established direct outbound TCP connection on non-standard port 4444 to external IP `185.220.101.47`, egressing 2.457 MB of data at 01:22 IST.
- **Defensive Significance:** Non-standard egress port bypasses standard HTTP/HTTPS content inspection proxies.

### Phase 6: T1071 / T1048 — Persistent C2 Callback
- **Tactic:** Command and Control
- **Evidence Citation:** `LOG-APT-006`
- **Observed Activity:** Continuous 30-second heartbeat beaconing from `db-prod-01` to `185.220.101.47` over TCP:4444.
- **Defensive Significance:** Confirms active remote interactive control across the database server.
