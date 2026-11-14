# OBSYRON Research — MITRE ATT&CK Framework Integration

OBSYRON maps forensic multigraph transitions directly to MITRE ATT&CK Enterprise Matrix (v14):
- **Initial Access:** T1078 (Valid Accounts) — Off-hours ingress via external TOR relay.
- **Discovery:** T1087 (Account Discovery) — LDAP Active Directory queries across port 389.
- **Privilege Escalation:** T1558 (Steal or Forge Kerberos Tickets) — `SeDebugPrivilege` assignment to CI/CD service account.
- **Lateral Movement:** T1021.002 (Remote Services: SMB / Windows Admin Shares) — Lateral pivot mounting `ADMIN$` share on database host.
- **Exfiltration:** T1048.003 (Exfiltration Over Alternative Protocol) — Direct outbound egress over TCP:4444.
- **Command & Control:** T1071 / T1048 (Persistent Callback) — 30-second heartbeat beaconing.

