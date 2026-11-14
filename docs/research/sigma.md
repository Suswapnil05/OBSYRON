# OBSYRON Research — Sigma Rule Interoperability

OBSYRON's log ingestion and event detection criteria are aligned with open-source Sigma detection rules:
- **T1078:** Matches Sigma rule `proc_creation_win_remote_powershell_session.yml` and anomalous logon type 10 (RemoteInteractive).
- **T1087:** Matches Sigma rule `net_user_domain_discovery.yml` (execution of `net user /domain` or `Get-ADUser`).
- **T1558:** Matches Sigma rule `win_security_sedebugprivilege_assigned.yml` (Event ID 4672 / 4673).
- **T1021:** Matches Sigma rule `win_security_net_share_mounted.yml` (Event ID 5140 / 5145 targeting `ADMIN$`).
- **T1048:** Matches Sigma rule `sysmon_network_unusual_outbound_port.yml` (outbound traffic to non-standard TCP ports).
