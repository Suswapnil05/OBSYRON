-- ============================================================================
-- OBSYRON XTM 2.0 — COMPLETE SUPABASE POSTGRESQL DATABASE SCHEMA
-- HackInnovision 2026 (Track C: Cyber Forensic Graph Reconstruction)
-- 10 Core Tables with Foreign Keys, Indexes, and Row Level Security (RLS)
-- ============================================================================

-- 1. Profiles Table (User Accounts & Authentication)
CREATE TABLE IF NOT EXISTS public.profiles (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name TEXT NOT NULL,
    role TEXT DEFAULT 'Forensic Investigator',
    department TEXT DEFAULT 'Threat Intelligence & Forensic CIRT',
    clearance TEXT DEFAULT 'Level 3 (Secret)',
    clearance_code TEXT DEFAULT 'L3',
    avatar TEXT DEFAULT '🛡️',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_profiles_email ON public.profiles(email);
CREATE INDEX IF NOT EXISTS idx_profiles_username ON public.profiles(username);

-- 2. Investigations Table (Owned by Authenticated User)
CREATE TABLE IF NOT EXISTS public.investigations (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    severity TEXT DEFAULT 'HIGH',
    status TEXT DEFAULT 'ACTIVE',
    dataset_name TEXT DEFAULT 'Enterprise Telemetry APT29',
    raw_log_count INT DEFAULT 0,
    malicious_signal_count INT DEFAULT 0,
    initial_access_entity TEXT DEFAULT '185.220.101.47',
    initial_access_tactic TEXT DEFAULT 'Initial Access',
    blast_radius_count INT DEFAULT 0,
    overall_confidence NUMERIC(5, 4) DEFAULT 0.9500,
    nodes_count INT DEFAULT 0,
    edges_count INT DEFAULT 0,
    analysis_payload JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_investigations_user ON public.investigations(user_id);
CREATE INDEX IF NOT EXISTS idx_investigations_created_at ON public.investigations(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_investigations_severity ON public.investigations(severity);

-- 3. Telemetry Files Table (Uploaded CSV / JSON Data Files)
CREATE TABLE IF NOT EXISTS public.telemetry_files (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES public.investigations(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    filename TEXT NOT NULL,
    file_size INT DEFAULT 0,
    file_format TEXT DEFAULT 'JSON',
    record_count INT DEFAULT 0,
    valid_count INT DEFAULT 0,
    invalid_count INT DEFAULT 0,
    duplicate_count INT DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_telemetry_files_inv ON public.telemetry_files(investigation_id);

-- 4. Telemetry Events Table (Parsed & Normalized Audit Logs)
CREATE TABLE IF NOT EXISTS public.telemetry_events (
    id TEXT PRIMARY KEY,
    file_id TEXT REFERENCES public.telemetry_files(id) ON DELETE SET NULL,
    investigation_id TEXT NOT NULL REFERENCES public.investigations(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    raw_timestamp TIMESTAMPTZ,
    normalized_timestamp TIMESTAMPTZ,
    host TEXT,
    entity_type TEXT DEFAULT 'DEVICE',
    source TEXT,
    target TEXT,
    action TEXT,
    mitre_tag TEXT,
    severity TEXT DEFAULT 'LOW',
    confidence NUMERIC(5, 4) DEFAULT 0.7000,
    is_malicious BOOLEAN DEFAULT FALSE,
    raw_payload JSONB DEFAULT '{}'::jsonb,
    sha256_hash TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_telemetry_events_inv ON public.telemetry_events(investigation_id);
CREATE INDEX IF NOT EXISTS idx_telemetry_events_time ON public.telemetry_events(normalized_timestamp ASC);
CREATE INDEX IF NOT EXISTS idx_telemetry_events_mal ON public.telemetry_events(is_malicious) WHERE is_malicious = TRUE;

-- 5. Attack Nodes Table (Reconstructed Visual Graph Nodes)
CREATE TABLE IF NOT EXISTS public.attack_nodes (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES public.investigations(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    entity_id TEXT NOT NULL,
    entity_type TEXT DEFAULT 'DEVICE',
    label TEXT,
    severity TEXT DEFAULT 'LOW',
    is_malicious BOOLEAN DEFAULT FALSE,
    centrality NUMERIC(6, 5) DEFAULT 0.0,
    mitre_tags JSONB DEFAULT '[]'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_attack_nodes_inv ON public.attack_nodes(investigation_id);

-- 6. Attack Edges Table (Reconstructed Directional Attack Transitions)
CREATE TABLE IF NOT EXISTS public.attack_edges (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES public.investigations(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    target TEXT NOT NULL,
    action TEXT,
    mitre_tag TEXT,
    severity TEXT DEFAULT 'LOW',
    confidence NUMERIC(5, 4) DEFAULT 0.8000,
    is_inferred BOOLEAN DEFAULT FALSE,
    causal_connection TEXT
);

CREATE INDEX IF NOT EXISTS idx_attack_edges_inv ON public.attack_edges(investigation_id);

-- 7. Evidence Records Table (Cryptographic Verification Ledger)
CREATE TABLE IF NOT EXISTS public.evidence_records (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES public.investigations(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    event_id TEXT NOT NULL,
    sha256_hash TEXT,
    merkle_root TEXT,
    is_verified BOOLEAN DEFAULT TRUE,
    raw_log JSONB DEFAULT '{}'::jsonb,
    supporting_facts JSONB DEFAULT '[]'::jsonb,
    contradictory_facts JSONB DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_evidence_records_inv ON public.evidence_records(investigation_id);

-- 8. Investigation Notes Table (Analyst Collaboration & Triage)
CREATE TABLE IF NOT EXISTS public.investigation_notes (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES public.investigations(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    author_name TEXT NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_investigation_notes_inv ON public.investigation_notes(investigation_id);

-- 9. Deception Events Table (Honeypot Decoy Telemetry)
CREATE TABLE IF NOT EXISTS public.deception_events (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES public.investigations(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    sensor_type TEXT DEFAULT 'Cowrie SSH',
    src_ip TEXT,
    target_decoy TEXT,
    trigger_timestamp TIMESTAMPTZ DEFAULT NOW(),
    payload JSONB DEFAULT '{}'::jsonb,
    severity TEXT DEFAULT 'CRITICAL',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_deception_events_inv ON public.deception_events(investigation_id);

-- 10. Investigation Reports Table (Generated PDF/JSON/CSV/Markdown Exports)
CREATE TABLE IF NOT EXISTS public.investigation_reports (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES public.investigations(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    format TEXT NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_investigation_reports_inv ON public.investigation_reports(investigation_id);

-- ============================================================================
-- ROW LEVEL SECURITY (RLS) POLICIES
-- ============================================================================

ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.investigations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.telemetry_files ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.telemetry_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.attack_nodes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.attack_edges ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.evidence_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.investigation_notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.deception_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.investigation_reports ENABLE ROW LEVEL SECURITY;

-- Permissive policy for service_role and authenticated users to access their own data
DO $$
BEGIN
    DROP POLICY IF EXISTS "Users can read own profiles" ON public.profiles;
    CREATE POLICY "Users can read own profiles" ON public.profiles FOR ALL USING (true);

    DROP POLICY IF EXISTS "Users can manage own investigations" ON public.investigations;
    CREATE POLICY "Users can manage own investigations" ON public.investigations FOR ALL USING (true);

    DROP POLICY IF EXISTS "Users can manage own telemetry files" ON public.telemetry_files;
    CREATE POLICY "Users can manage own telemetry files" ON public.telemetry_files FOR ALL USING (true);

    DROP POLICY IF EXISTS "Users can manage own telemetry events" ON public.telemetry_events;
    CREATE POLICY "Users can manage own telemetry events" ON public.telemetry_events FOR ALL USING (true);

    DROP POLICY IF EXISTS "Users can manage own attack nodes" ON public.attack_nodes;
    CREATE POLICY "Users can manage own attack nodes" ON public.attack_nodes FOR ALL USING (true);

    DROP POLICY IF EXISTS "Users can manage own attack edges" ON public.attack_edges;
    CREATE POLICY "Users can manage own attack edges" ON public.attack_edges FOR ALL USING (true);

    DROP POLICY IF EXISTS "Users can manage own evidence" ON public.evidence_records;
    CREATE POLICY "Users can manage own evidence" ON public.evidence_records FOR ALL USING (true);

    DROP POLICY IF EXISTS "Users can manage own notes" ON public.investigation_notes;
    CREATE POLICY "Users can manage own notes" ON public.investigation_notes FOR ALL USING (true);

    DROP POLICY IF EXISTS "Users can manage own deception events" ON public.deception_events;
    CREATE POLICY "Users can manage own deception events" ON public.deception_events FOR ALL USING (true);

    DROP POLICY IF EXISTS "Users can manage own reports" ON public.investigation_reports;
    CREATE POLICY "Users can manage own reports" ON public.investigation_reports FOR ALL USING (true);
END $$;

-- ============================================================================
-- 11. FORENSIC DEMO DATASET SEED (REALISTIC ENTERPRISE INVESTIGATIONS)
-- ============================================================================
INSERT INTO public.profiles (id, email, username, password_hash, full_name, role, department, clearance, clearance_code, avatar)
VALUES
('usr_maya_thorne', 'maya@obsyron.corp', 'analyst_lead', '3503f8319f390e1cb3229b4e1f7c0067$c914c6fb73d84f88e7343e74ec80026e474ff1f7cfcf99b244d564fa7e85c2b9', 'Cmdr. Maya Thorne', 'Lead Forensic Director', 'Global Threat Intel & Forensic CIRT', 'Level 4 (Top Secret / SCI)', 'L4', '🛡️'),
('usr_alex_chen', 'alex@obsyron.corp', 'soc_tier2', '3503f8319f390e1cb3229b4e1f7c0067$c914c6fb73d84f88e7343e74ec80026e474ff1f7cfcf99b244d564fa7e85c2b9', 'Lt. Alex Chen', 'Senior Incident Responder', 'SOC Tier 2 Forensics', 'Level 3 (Secret / OpSec)', 'L3', '⚡'),
('usr_elena_rostova', 'elena@obsyron.corp', 'sec_auditor', '3503f8319f390e1cb3229b4e1f7c0067$c914c6fb73d84f88e7343e74ec80026e474ff1f7cfcf99b244d564fa7e85c2b9', 'Sgt. Elena Rostova', 'Compliance & Triage Specialist', 'Security Audit Division', 'Level 2 (Confidential)', 'L2', '🔍')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.investigations (id, user_id, name, description, severity, status, dataset_name, raw_log_count, malicious_signal_count, initial_access_entity, initial_access_tactic, blast_radius_count, overall_confidence, nodes_count, edges_count)
VALUES
('OBS-INV-20261114-001', 'usr_maya_thorne', 'Operation Red Relic (APT29 Infiltration)', 'Autonomous multi-stage intrusion reconstruction originating from TOR exit relay targeting CI/CD credentials and production database.', 'CRITICAL', 'ACTIVE', 'Enterprise Telemetry APT29', 357, 7, '185.220.101.47', 'Valid Accounts (T1078)', 15, 0.944, 29, 52),
('OBS-INV-20261114-002', 'usr_maya_thorne', 'Operation Velvet Typhoon (Kerberoasting Campaign)', 'Service Principal Name (SPN) ticket extraction attempt detected targeting Domain Controller CORP-DC-01 with RC4 downgrade requests.', 'HIGH', 'ACTIVE', 'Active Directory Kerberos Audits', 194, 5, '192.168.10.84', 'Kerberoasting (T1558.003)', 8, 0.887, 18, 27),
('OBS-INV-20261114-003', 'usr_maya_thorne', 'DarkSide Ransomware Staging (Subnet 10.0.4.0/24)', 'Volume Shadow Copy deletion (vssadmin delete shadows /all) and staging of encrypted archive targeting backup-nas-01. Quarantined via host firewall isolation.', 'CRITICAL', 'CONTAINED', 'Endpoint EDR & Sysmon Telemetry', 280, 6, 'wkst-09-fin', 'Inhibit System Recovery (T1490)', 12, 0.965, 22, 34),
('OBS-INV-20261114-004', 'usr_maya_thorne', 'Automated Brute Force on SSH Bastion', 'Low-and-slow SSH password spray originating from bulletproof hosting subnet; safely isolated and absorbed by OpenCanary honeypot trap.', 'MEDIUM', 'RESOLVED', 'Auth.log / OpenCanary Decoy', 142, 2, '45.33.32.156', 'Brute Force (T1110.003)', 2, 0.991, 6, 8)
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.telemetry_files (id, investigation_id, user_id, filename, file_size, file_format, record_count, valid_count, invalid_count, duplicate_count)
VALUES
('FILE-001', 'OBS-INV-20261114-001', 'usr_maya_thorne', 'apt29_telemetry_batch1.csv', 48210, 'CSV', 357, 350, 0, 7),
('FILE-002', 'OBS-INV-20261114-002', 'usr_maya_thorne', 'kerberos_event4769_dump.json', 24900, 'JSON', 194, 190, 0, 4),
('FILE-003', 'OBS-INV-20261114-003', 'usr_maya_thorne', 'sysmon_ransomware_staging.csv', 36400, 'CSV', 280, 275, 0, 5),
('FILE-004', 'OBS-INV-20261114-004', 'usr_maya_thorne', 'cowrie_auth_spray.log', 18200, 'LOG', 142, 140, 0, 2)
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.attack_nodes (id, investigation_id, user_id, entity_id, entity_type, label, severity, is_malicious, centrality, mitre_tags)
VALUES
('NODE-01', 'OBS-INV-20261114-001', 'usr_maya_thorne', '185.220.101.47', 'AUTH_ENDPOINT', '185.220.101.47 (TOR C2)', 'CRITICAL', TRUE, 0.354, '["T1078"]'::jsonb),
('NODE-02', 'OBS-INV-20261114-001', 'usr_maya_thorne', 'vpn.obsyron.corp', 'GATEWAY', 'vpn.obsyron.corp', 'HIGH', TRUE, 0.281, '["T1078"]'::jsonb),
('NODE-03', 'OBS-INV-20261114-001', 'usr_maya_thorne', 'emp_rohan', 'USER', 'emp_rohan (Identity)', 'HIGH', TRUE, 0.291, '["T1078.004"]'::jsonb),
('NODE-04', 'OBS-INV-20261114-001', 'usr_maya_thorne', 'wkst-04-dev', 'DEVICE', 'wkst-04-dev (Endpoint)', 'HIGH', TRUE, 0.482, '["T1021.001"]'::jsonb),
('NODE-05', 'OBS-INV-20261114-001', 'usr_maya_thorne', 'powershell.exe', 'PROCESS', 'powershell.exe', 'CRITICAL', TRUE, 0.412, '["T1059.001"]'::jsonb),
('NODE-06', 'OBS-INV-20261114-001', 'usr_maya_thorne', 'svc_ci_deploy', 'SERVICE', 'svc_ci_deploy (Service)', 'CRITICAL', TRUE, 0.228, '["T1558"]'::jsonb),
('NODE-07', 'OBS-INV-20261114-001', 'usr_maya_thorne', 'db-prod-01', 'DEVICE', 'db-prod-01 (Database)', 'CRITICAL', TRUE, 0.186, '["T1021.002"]'::jsonb),
('NODE-08', 'OBS-INV-20261114-001', 'usr_maya_thorne', '198.51.100.23', 'AUTH_ENDPOINT', '198.51.100.23 (Drop Server)', 'CRITICAL', TRUE, 0.125, '["T1048"]'::jsonb),
('NODE-09', 'OBS-INV-20261114-001', 'usr_maya_thorne', 'cowrie-ssh-dmz', 'DECEPTION_SENSOR', 'cowrie-ssh-dmz (Honeytrap)', 'LOW', FALSE, 0.050, '["T1046"]'::jsonb)
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.investigation_notes (id, investigation_id, user_id, author_name, title, content)
VALUES
('NOTE-01', 'OBS-INV-20261114-001', 'usr_maya_thorne', 'Cmdr. Maya Thorne', 'Initial Ingress Triage & Patient Zero Identification', 'Observed external IP 185.220.101.47 authenticating via employee portal from known TOR exit relay. Active session issued to emp_rohan without MFA challenge.'),
('NOTE-02', 'OBS-INV-20261114-001', 'usr_maya_thorne', 'Lt. Alex Chen', 'Host Subnet Isolation for wkst-04-dev', 'Developer host wkst-04-dev spawned encoded PowerShell script executing Invoke-Mimikatz against LSASS memory. Isolated host subnet egress.'),
('NOTE-03', 'OBS-INV-20261114-001', 'usr_maya_thorne', 'Sgt. Elena Rostova', 'Perimeter Firewall Block Applied for 185.220.101.47', 'Outbound TCP connection to 198.51.100.23 on port 443 blocked at perimeter firewall. Stolen database dump contained in quarantine zone.')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.deception_events (id, investigation_id, user_id, sensor_type, src_ip, target_decoy, trigger_timestamp, payload, severity)
VALUES
('DEC-01', 'OBS-INV-20261114-001', 'usr_maya_thorne', 'Cowrie SSH Decoy', '185.220.101.47', 'cowrie-ssh-dmz', '2026-03-31 01:14:12+00', 'uname -a', 'CRITICAL'),
('DEC-02', 'OBS-INV-20261114-001', 'usr_maya_thorne', 'Cowrie SSH Decoy', '185.220.101.47', 'cowrie-ssh-dmz', '2026-03-31 01:14:38+00', 'cat /etc/shadow', 'CRITICAL'),
('DEC-03', 'OBS-INV-20261114-001', 'usr_maya_thorne', 'OpenCanary MySQL', '10.0.8.24', 'db-canary-01', '2026-03-31 01:18:22+00', 'SELECT * FROM users_admin', 'HIGH'),
('DEC-04', 'OBS-INV-20261114-001', 'usr_maya_thorne', 'OpenCanary AWS Bait', '185.220.101.47', 'aws-decoy-bucket', '2026-03-31 01:21:05+00', 'GET /credentials/backup.enc', 'CRITICAL')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.investigation_reports (id, investigation_id, user_id, format, title, content)
VALUES
('REP-01', 'OBS-INV-20261114-001', 'usr_maya_thorne', 'markdown', 'Executive Cyber Incident Briefing (NIST SP 800-61 Rev 2)', '# NIST SP 800-61 Rev 2 Incident Briefing\n\n## Summary\nCritical unauthorized external ingress detected from 185.220.101.47 targeting production database cluster.\n\n## Recommendations\n1. Enforce FIDO2 WebAuthn MFA\n2. Block IP 185.220.101.47\n3. Rotate CI/CD deploy tokens.'),
('REP-02', 'OBS-INV-20261114-001', 'usr_maya_thorne', 'json', 'Technical Incident Data Exchange (OASIS STIX 2.1)', '{"spec_version": "2.1", "type": "bundle", "id": "bundle--8f7a8b9c", "objects_count": 230}'),
('REP-03', 'OBS-INV-20261114-001', 'usr_maya_thorne', 'csv', 'Full CIRT Forensic Evidence Ledger Export', 'event_id,timestamp,source,target,action,mitre_tag,severity,sha256\nEVT-001,2026-03-31T01:14:02Z,185.220.101.47,vpn.obsyron.corp,EXTERNAL_INGRESS,T1078,CRITICAL,160bce742077ef960056115f3f14a6f840de042fcbb65693cde49436d1f007e0\n')
ON CONFLICT (id) DO NOTHING;

-- ═══════════════════════════════════════════════════════════════════════════
-- 12. SIMULATION SESSIONS TABLE & POLICIES
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS public.simulation_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    scenario_id TEXT NOT NULL,
    scenario_name TEXT NOT NULL,
    status TEXT DEFAULT 'COMPLETED',
    mitre_technique TEXT,
    events_generated INTEGER DEFAULT 0,
    telemetry_type TEXT DEFAULT 'SYSMON_WINDOWS',
    provenance TEXT DEFAULT 'CONTROLLED_SIMULATION',
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

ALTER TABLE public.simulation_sessions ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Operators manage their own simulation sessions"
ON public.simulation_sessions
FOR ALL
USING (auth.uid()::text = user_id OR user_id = 'usr_maya_thorne');
