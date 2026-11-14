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
