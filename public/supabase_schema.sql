-- ============================================================================
-- OBSYRON XTM 2.0 — SUPABASE POSTGRESQL DATABASE SCHEMA
-- HackInnovision 2026 (Track C: Cyber Forensic Graph Reconstruction)
-- Project: https://ugkekxiwvgsitzqduzxq.supabase.co
-- ============================================================================

-- 1. Investigations Table
-- Stores forensic case records, attack graph KPIs, and root cause summaries
CREATE TABLE IF NOT EXISTS public.investigations (
    id TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    status TEXT DEFAULT 'COMPLETED',
    dataset_name TEXT DEFAULT 'Enterprise Telemetry APT29',
    raw_log_count INT DEFAULT 0,
    malicious_signal_count INT DEFAULT 0,
    initial_access_entity TEXT,
    initial_access_tactic TEXT,
    blast_radius_count INT DEFAULT 0,
    overall_confidence NUMERIC(5, 4) DEFAULT 0.0,
    nodes_count INT DEFAULT 0,
    edges_count INT DEFAULT 0,
    analysis_payload JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_investigations_created_at ON public.investigations(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_investigations_initial_access ON public.investigations(initial_access_entity);

-- 2. Audit Logs Table
-- Stores normalized enterprise forensic logs and synthetic APT injections
CREATE TABLE IF NOT EXISTS public.audit_logs (
    log_id TEXT PRIMARY KEY,
    raw_timestamp TIMESTAMPTZ,
    normalized_timestamp TIMESTAMPTZ,
    host TEXT,
    entity_type TEXT DEFAULT 'GENERIC',
    source TEXT,
    target TEXT,
    action TEXT,
    mitre_tag TEXT,
    severity TEXT DEFAULT 'LOW',
    confidence NUMERIC(5, 4) DEFAULT 0.7,
    is_malicious BOOLEAN DEFAULT FALSE,
    raw_payload JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON public.audit_logs(normalized_timestamp ASC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_malicious ON public.audit_logs(is_malicious) WHERE is_malicious = TRUE;
CREATE INDEX IF NOT EXISTS idx_audit_logs_mitre ON public.audit_logs(mitre_tag);

-- 3. Operators Table
-- Stores cybersecurity forensic operator clearance and authorization credentials
CREATE TABLE IF NOT EXISTS public.operators (
    username TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    role TEXT DEFAULT 'Forensic Investigator',
    clearance TEXT DEFAULT 'Level 3',
    clearance_code TEXT DEFAULT 'L3',
    mfa_verified BOOLEAN DEFAULT TRUE,
    department TEXT DEFAULT 'Threat Intelligence & Forensic CIRT',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Seed default operator profiles
INSERT INTO public.operators (username, name, role, clearance, clearance_code, mfa_verified, department)
VALUES
    ('analyst_lead', 'Cmdr. Maya Thorne', 'Lead Forensic Director', 'Level 4 (Top Secret / SCI)', 'L4', TRUE, 'Global Threat Intel & Forensic CIRT'),
    ('soc_investigator', 'Lt. Alex Chen', 'Senior Incident Responder', 'Level 3 (Secret)', 'L3', TRUE, 'SOC Tier 3 Forensics'),
    ('tactical_ops', 'Sgt. Elena Rostova', 'Containment & Triage Specialist', 'Level 2 (Confidential)', 'L2', TRUE, 'Defensive Triage Unit')
ON CONFLICT (username) DO UPDATE
SET updated_at = NOW();

-- 4. Containment Actions Table
-- Stores forensic containment measures executed by operators
CREATE TABLE IF NOT EXISTS public.containment_actions (
    action_id TEXT PRIMARY KEY,
    investigation_id TEXT REFERENCES public.investigations(id) ON DELETE SET NULL,
    entity_id TEXT NOT NULL,
    action_type TEXT NOT NULL,
    status TEXT DEFAULT 'EXECUTED',
    executed_at TIMESTAMPTZ DEFAULT NOW(),
    operator TEXT DEFAULT 'Cmdr. Maya Thorne',
    impact TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_containment_actions_time ON public.containment_actions(executed_at DESC);

-- ============================================================================
-- ROW LEVEL SECURITY (RLS) POLICIES
-- Permissive policies for anon and authenticated API clients
-- ============================================================================

ALTER TABLE public.investigations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.operators ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.containment_actions ENABLE ROW LEVEL SECURITY;

-- Allow read/write for all client connections with anon key
DO $$
BEGIN
    DROP POLICY IF EXISTS "Public select investigations" ON public.investigations;
    CREATE POLICY "Public select investigations" ON public.investigations FOR SELECT USING (true);

    DROP POLICY IF EXISTS "Public insert/update investigations" ON public.investigations;
    CREATE POLICY "Public insert/update investigations" ON public.investigations FOR ALL USING (true);

    DROP POLICY IF EXISTS "Public select audit_logs" ON public.audit_logs;
    CREATE POLICY "Public select audit_logs" ON public.audit_logs FOR SELECT USING (true);

    DROP POLICY IF EXISTS "Public insert audit_logs" ON public.audit_logs;
    CREATE POLICY "Public insert audit_logs" ON public.audit_logs FOR ALL USING (true);

    DROP POLICY IF EXISTS "Public select operators" ON public.operators;
    CREATE POLICY "Public select operators" ON public.operators FOR SELECT USING (true);

    DROP POLICY IF EXISTS "Public insert/update operators" ON public.operators;
    CREATE POLICY "Public insert/update operators" ON public.operators FOR ALL USING (true);

    DROP POLICY IF EXISTS "Public select containment_actions" ON public.containment_actions;
    CREATE POLICY "Public select containment_actions" ON public.containment_actions FOR SELECT USING (true);

    DROP POLICY IF EXISTS "Public insert containment_actions" ON public.containment_actions;
    CREATE POLICY "Public insert containment_actions" ON public.containment_actions FOR ALL USING (true);
END $$;
