-- 002_policies.sql
-- Policies table with pgvector semantic embedding (Warden Phase 2 / Lock 9)

CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS policies (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL UNIQUE,
    action      TEXT NOT NULL CHECK (action IN ('allow', 'escalate', 'deny')),
    description TEXT,
    rule_text   TEXT NOT NULL,
    embedding   VECTOR,
    active      BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_policies_active ON policies(active);
CREATE INDEX IF NOT EXISTS idx_policies_action ON policies(action);
CREATE INDEX IF NOT EXISTS idx_policies_name ON policies(name);
