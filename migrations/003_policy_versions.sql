-- 003_policy_versions.sql
-- Append-only policy versions table (Warden Lock 9: accountability & audit trail)

CREATE TABLE IF NOT EXISTS policy_versions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id   UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    version     INTEGER NOT NULL CHECK (version >= 1),
    content     JSONB NOT NULL,
    who         TEXT NOT NULL,
    changed_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_policy_versions_version UNIQUE (policy_id, version)
);

CREATE INDEX IF NOT EXISTS idx_policy_versions_policy_id ON policy_versions(policy_id);
CREATE INDEX IF NOT EXISTS idx_policy_versions_changed_at ON policy_versions(changed_at);

-- Lock 9 Guardrail: policy_versions is strictly append-only.
-- Updates and deletes are rejected at the database level.
CREATE OR REPLACE FUNCTION prevent_policy_versions_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'policy_versions is append-only (Lock 9): updates and deletes are forbidden';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_policy_versions_no_update_delete ON policy_versions;

CREATE TRIGGER trg_policy_versions_no_update_delete
BEFORE UPDATE OR DELETE ON policy_versions
FOR EACH ROW EXECUTE FUNCTION prevent_policy_versions_modification();
