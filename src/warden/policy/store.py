"""PostgreSQL + pgvector PolicyStore (Warden Phase 2 / Lock 9).

Owns:
- DDL for `policies` and append-only `policy_versions` tables
- pgvector semantic retrieval adapter satisfying `PolicyVectorStore` (engine.py)
- Version history audit trail (Lock 9: edits are logged, no row is updated/deleted in policy_versions)
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import psycopg
from psycopg import sql

from warden.policy.engine import PolicyVectorStore
from warden.policy.versions import PolicyVersionRecord

logger = logging.getLogger("warden.policy.store")

# DDL definitions per ARCHITECTURE.md §5 and docs/DATA_MODEL.md §6
POLICIES_TABLE_DDL = """
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
"""

POLICY_VERSIONS_TABLE_DDL = """
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
"""


def _ensure_uuid(val: str) -> str:
    """Return val if valid UUID string, else derive a deterministic UUID."""
    try:
        return str(uuid.UUID(val))
    except (ValueError, AttributeError):
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, val))


def _format_vector(vec: list[float] | None) -> str | None:
    """Format list of floats into PostgreSQL vector literal '[x,y,z]'."""
    if vec is None:
        return None
    return f"[{','.join(str(float(x)) for x in vec)}]"


def setup_policy_tables(conn_or_uri: psycopg.Connection[Any] | str) -> None:
    """Create pgvector extension, policies, and policy_versions tables if not exist."""
    if isinstance(conn_or_uri, str):
        with psycopg.connect(conn_or_uri) as conn:
            _execute_ddl(conn)
    else:
        _execute_ddl(conn_or_uri)


def _execute_ddl(conn: psycopg.Connection[Any]) -> None:
    with conn.cursor() as cur:
        cur.execute(POLICIES_TABLE_DDL)
        cur.execute(POLICY_VERSIONS_TABLE_DDL)
    conn.commit()
    logger.info("policy.tables.setup_complete")


@dataclass(frozen=True)
class PolicyRecord:
    id: str
    name: str
    action: str
    description: str | None
    rule_text: str
    embedding: list[float] | None
    active: bool
    created_at: datetime
    current_version: int


class PgVectorPolicyStore(PolicyVectorStore):
    """PostgreSQL + pgvector backed implementation of PolicyVectorStore.

    Drop-in replacement for InMemoryPolicyStore in L1L2PolicyEngine.
    """

    def __init__(self, conn_string: str) -> None:
        self._conn_string = conn_string

    @property
    def conn_string(self) -> str:
        return self._conn_string

    def setup(self) -> None:
        """Initialize tables and triggers."""
        setup_policy_tables(self._conn_string)

    def search(
        self, query_embedding: list[float], k: int = 1
    ) -> list[tuple[float, str, str]]:
        """Return [(similarity, policy_id, verdict)] ordered best-first.

        Uses cosine distance operator `<=>` where similarity = 1 - (embedding <=> query).
        """
        vec_literal = _format_vector(query_embedding)
        if not vec_literal:
            return []

        dim = len(query_embedding)
        query = """
            SELECT
                id::text,
                action,
                (1.0 - (embedding <=> %s::vector)) AS similarity
            FROM policies
            WHERE active = true
              AND embedding IS NOT NULL
              AND vector_dims(embedding) = %s
            ORDER BY embedding <=> %s::vector ASC
            LIMIT %s;
        """
        results: list[tuple[float, str, str]] = []
        try:
            with psycopg.connect(self._conn_string) as conn:
                with conn.cursor() as cur:
                    cur.execute(query, (vec_literal, dim, vec_literal, k))
                    for row in cur.fetchall():
                        policy_id_str, action, similarity = row[0], row[1], float(row[2])
                        results.append((similarity, policy_id_str, action))
        except Exception as e:
            logger.error("pgvector.search_failed: %s", e)
            return []
        return results

    def add_policy(
        self,
        policy_id: str,
        verdict: str,
        text: str,
        *,
        embedding: list[float] | None = None,
        name: str | None = None,
        description: str | None = None,
        who: str = "system",
    ) -> str:
        """Add policy row and write initial version 1 (Lock 9: edits are logged)."""
        pid = _ensure_uuid(policy_id)
        pname = name if name is not None else policy_id
        vec_str = _format_vector(embedding)

        insert_policy_sql = """
            INSERT INTO policies (id, name, action, description, rule_text, embedding, active)
            VALUES (%s, %s, %s, %s, %s, %s::vector, true)
            ON CONFLICT (id) DO UPDATE SET
                action = EXCLUDED.action,
                description = EXCLUDED.description,
                rule_text = EXCLUDED.rule_text,
                embedding = EXCLUDED.embedding,
                active = true
            RETURNING id::text;
        """

        snapshot = {
            "id": pid,
            "name": pname,
            "action": verdict,
            "description": description,
            "rule_text": text,
            "active": True,
        }

        insert_version_sql = """
            INSERT INTO policy_versions (policy_id, version, content, who)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (policy_id, version) DO NOTHING;
        """

        with psycopg.connect(self._conn_string) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    insert_policy_sql,
                    (pid, pname, verdict, description, text, vec_str),
                )
                cur.execute(
                    insert_version_sql,
                    (pid, 1, json.dumps(snapshot), who),
                )
            conn.commit()
        return pid

    def update_policy(
        self,
        policy_id: str,
        *,
        verdict: str | None = None,
        text: str | None = None,
        embedding: list[float] | None = None,
        description: str | None = None,
        active: bool | None = None,
        who: str,
    ) -> int:
        """Update an existing policy and append a new version row to policy_versions."""
        if not who.strip():
            raise ValueError("Attribution required: 'who' must not be empty (Lock 8/9)")

        pid = _ensure_uuid(policy_id)

        with psycopg.connect(self._conn_string) as conn:
            with conn.cursor() as cur:
                # 1. Fetch current row
                cur.execute(
                    "SELECT name, action, description, rule_text, active FROM policies WHERE id = %s",
                    (pid,),
                )
                row = cur.fetchone()
                if not row:
                    raise KeyError(f"Policy not found: {policy_id}")

                curr_name, curr_action, curr_desc, curr_text, curr_active = row

                new_action = verdict if verdict is not None else curr_action
                new_text = text if text is not None else curr_text
                new_desc = description if description is not None else curr_desc
                new_active = active if active is not None else curr_active

                # 2. Get latest version
                cur.execute(
                    "SELECT COALESCE(MAX(version), 0) FROM policy_versions WHERE policy_id = %s",
                    (pid,),
                )
                v_row = cur.fetchone()
                latest_version = int(v_row[0]) if v_row is not None else 0
                next_version = latest_version + 1

                # 3. Update policies table
                vec_str = _format_vector(embedding)
                if vec_str is not None:
                    cur.execute(
                        """
                        UPDATE policies
                        SET action = %s, rule_text = %s, description = %s, active = %s, embedding = %s::vector
                        WHERE id = %s
                        """,
                        (new_action, new_text, new_desc, new_active, vec_str, pid),
                    )
                else:
                    cur.execute(
                        """
                        UPDATE policies
                        SET action = %s, rule_text = %s, description = %s, active = %s
                        WHERE id = %s
                        """,
                        (new_action, new_text, new_desc, new_active, pid),
                    )

                # 4. Append to policy_versions
                snapshot = {
                    "id": pid,
                    "name": curr_name,
                    "action": new_action,
                    "description": new_desc,
                    "rule_text": new_text,
                    "active": new_active,
                }
                cur.execute(
                    """
                    INSERT INTO policy_versions (policy_id, version, content, who)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (pid, next_version, json.dumps(snapshot), who),
                )
            conn.commit()
        return next_version

    def get_policy(self, policy_id: str) -> dict[str, Any] | None:
        """Fetch policy by id or name."""
        pid = _ensure_uuid(policy_id)
        query = """
            SELECT
                p.id::text,
                p.name,
                p.action,
                p.description,
                p.rule_text,
                p.active,
                p.created_at,
                COALESCE(MAX(pv.version), 1) as current_version
            FROM policies p
            LEFT JOIN policy_versions pv ON p.id = pv.policy_id
            WHERE p.id = %s OR p.name = %s
            GROUP BY p.id;
        """
        with psycopg.connect(self._conn_string) as conn:
            with conn.cursor() as cur:
                cur.execute(query, (pid, policy_id))
                row = cur.fetchone()
                if not row:
                    return None
                return {
                    "id": row[0],
                    "name": row[1],
                    "action": row[2],
                    "description": row[3],
                    "rule_text": row[4],
                    "active": row[5],
                    "created_at": row[6].isoformat() if hasattr(row[6], "isoformat") else str(row[6]),
                    "current_version": int(row[7]),
                }

    def list_policies(self, active_only: bool = False) -> list[dict[str, Any]]:
        """List policies with their current versions."""
        where = "WHERE p.active = true" if active_only else ""
        query = f"""
            SELECT
                p.id::text,
                p.name,
                p.action,
                p.description,
                p.rule_text,
                p.active,
                p.created_at,
                COALESCE(MAX(pv.version), 1) as current_version
            FROM policies p
            LEFT JOIN policy_versions pv ON p.id = pv.policy_id
            {where}
            GROUP BY p.id
            ORDER BY p.created_at ASC;
        """
        results: list[dict[str, Any]] = []
        with psycopg.connect(self._conn_string) as conn:
            with conn.cursor() as cur:
                cur.execute(query)
                for row in cur.fetchall():
                    results.append(
                        {
                            "id": row[0],
                            "name": row[1],
                            "action": row[2],
                            "description": row[3],
                            "rule_text": row[4],
                            "active": row[5],
                            "created_at": row[6].isoformat() if hasattr(row[6], "isoformat") else str(row[6]),
                            "current_version": int(row[7]),
                        }
                    )
        return results

    def get_versions(self, policy_id: str) -> list[PolicyVersionRecord]:
        """Fetch all versions for a policy ordered by version ASC."""
        pid = _ensure_uuid(policy_id)
        query = """
            SELECT id::text, policy_id::text, version, content, who, changed_at
            FROM policy_versions
            WHERE policy_id = %s
            ORDER BY version ASC;
        """
        records: list[PolicyVersionRecord] = []
        with psycopg.connect(self._conn_string) as conn:
            with conn.cursor() as cur:
                cur.execute(query, (pid,))
                for row in cur.fetchall():
                    content = row[3] if isinstance(row[3], dict) else json.loads(row[3])
                    records.append(
                        PolicyVersionRecord(
                            id=row[0],
                            policy_id=row[1],
                            version=int(row[2]),
                            content=content,
                            who=row[4],
                            changed_at=row[5],
                        )
                    )
        return records


def main() -> None:
    """CLI to apply policy migrations to a PostgreSQL database."""
    parser = argparse.ArgumentParser(description="Warden PostgreSQL Policy Tables Setup")
    parser.add_argument(
        "--uri",
        default=None,
        help="Postgres URI (defaults to WARDEN_PG_URI or bundled pgserver)",
    )
    args = parser.parse_args()

    import os
    conn_uri = args.uri or os.environ.get("WARDEN_PG_URI")
    if not conn_uri:
        from tests.cli_chat import _resolve_pg_uri
        conn_uri = _resolve_pg_uri(None)

    print(f"Applying policy tables to PostgreSQL: {conn_uri}")
    setup_policy_tables(conn_uri)
    print("Successfully created policies and policy_versions tables.")


if __name__ == "__main__":
    main()
