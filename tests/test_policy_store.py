"""Tests for PostgreSQL + pgvector policy tables and store (Warden Phase 2 / Lock 9).

Covers:
- setup_policy_tables idempotency and table creation
- add_policy writes policies row + policy_versions initial version (version=1)
- update_policy appends new version (version=2) with attribution
- policy_versions append-only trigger rejects UPDATE and DELETE (Lock 9 guardrail)
- pgvector semantic search (cosine similarity ordering)
- Drop-in integration with L1L2PolicyEngine
"""

from __future__ import annotations

import asyncio
import sys
import uuid
from typing import Any

import psycopg
import pytest

from warden.policy.engine import HashEmbeddings, L1L2PolicyEngine
from warden.policy.store import PgVectorPolicyStore, setup_policy_tables
from warden.models import Action, ActionKind

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


def _action(name: str, payload: dict[str, Any] | None = None) -> Action:
    return Action(
        id=str(uuid.uuid4()),
        kind=ActionKind.TOOL,
        name=name,
        payload=payload if payload is not None else {},
        run_id=str(uuid.uuid4()),
        thread_id="t-store-test",
    )


def test_setup_policy_tables_creates_tables_and_is_idempotent(pg_uri: str) -> None:
    # 1st call creates
    setup_policy_tables(pg_uri)
    # 2nd call is idempotent
    setup_policy_tables(pg_uri)

    with psycopg.connect(pg_uri) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT table_name
                FROM information_schema.tables
                WHERE table_schema = 'public'
                  AND table_name IN ('policies', 'policy_versions')
                ORDER BY table_name;
                """
            )
            tables = [row[0] for row in cur.fetchall()]
            assert tables == ["policies", "policy_versions"]


def test_add_policy_creates_row_and_version_1(pg_uri: str) -> None:
    setup_policy_tables(pg_uri)
    store = PgVectorPolicyStore(pg_uri)

    pid = f"pol-{uuid.uuid4().hex[:8]}"
    store.add_policy(
        policy_id=pid,
        verdict="deny",
        text="destructive SQL drops are forbidden",
        name=pid,
        who="alice",
        description="Block drop table",
    )

    p = store.get_policy(pid)
    assert p is not None
    assert p["name"] == pid
    assert p["action"] == "deny"
    assert p["current_version"] == 1
    assert p["rule_text"] == "destructive SQL drops are forbidden"

    versions = store.get_versions(pid)
    assert len(versions) == 1
    assert versions[0].version == 1
    assert versions[0].who == "alice"
    assert versions[0].content["action"] == "deny"


def test_update_policy_appends_version_and_updates_state(pg_uri: str) -> None:
    setup_policy_tables(pg_uri)
    store = PgVectorPolicyStore(pg_uri)

    pid = f"pol-{uuid.uuid4().hex[:8]}"
    store.add_policy(
        policy_id=pid,
        verdict="escalate",
        text="email sending requires approval",
        who="alice",
    )

    next_ver = store.update_policy(
        pid,
        verdict="allow",
        text="internal email allowed",
        who="bob",
    )
    assert next_ver == 2

    p = store.get_policy(pid)
    assert p is not None
    assert p["action"] == "allow"
    assert p["current_version"] == 2
    assert p["rule_text"] == "internal email allowed"

    versions = store.get_versions(pid)
    assert len(versions) == 2
    assert versions[0].version == 1
    assert versions[0].who == "alice"
    assert versions[1].version == 2
    assert versions[1].who == "bob"
    assert versions[1].content["action"] == "allow"


def test_policy_versions_append_only_trigger_blocks_update_and_delete(pg_uri: str) -> None:
    setup_policy_tables(pg_uri)
    store = PgVectorPolicyStore(pg_uri)

    pid = f"pol-{uuid.uuid4().hex[:8]}"
    store.add_policy(
        policy_id=pid,
        verdict="deny",
        text="cannot touch files",
        who="alice",
    )

    with psycopg.connect(pg_uri) as conn:
        with conn.cursor() as cur:
            # UPDATE must fail
            with pytest.raises(psycopg.DatabaseError, match="append-only"):
                cur.execute("UPDATE policy_versions SET who = 'mallory';")
            conn.rollback()

            # DELETE must fail
            with pytest.raises(psycopg.DatabaseError, match="append-only"):
                cur.execute("DELETE FROM policy_versions;")
            conn.rollback()


def test_pgvector_search_returns_similarity_ranking(pg_uri: str) -> None:
    setup_policy_tables(pg_uri)
    store = PgVectorPolicyStore(pg_uri)

    pid1 = f"pol-{uuid.uuid4().hex[:8]}"
    pid2 = f"pol-{uuid.uuid4().hex[:8]}"

    # Vector 1 aligns with query [1.0, 0.0]
    store.add_policy(
        policy_id=pid1,
        verdict="deny",
        text="rule 1",
        embedding=[1.0, 0.0],
        who="alice",
    )
    # Vector 2 is orthogonal [0.0, 1.0]
    store.add_policy(
        policy_id=pid2,
        verdict="allow",
        text="rule 2",
        embedding=[0.0, 1.0],
        who="alice",
    )

    hits = store.search([1.0, 0.0], k=2)
    assert len(hits) >= 2
    # First hit should be pid1 with similarity ~1.0
    top_sim, top_id, top_verdict = hits[0]
    assert top_id == store.get_policy(pid1)["id"]  # type: ignore[index]
    assert top_verdict == "deny"
    assert top_sim > 0.99


def test_integration_with_l1l2_policy_engine(pg_uri: str) -> None:
    setup_policy_tables(pg_uri)
    store = PgVectorPolicyStore(pg_uri)
    emb = HashEmbeddings(dim=64)

    # Seed a policy in Postgres
    action_text = "list_orders list open orders"
    vec = emb.embed_query(action_text)
    pid = f"pol-{uuid.uuid4().hex[:8]}"
    store.add_policy(
        policy_id=pid,
        verdict="deny",
        text=action_text,
        embedding=vec,
        who="alice",
    )

    engine = L1L2PolicyEngine(emb, store=store, threshold=0.99)
    # Action matching the seeded text
    act = _action("list_orders", {"query": "list open orders"})
    verdict = engine.evaluate(act)
    assert verdict == "deny"
