"""Unit tests for GrantsStore, Grant lifecycle, and ScopeRule matching matrix."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from warden.grants import (
    Grant,
    GrantStatus,
    InMemoryGrantsStore,
    ScopeRule,
)


def _fixed_clock(start_time: datetime) -> tuple[InMemoryGrantsStore, list[datetime]]:
    curr = [start_time]

    def tick() -> datetime:
        return curr[0]

    store = InMemoryGrantsStore(clock=tick)
    return store, curr


def test_scope_rule_exact_table_matching() -> None:
    rule = ScopeRule(tool="exec_db_mutation", constraints={"table": "staging_imports"})
    # Direct payload key
    assert rule.matches("exec_db_mutation", {"table": "staging_imports"})
    # SQL payload DDL extraction
    assert rule.matches("exec_db_mutation", {"sql": "DROP TABLE staging_imports;"})
    # Table mismatch
    assert not rule.matches("exec_db_mutation", {"sql": "DROP TABLE users;"})
    # Tool mismatch
    assert not rule.matches("other_tool", {"sql": "DROP TABLE staging_imports;"})


def test_scope_rule_exact_service_matching() -> None:
    rule = ScopeRule(tool="restart_service", constraints={"service": "postgres_primary"})
    assert rule.matches("restart_service", {"service": "postgres_primary"})
    assert not rule.matches("restart_service", {"service": "redis_cache"})
    assert not rule.matches("send_email", {"service": "postgres_primary"})


def test_scope_rule_path_prefix_matching() -> None:
    rule = ScopeRule(tool="exec_shell", constraints={"path_prefix": "/workspace/tmp/"})
    assert rule.matches("exec_shell", {"cmd": "rm -rf /workspace/tmp/scratch"})
    assert not rule.matches("exec_shell", {"cmd": "rm -rf /workspace/data"})
    assert not rule.matches("exec_shell", {"cmd": "rm -rf /workspace/tmp_production"})


def test_scope_rule_batch_delete_targets_matching() -> None:
    rule = ScopeRule(tool="batch_delete_files", constraints={"path_prefix": "/workspace/tmp/"})
    # All targets within prefix
    payload_ok = {
        "targets": ["/workspace/tmp/cache1", "/workspace/tmp/cache2"],
        "target_resource": "/workspace/tmp/",
    }
    assert rule.matches("batch_delete_files", payload_ok)

    # One target outside prefix
    payload_bad = {
        "targets": ["/workspace/tmp/cache1", "/etc/shadow"],
        "target_resource": "/workspace/tmp/",
    }
    assert not rule.matches("batch_delete_files", payload_bad)


def test_grant_expiry_boundary() -> None:
    t0 = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    store, curr = _fixed_clock(t0)

    grant = Grant(
        id="gr_exp_01",
        thread_id="thr_exp",
        granted_by="alice",
        scope=(ScopeRule(tool="exec_db_mutation", constraints={"table": "tmp_tbl"}),),
        ttl_seconds=300,
        max_uses=5,
        created_at=t0,
    )
    store.issue(grant)

    # 1 second before expiry
    curr[0] = t0 + timedelta(seconds=299)
    g_active = store.find_covering_grant("thr_exp", "exec_db_mutation", {"table": "tmp_tbl"})
    assert g_active is not None
    assert g_active.status == GrantStatus.ACTIVE

    # Exactly at TTL boundary
    curr[0] = t0 + timedelta(seconds=300)
    g_expired = store.find_covering_grant("thr_exp", "exec_db_mutation", {"table": "tmp_tbl"})
    assert g_expired is None

    # Lazy status update on get()
    fetched = store.get("gr_exp_01")
    assert fetched is not None
    assert fetched.status == GrantStatus.EXPIRED


def test_grant_max_uses_exhaustion() -> None:
    t0 = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    store, _ = _fixed_clock(t0)

    grant = Grant(
        id="gr_use_01",
        thread_id="thr_use",
        granted_by="bob",
        scope=(ScopeRule(tool="send_email"),),
        ttl_seconds=1800,
        max_uses=2,
        created_at=t0,
    )
    store.issue(grant)

    # First consume
    g1, left1 = store.consume("gr_use_01")
    assert g1 is not None and g1.uses == 1 and left1 == 1
    assert g1.status == GrantStatus.ACTIVE

    # Second consume (exhausts)
    g2, left2 = store.consume("gr_use_01")
    assert g2 is not None and g2.uses == 2 and left2 == 0
    assert g2.status == GrantStatus.EXHAUSTED

    # Third consume fails
    g3, left3 = store.consume("gr_use_01")
    assert g3 is None and left3 == 0

    # Covering grant search returns None once exhausted
    assert store.find_covering_grant("thr_use", "send_email", {}) is None


def test_grant_revocation() -> None:
    t0 = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    store, _ = _fixed_clock(t0)

    grant = Grant(
        id="gr_rev_01",
        thread_id="thr_rev",
        granted_by="charlie",
        scope=(ScopeRule(tool="restart_service"),),
        ttl_seconds=1800,
        max_uses=5,
        created_at=t0,
    )
    store.issue(grant)

    # Active initially
    assert store.find_covering_grant("thr_rev", "restart_service", {}) is not None

    # Revoke
    revoked = store.revoke("gr_rev_01", revoked_by="admin")
    assert revoked is not None
    assert revoked.status == GrantStatus.REVOKED

    # No longer covering
    assert store.find_covering_grant("thr_rev", "restart_service", {}) is None

    # Cannot consume
    g_consume, _ = store.consume("gr_rev_01")
    assert g_consume is None


def test_corrupt_and_missing_grant_fail_closed() -> None:
    store = InMemoryGrantsStore()

    # Non-existent grant
    assert store.get("non_existent") is None
    assert store.consume("non_existent") == (None, 0)
    assert store.revoke("non_existent") is None
    assert store.find_covering_grant("thr_none", "tool", {}) is None
    assert store.list_for_thread("thr_none") == []


def test_scope_rule_multi_arg_shell_rejected() -> None:
    rule = ScopeRule(tool="exec_shell", constraints={"path_prefix": "/workspace/tmp/"})
    # Multi-argument command targeting outside scope
    assert not rule.matches("exec_shell", {"cmd": "rm -rf /workspace/tmp/scratch /workspace/data"})
    assert not rule.matches("exec_shell", {"cmd": "rm -rf /workspace/tmp/scratch /etc/shadow"})
    # Multi-argument command where all targets are within scope
    assert rule.matches("exec_shell", {"cmd": "rm -rf /workspace/tmp/a /workspace/tmp/b"})


def test_scope_rule_batch_delete_target_resource_outside_rejected() -> None:
    rule = ScopeRule(tool="batch_delete_files", constraints={"path_prefix": "/workspace/tmp/"})
    payload = {"target_resource": "/workspace/data", "targets": ["/workspace/tmp/1"]}
    assert not rule.matches("batch_delete_files", payload)


def test_scope_rule_path_traversal_rejected() -> None:
    rule = ScopeRule(tool="exec_shell", constraints={"path_prefix": "/workspace/tmp/"})
    assert not rule.matches("exec_shell", {"path": "/workspace/tmp/../etc/passwd"})
    assert not rule.matches("exec_shell", {"cmd": "rm -rf /workspace/tmp/../etc/shadow"})


def test_scope_rule_prefix_boundary_matching() -> None:
    rule = ScopeRule(tool="exec_shell", constraints={"path_prefix": "/workspace/tmp"})
    assert not rule.matches("exec_shell", {"path": "/workspace/tmp_production/data"})
    assert rule.matches("exec_shell", {"path": "/workspace/tmp/data"})


def test_scope_rule_unhandled_constraints_fail_closed() -> None:
    rule = ScopeRule(tool="restart_service", constraints={"service": "postgres", "environment": "staging"})
    # Payload matches service but differs on environment
    assert not rule.matches("restart_service", {"service": "postgres", "environment": "production"})
    # Payload matches all constraints
    assert rule.matches("restart_service", {"service": "postgres", "environment": "staging"})


def test_grant_status_preservation_on_issue() -> None:
    store = InMemoryGrantsStore()
    g_rev = Grant(id="g_rev", thread_id="t1", granted_by="alice", status=GrantStatus.REVOKED)
    issued_rev = store.issue(g_rev)
    assert issued_rev.status == GrantStatus.REVOKED

    g_exh = Grant(id="g_exh", thread_id="t1", granted_by="alice", status=GrantStatus.EXHAUSTED)
    issued_exh = store.issue(g_exh)
    assert issued_exh.status == GrantStatus.EXHAUSTED


def test_grant_naive_datetime_handled() -> None:
    store = InMemoryGrantsStore()
    naive_dt = datetime(2026, 10, 12, 12, 0, 0)
    g = Grant(id="g_naive", thread_id="t_naive", granted_by="alice", created_at=naive_dt)
    assert g.created_at.tzinfo == timezone.utc
    store.issue(g)
    assert store.find_covering_grant("t_naive", "tool", {}) is None


def test_grant_thread_isolation() -> None:
    store = InMemoryGrantsStore()
    g = Grant(
        id="g_thr",
        thread_id="thread_A",
        granted_by="alice",
        scope=(ScopeRule(tool="send_email"),),
    )
    store.issue(g)

    # Found for thread_A
    assert store.find_covering_grant("thread_A", "send_email", {}) is not None
    # Not found for thread_B
    assert store.find_covering_grant("thread_B", "send_email", {}) is None
    assert store.list_for_thread("thread_B") == []


def test_scope_rule_table_matches_legacy_statement_key() -> None:
    """Regression: DBAgent historically sent {'statement': ...}; grants must still match."""
    rule = ScopeRule(tool="exec_db_mutation", constraints={"table": "staging_imports"})
    assert rule.matches("exec_db_mutation", {"statement": "DROP TABLE staging_imports;"})
    assert not rule.matches("exec_db_mutation", {"statement": "DROP TABLE users;"})


def test_dbagent_proposes_canonical_mutation_tool() -> None:
    """Regression: DBAgent must propose registry-canonical exec_db_mutation/sql, not sql_query/statement."""
    import asyncio

    from warden.agent_engine import DBAgent

    result = asyncio.run(DBAgent().process_message("drop table users", "thr_reg", []))
    assert result.action is not None
    assert result.action.name == "exec_db_mutation"
    assert "sql" in result.action.payload


def test_dbagent_readonly_proposes_registered_handler_key() -> None:
    """Regression: DBAgent readonly must use the registered query_db_readonly/query shape."""
    import asyncio

    from warden.agent_engine import DBAgent

    result = asyncio.run(DBAgent().process_message("check index health", "thr_reg", []))
    assert result.action is not None
    assert result.action.name == "query_db_readonly"
    assert "query" in result.action.payload


def test_codeagent_proposes_canonical_shell_tool() -> None:
    """Regression: CodeAgent must propose registry-canonical exec_shell, not run_shell."""
    import asyncio

    from warden.agent_engine import CodeAgent

    result = asyncio.run(CodeAgent().process_message("delete /etc/shadow", "thr_reg", []))
    assert result.action is not None
    assert result.action.name == "exec_shell"


def test_derive_scope_handles_legacy_statement_key() -> None:
    """Regression: inbox-upgrade grant derivation must narrow statement payloads to table constraints."""
    from app.grants import derive_scope_from_payload

    rule = derive_scope_from_payload(
        "exec_db_mutation", {"statement": "DROP TABLE staging_imports;"}
    )
    assert rule.tool == "exec_db_mutation"
    assert rule.constraints.get("table") == "staging_imports"
