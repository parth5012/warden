"""End-to-End verification of User Grants lifecycle and GuardedExecutor interception.

Validates the complete Grants user story:
1. Upfront grant: risky task (scoped file delete + named table drop) completes with zero parks.
2. Revocation: revoking grant causes next attempt to park at HITL gate.
3. Inbox upgrade: upgrading parked gate issues grant and resolves gate, covering remaining steps.
4. Terminal deny invariant: unbounded destructive operations strictly deny despite grants.
"""

from __future__ import annotations

from typing import Iterator
import pytest

from warden.executor import GuardedExecutor
from warden.grants import (
    Grant,
    GrantStatus,
    InMemoryGrantsStore,
    ScopeRule,
    set_grants_store,
)
from warden.journal import EventKind, InMemoryJournal
from warden.models import (
    Action,
    ActionKind,
    Allowed,
    Denied,
    ExecutionContext,
    OutcomeKind,
    Pending,
)


@pytest.fixture
def e2e_env() -> Iterator[tuple[GuardedExecutor, InMemoryJournal, InMemoryGrantsStore]]:
    journal = InMemoryJournal()
    store = InMemoryGrantsStore()
    set_grants_store(store)
    executor = GuardedExecutor(journal=journal, grants=store)
    yield executor, journal, store
    set_grants_store(None)


@pytest.mark.asyncio
async def test_e2e_upfront_grant_then_revoke_reparks(
    e2e_env: tuple[GuardedExecutor, InMemoryJournal, InMemoryGrantsStore],
) -> None:
    executor, journal, store = e2e_env
    thread_id = "thr_e2e_upfront"
    ctx = ExecutionContext(actor="ops_assistant", thread_id=thread_id)

    # 1. Issue upfront grant covering both scoped file delete and table drop
    grant = Grant(
        id="gr_e2e_upfront",
        thread_id=thread_id,
        granted_by="alice",
        scope=(
            ScopeRule(tool="batch_delete_files", constraints={"path_prefix": "/workspace/tmp/"}),
            ScopeRule(tool="exec_db_mutation", constraints={"table": "staging_imports"}),
        ),
        ttl_seconds=1800,
        max_uses=5,
        reason="Automated cleanup of staging imports",
    )
    store.issue(grant)

    # Step 1: Risky scoped file deletion under /workspace/tmp/
    act_fs = Action(
        id="act_fs_01",
        kind=ActionKind.TOOL,
        name="batch_delete_files",
        payload={
            "operation": "FILE_BATCH_DELETE",
            "target_resource": "/workspace/tmp/",
            "targets": ["/workspace/tmp/chunk_1.bin", "/workspace/tmp/chunk_2.bin"],
        },
        run_id="run_e2e_1",
        thread_id=thread_id,
    )
    out_fs = await executor.execute(act_fs, ctx)
    # Zero parks: auto-allowed by upfront grant
    assert isinstance(out_fs, Allowed)
    assert out_fs.kind == OutcomeKind.ALLOWED

    # Step 2: Named-table drop
    act_sql = Action(
        id="act_sql_01",
        kind=ActionKind.TOOL,
        name="exec_db_mutation",
        payload={"sql": "DROP TABLE staging_imports;"},
        run_id="run_e2e_1",
        thread_id=thread_id,
    )
    out_sql = await executor.execute(act_sql, ctx)
    # Zero parks: auto-allowed by upfront grant
    assert isinstance(out_sql, Allowed)
    assert out_sql.kind == OutcomeKind.ALLOWED

    # Verify journal events: 2x grant_consumed, 0x gate_requested
    consumed_evs = [e for e in journal.events if e.kind == EventKind.GRANT_CONSUMED.value]
    assert len(consumed_evs) == 2
    assert consumed_evs[0].payload["uses_left"] == 4
    assert consumed_evs[1].payload["uses_left"] == 3
    gate_evs = [e for e in journal.events if e.kind == EventKind.GATE_REQUESTED.value]
    assert len(gate_evs) == 0

    # 2. Revoke grant mid-task
    revoked = store.revoke(grant.id, revoked_by="alice")
    assert revoked is not None and revoked.status == GrantStatus.REVOKED

    # Step 3: Next attempt now parks to Pending (gate requested)
    act_sql_next = Action(
        id="act_sql_02",
        kind=ActionKind.TOOL,
        name="exec_db_mutation",
        payload={"sql": "DROP TABLE staging_imports;"},
        run_id="run_e2e_1",
        thread_id=thread_id,
    )
    out_next = await executor.execute(act_sql_next, ctx)
    assert isinstance(out_next, Pending)
    assert out_next.kind == OutcomeKind.PENDING
    assert out_next.gate_request.context["rule_id"] == "scoped-ddl-drop-table"

    gate_evs_after = [e for e in journal.events if e.kind == EventKind.GATE_REQUESTED.value]
    assert len(gate_evs_after) == 1


@pytest.mark.asyncio
async def test_e2e_inbox_upgrade_resolves_gate_and_covers_rest(
    e2e_env: tuple[GuardedExecutor, InMemoryJournal, InMemoryGrantsStore],
) -> None:
    executor, journal, store = e2e_env
    thread_id = "thr_e2e_inbox"
    ctx = ExecutionContext(actor="ops_assistant", thread_id=thread_id)

    # 1. Un-granted risky action parks at gate
    act_parked = Action(
        id="act_park_01",
        kind=ActionKind.TOOL,
        name="batch_delete_files",
        payload={
            "operation": "FILE_BATCH_DELETE",
            "target_resource": "/workspace/tmp/",
            "targets": ["/workspace/tmp/old_1.tmp"],
        },
        run_id="run_e2e_2",
        thread_id=thread_id,
    )
    out_initial = await executor.execute(act_parked, ctx)
    assert isinstance(out_initial, Pending)
    gate_req = out_initial.gate_request

    # 2. Approver performs "Grant Rest of Task" inbox upgrade
    # Derives scope rule from parked action: batch_delete_files targeting /workspace/tmp/
    upgraded_grant = Grant(
        id="gr_inbox_upgraded",
        thread_id=thread_id,
        granted_by="security_admin",
        scope=(
            ScopeRule(
                tool=act_parked.name,
                constraints={"path_prefix": "/workspace/tmp/"},
            ),
        ),
        ttl_seconds=1800,
        max_uses=5,
        reason=f"Inbox upgrade for gate #{gate_req.gate_id}",
    )
    store.issue(upgraded_grant)

    # Resolves parked action under the new grant
    out_resolved = await executor.execute(act_parked, ctx)
    assert isinstance(out_resolved, Allowed)

    # Exactly 1 use consumed
    consumed_evs = [e for e in journal.events if e.kind == EventKind.GRANT_CONSUMED.value]
    assert len(consumed_evs) == 1
    assert consumed_evs[0].payload["uses_left"] == 4

    # 3. Subsequent actions in the same task run auto-allow under the grant
    act_subsequent = Action(
        id="act_park_02",
        kind=ActionKind.TOOL,
        name="batch_delete_files",
        payload={
            "operation": "FILE_BATCH_DELETE",
            "target_resource": "/workspace/tmp/",
            "targets": ["/workspace/tmp/old_2.tmp"],
        },
        run_id="run_e2e_2",
        thread_id=thread_id,
    )
    out_subsequent = await executor.execute(act_subsequent, ctx)
    assert isinstance(out_subsequent, Allowed)

    consumed_evs_2 = [e for e in journal.events if e.kind == EventKind.GRANT_CONSUMED.value]
    assert len(consumed_evs_2) == 2
    assert consumed_evs_2[1].payload["uses_left"] == 3


@pytest.mark.asyncio
async def test_e2e_unbounded_destructive_strictly_denies_despite_grant(
    e2e_env: tuple[GuardedExecutor, InMemoryJournal, InMemoryGrantsStore],
) -> None:
    executor, journal, store = e2e_env
    thread_id = "thr_e2e_deny"
    ctx = ExecutionContext(actor="ops_assistant", thread_id=thread_id)

    # Broad wildcard grant
    store.issue(
        Grant(
            id="gr_wildcard",
            thread_id=thread_id,
            granted_by="admin",
            scope=(ScopeRule(tool="*"),),
            ttl_seconds=3600,
            max_uses=20,
        )
    )

    # 1. Unbounded DROP DATABASE
    act_db = Action(
        id="act_drop_db",
        kind=ActionKind.TOOL,
        name="exec_db_mutation",
        payload={"sql": "DROP DATABASE production;"},
        run_id="run_e2e_3",
        thread_id=thread_id,
    )
    out_db = await executor.execute(act_db, ctx)
    assert isinstance(out_db, Denied)
    assert out_db.policy in ("no-destructive-sql", "no_destructive_sql")

    # 2. Unbounded root rm -rf /
    act_rm = Action(
        id="act_rm_root",
        kind=ActionKind.TOOL,
        name="exec_shell",
        payload={"command": "rm -rf /"},
        run_id="run_e2e_3",
        thread_id=thread_id,
    )
    out_rm = await executor.execute(act_rm, ctx)
    assert isinstance(out_rm, Denied)
    assert out_rm.policy in ("no-destructive-shell", "no_destructive_shell")

    # 3. Path traversal attack
    act_trav = Action(
        id="act_trav",
        kind=ActionKind.TOOL,
        name="read_file_sensitive",
        payload={"path": "/workspace/tmp/../../../etc/shadow"},
        run_id="run_e2e_3",
        thread_id=thread_id,
    )
    out_trav = await executor.execute(act_trav, ctx)
    assert isinstance(out_trav, Denied)

    # Zero grant consumption on denied actions
    consumed_evs = [e for e in journal.events if e.kind == EventKind.GRANT_CONSUMED.value]
    assert len(consumed_evs) == 0
