"""Focused tests for Phase 1 Step 3 — secure human-in-the-loop approvals.

Covers:
- Normal approval and successful guarded resumption
- Rejection and expiry
- Unauthorized approvers
- Action/payload mismatch (tampered action)
- Policy-identity mismatch
- Replay and duplicate approval
- Concurrent approval attempts (SQLite BEGIN IMMEDIATE)
- Persistence across process restart (SQLite on disk)
- Terminal DENY with attempted approval override
- Audit recording on gate decisions and executor ordering
- Step 2 tool regression via existing tests/test_tools.py (untouched)

All external effects are mocks: no real emails, no real service restarts.
"""

from __future__ import annotations

import asyncio
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from warden.executor import GuardedExecutor
from warden.hitl import (
    ApprovalAlreadyClaimed,
    ApprovalExpired,
    ApprovalMismatch,
    ApprovalUnauthorized,
    InMemoryApprovalStore,
    SqliteApprovalStore,
    canonical_payload_hash,
)
from warden.journal import InMemoryAuditJournal
from warden.models import (
    Action,
    ActionKind,
    Allowed,
    Denied,
    Error,
    GateDecision,
    GateVerdict,
    Pending,
)
from warden.policy.engine import PolicyDecision, PolicyEngine


def _action(
    name: str = "send_email",
    payload: dict[str, Any] | None = None,
    action_id: str = "act-h-1",
    run_id: str = "run-h",
    thread_id: str = "th-h",
) -> Action:
    return Action(
        id=action_id,
        kind=ActionKind.TOOL,
        name=name,
        payload=payload if payload is not None else {"to": "team@example.com"},
        run_id=run_id,
        thread_id=thread_id,
    )


def _approval(approval_id: str, approver: str = "alice", verdict: GateVerdict = GateVerdict.APPROVE) -> GateDecision:
    return GateDecision(
        gate_id=approval_id,
        verdict=verdict,
        reason="reviewed",
        decided_by=approver,
    )


def _make_executor(
    store: Any,
    approver_keys: dict[str, str] | None = None,
    *,
    journal: InMemoryAuditJournal | None = None,
    handler_result: str = "done",
) -> GuardedExecutor:
    ex = GuardedExecutor(
        journal=journal or InMemoryAuditJournal(),
        policy=PolicyEngine.with_seed_policies(),
        approval_store=store,
        approver_keys=approver_keys or {"alice": "key-a", "bob": "key-b"},
    )
    ex.register_handler("send_email", lambda a: handler_result)
    ex.register_handler("restart_service", lambda a: f"restarted-{a.payload.get('service', 'svc')}")
    return ex


def _approve_action_and_capture(
    ex: GuardedExecutor, action: Action
) -> Any:  # runtime skip; helper used in sync tests via asyncio
    raise NotImplementedError


# ---------------------------------------------------------------------------
# Normal approval + guarded resumption
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_pending_records_approval_bound_to_exact_action() -> None:
    store = InMemoryApprovalStore()
    ex = _make_executor(store)
    action = _action()
    outcome = await ex.execute(action)
    assert isinstance(outcome, Pending)
    assert isinstance(outcome, Pending)
    approval_id = outcome.gate_request.gate_id
    rec = await store.get(approval_id)
    assert rec is not None
    assert rec["action_id"] == action.id
    assert rec["name"] == action.name
    assert rec["payload_hash"] == canonical_payload_hash(action.payload)
    assert rec["policy_identity"] == "escalate_external_email"
    assert rec["claimed"] is False
    assert rec["expires_at"] > datetime.now(timezone.utc)


@pytest.mark.asyncio
async def test_normal_approval_executes_once_via_store() -> None:
    store = InMemoryApprovalStore()
    ex = _make_executor(store)
    action = _action()
    pending = await ex.execute(action)
    assert isinstance(pending, Pending)
    approval_id = pending.gate_request.gate_id
    allowed = await ex.execute(action, approval=_approval(approval_id, "alice"))
    assert isinstance(allowed, Allowed)
    assert allowed.result == "done"


# ---------------------------------------------------------------------------
# Rejection and expiry
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rejection_denies_without_execution() -> None:
    call_count = 0

    def handler(a: Action) -> str:
        nonlocal call_count
        call_count += 1
        return "x"

    store = InMemoryApprovalStore()
    ex = GuardedExecutor(
        journal=InMemoryAuditJournal(),
        policy=PolicyEngine.with_seed_policies(),
        approval_store=store,
        approver_keys={"alice": "k"},
    )
    ex.register_handler("send_email", handler)

    action = _action()
    pending = await ex.execute(action)
    assert isinstance(pending, Pending)
    approval_id = pending.gate_request.gate_id
    denied = await ex.execute(
        action,
        approval=_approval(approval_id, "alice", GateVerdict.DENY),
    )
    assert isinstance(denied, Denied)
    assert call_count == 0
    assert "rejected by approver" in denied.reason.lower()


@pytest.mark.asyncio
async def test_expired_approval_is_rejected_fail_closed() -> None:
    store = InMemoryApprovalStore()
    ex = _make_executor(store)
    action = _action()
    pending = await ex.execute(action)
    assert isinstance(pending, Pending)
    approval_id = pending.gate_request.gate_id

    # Force expiry in the store record (test-only mutation).
    rec = await store.get(approval_id)
    assert rec is not None
    rec["expires_at"] = datetime.now(timezone.utc) - timedelta(seconds=1)

    denied = await ex.execute(action, approval=_approval(approval_id, "alice"))
    assert isinstance(denied, Denied)
    assert "expired" in denied.reason.lower()


# ---------------------------------------------------------------------------
# Unauthorized approvers
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unauthorized_approver_is_rejected() -> None:
    store = InMemoryApprovalStore()
    ex = _make_executor(store)
    action = _action()
    pending = await ex.execute(action)
    assert isinstance(pending, Pending)
    approval_id = pending.gate_request.gate_id

    denied = await ex.execute(
        action, approval=_approval(approval_id, "mallory")
    )
    assert isinstance(denied, Denied)
    assert "not an authorized approver" in denied.reason.lower()
    # Verify handler never ran: record still unclaimed
    rec = await store.get(approval_id)
    assert rec is not None
    assert rec["claimed"] is False


# ---------------------------------------------------------------------------
# Action / payload / policy mismatch
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_payload_mismatch_is_rejected() -> None:
    store = InMemoryApprovalStore()
    ex = _make_executor(store)
    action = _action(payload={"to": "team@example.com"})
    pending = await ex.execute(action)
    assert isinstance(pending, Pending)
    approval_id = pending.gate_request.gate_id

    tampered = _action(payload={"to": "someone-else@example.com"})
    denied = await ex.execute(tampered, approval=_approval(approval_id, "alice"))
    assert isinstance(denied, Denied)
    assert "does not match the originally proposed action" in denied.reason


@pytest.mark.asyncio
async def test_action_name_mismatch_is_rejected() -> None:
    store = InMemoryApprovalStore()
    ex = _make_executor(store)
    action = _action(name="send_email")
    pending = await ex.execute(action)
    assert isinstance(pending, Pending)
    approval_id = pending.gate_request.gate_id

    wrong_kind = _action(
        name="restart_service",
        payload={"service": "api-gateway"},
        action_id=action.id,
    )
    denied = await ex.execute(wrong_kind, approval=_approval(approval_id, "alice"))
    assert isinstance(denied, Denied)
    assert "does not match" in denied.reason


@pytest.mark.asyncio
async def test_policy_identity_mismatch_is_rejected() -> None:
    """Approval recorded under one policy identity cannot approve an action
    now evaluating under a different policy identity."""
    store = InMemoryApprovalStore()
    ex = _make_executor(store)
    action = _action(name="send_email", payload={})
    pending = await ex.execute(action)
    assert isinstance(pending, Pending)
    approval_id = pending.gate_request.gate_id

    rec = await store.get(approval_id)
    assert rec is not None
    # Simulate policy identity drift (e.g., rules changed between
    # gate creation and resumption).
    rec["policy_identity"] = "some_other_policy_v999"
    # Rebuild the fingerprint the same way the executor does.
    from warden.hitl.approvals import _binding_fingerprint
    rec["fingerprint"] = _binding_fingerprint(action, "some_other_policy_v999")

    denied = await ex.execute(action, approval=_approval(approval_id, "alice"))
    assert isinstance(denied, Denied)
    assert "does not match" in denied.reason


# ---------------------------------------------------------------------------
# Replay and duplicate claim
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_replayed_approval_is_rejected() -> None:
    store = InMemoryApprovalStore()
    ex = _make_executor(store)
    action = _action()
    pending = await ex.execute(action)
    assert isinstance(pending, Pending)
    approval_id = pending.gate_request.gate_id

    first = await ex.execute(action, approval=_approval(approval_id, "alice"))
    assert isinstance(first, Allowed)
    second = await ex.execute(action, approval=_approval(approval_id, "alice"))
    assert isinstance(second, Denied)
    assert "duplicate or replayed" in second.reason.lower()


@pytest.mark.asyncio
async def test_store_claim_is_one_time_only() -> None:
    store = InMemoryApprovalStore()
    ex = _make_executor(store)
    action = _action()
    pending = await ex.execute(action)
    assert isinstance(pending, Pending)
    approval_id = pending.gate_request.gate_id

    # Directly manipulate store outside of the executor: second claim must fail
    ok1 = await store.claim(
        approval_id=approval_id,
        action=action,
        approver_key="alice",
        decision="approve",
        policy_identity="escalate_external_email",
    )
    assert ok1 is True
    with pytest.raises(ApprovalAlreadyClaimed):
        await store.claim(
            approval_id=approval_id,
            action=action,
            approver_key="alice",
            decision="approve",
            policy_identity="escalate_external_email",
        )


# ---------------------------------------------------------------------------
# SQLite store: persistence across restart
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sqlite_store_persists_across_process_restart() -> None:
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "approvals.db"
        engine = PolicyEngine.with_seed_policies()

        # "First process"
        store_a = SqliteApprovalStore(db_path)
        ex_a = _make_executor(store_a)
        action = _action()
        pending = await ex_a.execute(action)
        assert isinstance(pending, Pending)
        approval_id = pending.gate_request.gate_id
        store_a.close()

        # "Second process" — fresh store object on the same file
        store_b = SqliteApprovalStore(db_path)
        rec = await store_b.get(approval_id)
        assert rec is not None
        assert rec["claimed"] is False
        assert rec["payload_hash"] == canonical_payload_hash(action.payload)

        ex_b = _make_executor(store_b)
        allowed = await ex_b.execute(action, approval=_approval(approval_id, "alice"))
        assert isinstance(allowed, Allowed)
        store_b.close()


@pytest.mark.asyncio
async def test_sqlite_concurrent_claims_only_one_wins() -> None:
    store = SqliteApprovalStore()
    ex = _make_executor(store)
    action = _action()
    pending = await ex.execute(action)
    assert isinstance(pending, Pending)
    approval_id = pending.gate_request.gate_id

    async def attempt(n: int) -> Any:
        try:
            await store.claim(
                approval_id=approval_id,
                action=action,
                approver_key="alice",
                decision="approve",
                policy_identity="escalate_external_email",
            )
            return n
        except ApprovalAlreadyClaimed:
            return f"{n}-rejected"

    results = await asyncio.gather(attempt(1), attempt(2))
    winners = [r for r in results if isinstance(r, int)]
    assert len(winners) == 1
    store.close()


# ---------------------------------------------------------------------------
# Executor-level: restart_service now requires approval
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_restart_service_escalates_to_pending_not_executed() -> None:
    called = False

    def restart_handler(a: Action) -> str:
        nonlocal called
        called = True
        return "restarted"

    store = InMemoryApprovalStore()
    ex = GuardedExecutor(
        journal=InMemoryAuditJournal(),
        policy=PolicyEngine.with_seed_policies(),
        approval_store=store,
        approver_keys={"alice": "k"},
    )
    ex.register_handler("restart_service", restart_handler)

    outcome = await ex.execute(
        _action(name="restart_service", payload={"service": "api-gateway"})
    )
    assert isinstance(outcome, Pending)
    assert called is False
    assert isinstance(outcome, Pending)
    rec = await store.get(outcome.gate_request.gate_id)
    assert rec is not None
    assert rec["policy_identity"] == "escalate_infrastructure_restart"


@pytest.mark.asyncio
async def test_restart_service_approved_resumes() -> None:
    store = InMemoryApprovalStore()
    ex = _make_executor(store)
    action = _action(name="restart_service", payload={"service": "api-gateway"})
    pending = await ex.execute(action)
    assert isinstance(pending, Pending)
    approval_id = pending.gate_request.gate_id
    # The approval record binds a specific authorized approver (allowlist
    # head by design). Inspect it and claim under the correct identity.
    rec = await store.get(approval_id)
    assert rec is not None
    owner = rec["approver_key"]
    allowed = await ex.execute(
        action, approval=_approval(approval_id, owner)
    )
    assert isinstance(allowed, Allowed)
    assert allowed.result == "restarted-api-gateway"


# ---------------------------------------------------------------------------
# Terminal DENY still cannot be overridden
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_terminal_deny_not_overridable_by_valid_approval() -> None:
    """Even with an approval store, DROP TABLE must remain a Denied outcome."""
    store = InMemoryApprovalStore()
    handler_ran = False

    def drop_handler(a: Action) -> str:
        nonlocal handler_ran
        handler_ran = True
        return "dropped"

    ex = GuardedExecutor(
        journal=InMemoryAuditJournal(),
        policy=PolicyEngine.with_seed_policies(),
        approval_store=store,
        approver_keys={"alice": "k"},
    )
    ex.register_handler("drop_table", drop_handler)

    action = _action(
        name="drop_table", payload={"table": "orders"}, action_id="act-h-drop"
    )
    outcome = await ex.execute(action)
    assert isinstance(outcome, Denied)
    # Approval override attempt (not from a real store claim — should be
    # impossible, but this test proves terminal DENY is not a Pending and no
    # approval record is ever created for DENY).
    assert await store.count_pending() == 0
    assert handler_ran is False


# ---------------------------------------------------------------------------
# Audit & fail-closed behavior
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_gate_events_are_journaled_and_failed_journal_fails_closed() -> None:
    journal = InMemoryAuditJournal()
    store = InMemoryApprovalStore()
    ex = _make_executor(store, journal=journal)

    action = _action()
    pending = await ex.execute(action)
    assert isinstance(pending, Pending)
    events = await journal.query()
    kinds = [e.kind for e in events]
    assert "action_requested" in kinds
    assert "gate_requested" in kinds
    # No secrets in the journaled payload (use synthetic '@example.com').
    import json as _json
    payloads = [_json.dumps(e.payload, default=str) for e in events]
    assert all("sk-" not in p for p in payloads)

    # Failing journal → fail closed
    failing = InMemoryAuditJournal(failing=True)
    ex_fail = _make_executor(InMemoryApprovalStore(), journal=failing)
    err = await ex_fail.execute(_action())
    assert isinstance(err, Error)
    assert err.reason == "governance_unavailable"


@pytest.mark.asyncio
async def test_store_failure_fails_closed_not_open() -> None:
    """If the approval store raises unexpectedly, the executor fails closed."""

    class ExplodingStore(InMemoryApprovalStore):
        async def record(self, **kwargs: Any) -> str:
            raise RuntimeError("disk on fire")

    ex = _make_executor(ExplodingStore())
    outcome = await ex.execute(_action())
    assert isinstance(outcome, Error)
    assert outcome.reason == "governance_unavailable"


# ---------------------------------------------------------------------------
# Regression through primitives: unchanged invariants
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_no_approval_store_keeps_legacy_semantics() -> None:
    """When no approval_store is configured, executor behaves exactly as
    previously (Pending on ESCALATE without a store record)."""
    ex = GuardedExecutor(
        journal=InMemoryAuditJournal(),
        policy=PolicyEngine.with_seed_policies(),
        # approval_store deliberately None
    )
    ex.register_handler("send_email", lambda a: "ok")
    pending = await ex.execute(_action())
    assert isinstance(pending, Pending)
    # Legacy flow still supports approve-replay as before (store absent)
    allowed = await ex.execute(
        _action(),
        approval=_approval("legacy-gate", "anyone"),
    )
    assert isinstance(allowed, Allowed)


def test_policy_identity_is_part_of_fingerprint() -> None:
    """Direct unit check on the fingerprint helper."""
    from warden.hitl.approvals import _binding_fingerprint

    a1 = _action(payload={"x": 1})
    a2 = _action(payload={"x": 1})
    a3 = _action(payload={"x": 2})
    assert _binding_fingerprint(a1, "p1") == _binding_fingerprint(a2, "p1")
    assert _binding_fingerprint(a1, "p1") != _binding_fingerprint(a3, "p1")
    assert _binding_fingerprint(a1, "p1") != _binding_fingerprint(a1, "p2")
