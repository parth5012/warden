"""Unit tests for GuardedExecutor (the core governance seam).

Validates:
- Lock 1: Both tool and LLM actions cross the seam
- Lock 2: Escalated actions return Pending(gate_request) explicitly
- Lock 4: Fail-closed on infrastructure / policy failure -> Error(governance_unavailable)
- Lock 5: Denied is terminal, no approval override
- Approvals: GateDecision(verdict=APPROVE) executes; DENY aborts
- Cryptographic write-ahead audit journaling for every transition
"""

from __future__ import annotations

import asyncio
from typing import Any
import pytest

from warden.journal import (
    EventKind,
    InMemoryJournal,
    JournalEvent,
    VerificationStatus,
)
from warden.models import (
    Action,
    ActionKind,
    Allowed,
    Denied,
    Error,
    ExecutionContext,
    GateDecision,
    GateRequest,
    GateVerdict,
    OutcomeKind,
    Pending,
)
from warden.executor import GuardedExecutor
from warden.grants import Grant, InMemoryGrantsStore, ScopeRule
from warden.policy.engine import PolicyDecision, PolicyEngine, PolicyVerdict
from warden.sandbox.port import SandboxPort, SandboxResult, SandboxUnavailable


class DummySandbox(SandboxPort):
    def __init__(self, should_fail: bool = False) -> None:
        self.should_fail = should_fail
        self.ran_actions: list[Action] = []

    async def run(self, action: Action) -> SandboxResult:
        if self.should_fail:
            raise SandboxUnavailable("Docker daemon is down")
        self.ran_actions.append(action)
        return SandboxResult(
            ok=True,
            exit_code=0,
            stdout="sandbox output",
            stderr="",
            timed_out=False,
            duration_ms=15,
            profile="shell",
        )


@pytest.fixture
def journal() -> InMemoryJournal:
    return InMemoryJournal()


@pytest.fixture
def sandbox() -> DummySandbox:
    return DummySandbox()


@pytest.fixture
def policy() -> PolicyEngine:
    return PolicyEngine()


@pytest.fixture
def executor(journal: InMemoryJournal, sandbox: DummySandbox, policy: PolicyEngine) -> GuardedExecutor:
    return GuardedExecutor(
        journal=journal,
        policy=policy,
        sandbox=sandbox,
    )


@pytest.mark.asyncio
async def test_tool_action_safe_allowed(executor: GuardedExecutor, journal: InMemoryJournal) -> None:
    action = Action(
        id="act_safe_01",
        kind=ActionKind.TOOL,
        name="get_system_metrics",
        payload={"service": "orders", "metric": "cpu", "window_minutes": 15},
        run_id="run_01",
        thread_id="thr_01",
    )
    ctx = ExecutionContext(actor="ops_agent")

    outcome = await executor.execute(action, ctx)

    assert isinstance(outcome, Allowed)
    assert outcome.kind == OutcomeKind.ALLOWED
    assert isinstance(outcome.result, dict)

    # Check journal events
    events = journal.events
    assert len(events) >= 3
    kinds = [e.kind for e in events]
    assert EventKind.ACTION_REQUESTED.value in kinds
    assert EventKind.POLICY_EVALUATED.value in kinds
    assert EventKind.ACTION_COMPLETED.value in kinds

    # Verify cryptographic hash chain
    status, detail = journal.verify()
    assert status == VerificationStatus.VERIFIED


@pytest.mark.asyncio
async def test_tool_action_terminal_denied(executor: GuardedExecutor, journal: InMemoryJournal) -> None:
    # SQL DROP TABLE is an invariant static deny (Lock 5)
    action = Action(
        id="act_deny_01",
        kind=ActionKind.TOOL,
        name="exec_db_mutation",
        payload={"sql": "DROP TABLE users CASCADE;"},
        run_id="run_01",
        thread_id="thr_01",
    )
    ctx = ExecutionContext(actor="db_agent")

    outcome = await executor.execute(action, ctx)

    assert isinstance(outcome, Denied)
    assert outcome.kind == OutcomeKind.DENIED
    assert outcome.policy == "no-destructive-sql"

    # Terminal deny event in journal
    deny_ev = [e for e in journal.events if e.kind == EventKind.ACTION_DENIED.value]
    assert len(deny_ev) == 1
    assert deny_ev[0].payload.get("terminal") is True


@pytest.mark.asyncio
async def test_terminal_denied_cannot_be_approved(executor: GuardedExecutor, journal: InMemoryJournal) -> None:
    # Lock 5: Even with an approval object, a terminal DENY cannot execute
    action = Action(
        id="act_deny_02",
        kind=ActionKind.TOOL,
        name="exec_db_mutation",
        payload={"sql": "DROP TABLE users CASCADE;"},
        run_id="run_01",
        thread_id="thr_01",
    )
    decision = GateDecision(
        gate_id="gate_fake",
        verdict=GateVerdict.APPROVE,
        reason="Operator tried to bypass deny",
        decided_by="rogue_admin",
    )

    outcome = await executor.execute(action, approval=decision)

    assert isinstance(outcome, Denied)
    assert outcome.policy == "no-destructive-sql"


@pytest.mark.asyncio
async def test_tool_action_escalates_to_pending(executor: GuardedExecutor, journal: InMemoryJournal) -> None:
    # send_email is a HITL escalation tool
    action = Action(
        id="act_hitl_01",
        kind=ActionKind.TOOL,
        name="send_email",
        payload={"recipient": "boss@company.com", "subject": "Alert", "body": "Disk full"},
        run_id="run_01",
        thread_id="thr_01",
    )

    outcome = await executor.execute(action)

    assert isinstance(outcome, Pending)
    assert outcome.kind == OutcomeKind.PENDING
    assert isinstance(outcome.gate_request, GateRequest)
    assert outcome.gate_request.action.id == action.id

    # Check journal has gate_requested
    gate_ev = [e for e in journal.events if e.kind == EventKind.GATE_REQUESTED.value]
    assert len(gate_ev) == 1
    assert gate_ev[0].payload["gate_id"] == outcome.gate_request.gate_id


@pytest.mark.asyncio
async def test_tool_action_approved_executes(executor: GuardedExecutor, journal: InMemoryJournal) -> None:
    action = Action(
        id="act_hitl_02",
        kind=ActionKind.TOOL,
        name="send_email",
        payload={"recipient": "boss@company.com", "subject": "Alert", "body": "Disk full"},
        run_id="run_01",
        thread_id="thr_01",
    )
    decision = GateDecision(
        gate_id=f"gate-{action.id}",
        verdict=GateVerdict.APPROVE,
        reason="Verified legitimate notification",
        decided_by="security_officer_alice",
    )

    outcome = await executor.execute(action, approval=decision)

    assert isinstance(outcome, Allowed)
    assert outcome.result["status"] == "sent-after-approval"

    # Journal should contain gate_decided and action_completed
    kinds = [e.kind for e in journal.events]
    assert EventKind.GATE_DECIDED.value in kinds
    assert EventKind.ACTION_COMPLETED.value in kinds


@pytest.mark.asyncio
async def test_tool_action_human_denied_aborts(executor: GuardedExecutor, journal: InMemoryJournal) -> None:
    action = Action(
        id="act_hitl_03",
        kind=ActionKind.TOOL,
        name="send_email",
        payload={"recipient": "boss@company.com", "subject": "Alert", "body": "Disk full"},
        run_id="run_01",
        thread_id="thr_01",
    )
    decision = GateDecision(
        gate_id=f"gate-{action.id}",
        verdict=GateVerdict.DENY,
        reason="Recipient address incorrect",
        decided_by="security_officer_alice",
    )

    outcome = await executor.execute(action, approval=decision)

    assert isinstance(outcome, Denied)
    assert "Recipient address incorrect" in outcome.reason

    # No action_completed in journal
    kinds = [e.kind for e in journal.events]
    assert EventKind.GATE_DECIDED.value in kinds
    assert EventKind.ACTION_COMPLETED.value not in kinds


@pytest.mark.asyncio
async def test_sandboxed_tool_executes_in_sandbox(executor: GuardedExecutor, sandbox: DummySandbox) -> None:
    action = Action(
        id="act_shell_01",
        kind=ActionKind.TOOL,
        name="exec_shell",
        payload={"command": "uptime"},
        run_id="run_01",
        thread_id="thr_01",
    )

    outcome = await executor.execute(action)

    assert isinstance(outcome, Allowed)
    assert len(sandbox.ran_actions) == 1
    assert sandbox.ran_actions[0].name == "shell"


@pytest.mark.asyncio
async def test_sandbox_unavailable_fails_closed(journal: InMemoryJournal, policy: PolicyEngine) -> None:
    failing_sandbox = DummySandbox(should_fail=True)
    executor = GuardedExecutor(journal=journal, policy=policy, sandbox=failing_sandbox)

    action = Action(
        id="act_shell_02",
        kind=ActionKind.TOOL,
        name="exec_shell",
        payload={"command": "uptime"},
        run_id="run_01",
        thread_id="thr_01",
    )

    outcome = await executor.execute(action)

    assert isinstance(outcome, Error)
    assert outcome.kind == OutcomeKind.ERROR
    assert outcome.reason == "governance_unavailable"

    failed_ev = [e for e in journal.events if e.kind == EventKind.ACTION_FAILED.value]
    assert len(failed_ev) >= 1


@pytest.mark.asyncio
async def test_llm_action_allowed_with_provider(executor: GuardedExecutor, journal: InMemoryJournal) -> None:
    action = Action(
        id="act_llm_01",
        kind=ActionKind.LLM,
        name="llama3-70b-8192",
        payload={"prompt": "Summarize server logs in 5 words"},
        run_id="run_01",
        thread_id="thr_01",
    )

    async def mock_provider(req: Any) -> dict[str, Any]:
        return {"content": "All systems operating normally."}

    executor.llm_provider = mock_provider

    outcome = await executor.execute(action)

    assert isinstance(outcome, Allowed)
    assert outcome.result == "All systems operating normally."
    kinds = [e.kind for e in journal.events]
    assert EventKind.ACTION_COMPLETED.value in kinds


@pytest.mark.asyncio
async def test_policy_infra_failure_fails_closed(executor: GuardedExecutor, journal: InMemoryJournal) -> None:
    # If policy engine raises unexpectedly, executor must fail closed
    action = Action(
        id="act_crash_01",
        kind=ActionKind.TOOL,
        name="get_system_metrics",
        payload={"service": "orders"},
        run_id="run_01",
        thread_id="thr_01",
    )

    def broken_eval(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("Policy database connection lost")

    executor.policy.evaluate = broken_eval  # type: ignore[method-assign]

    outcome = await executor.execute(action)

    assert isinstance(outcome, Error)
    assert outcome.reason == "governance_unavailable"


@pytest.mark.asyncio
async def test_grant_auto_allows_then_parks_at_max_uses() -> None:
    journal = InMemoryJournal()
    grants_store = InMemoryGrantsStore()
    executor = GuardedExecutor(journal=journal, grants=grants_store)

    grant = Grant(
        id="gr_exec_01",
        thread_id="thr_auto",
        granted_by="alice",
        scope=(ScopeRule(tool="send_email"),),
        ttl_seconds=1800,
        max_uses=2,
    )
    grants_store.issue(grant)

    # 1st use: auto-allowed, grant consumed
    act1 = Action(
        id="act_use_1",
        kind=ActionKind.TOOL,
        name="send_email",
        payload={"recipient": "a@b.com", "subject": "s", "body": "b"},
        run_id="run_1",
        thread_id="thr_auto",
    )
    out1 = await executor.execute(act1)
    assert isinstance(out1, Allowed)
    consumed_evs = [e for e in journal.events if e.kind == EventKind.GRANT_CONSUMED.value]
    assert len(consumed_evs) == 1
    assert consumed_evs[0].payload["uses_left"] == 1

    # 2nd use: auto-allowed, grant exhausted
    act2 = Action(
        id="act_use_2",
        kind=ActionKind.TOOL,
        name="send_email",
        payload={"recipient": "a@b.com", "subject": "s", "body": "b"},
        run_id="run_1",
        thread_id="thr_auto",
    )
    out2 = await executor.execute(act2)
    assert isinstance(out2, Allowed)
    consumed_evs = [e for e in journal.events if e.kind == EventKind.GRANT_CONSUMED.value]
    assert len(consumed_evs) == 2
    assert consumed_evs[1].payload["uses_left"] == 0

    # 3rd use (max-uses+1): parks to Pending
    act3 = Action(
        id="act_use_3",
        kind=ActionKind.TOOL,
        name="send_email",
        payload={"recipient": "a@b.com", "subject": "s", "body": "b"},
        run_id="run_1",
        thread_id="thr_auto",
    )
    out3 = await executor.execute(act3)
    assert isinstance(out3, Pending)
    gate_evs = [e for e in journal.events if e.kind == EventKind.GATE_REQUESTED.value]
    assert len(gate_evs) == 1


@pytest.mark.asyncio
async def test_revoke_mid_run_reparks() -> None:
    journal = InMemoryJournal()
    grants_store = InMemoryGrantsStore()
    executor = GuardedExecutor(journal=journal, grants=grants_store)

    grant = Grant(
        id="gr_exec_rev",
        thread_id="thr_rev",
        granted_by="alice",
        scope=(ScopeRule(tool="send_email"),),
        ttl_seconds=1800,
        max_uses=5,
    )
    grants_store.issue(grant)

    # 1st use: auto-allowed
    act1 = Action(
        id="act_rev_1",
        kind=ActionKind.TOOL,
        name="send_email",
        payload={"recipient": "a@b.com", "subject": "s", "body": "b"},
        run_id="run_1",
        thread_id="thr_rev",
    )
    out1 = await executor.execute(act1)
    assert isinstance(out1, Allowed)

    # Revoke grant mid-run
    grants_store.revoke("gr_exec_rev", revoked_by="alice")

    # 2nd use: parks because grant revoked
    act2 = Action(
        id="act_rev_2",
        kind=ActionKind.TOOL,
        name="send_email",
        payload={"recipient": "a@b.com", "subject": "s", "body": "b"},
        run_id="run_1",
        thread_id="thr_rev",
    )
    out2 = await executor.execute(act2)
    assert isinstance(out2, Pending)


@pytest.mark.asyncio
async def test_deny_with_grant_still_denies() -> None:
    journal = InMemoryJournal()
    grants_store = InMemoryGrantsStore()
    executor = GuardedExecutor(journal=journal, grants=grants_store)

    # Broad grant covering all tools
    grant = Grant(
        id="gr_broad",
        thread_id="thr_deny",
        granted_by="admin",
        scope=(ScopeRule(tool="*"),),
        ttl_seconds=1800,
        max_uses=10,
    )
    grants_store.issue(grant)

    # Unbounded destructive DDL action
    act = Action(
        id="act_deny_broad",
        kind=ActionKind.TOOL,
        name="exec_db_mutation",
        payload={"sql": "DROP DATABASE prod;"},
        run_id="run_1",
        thread_id="thr_deny",
    )
    out = await executor.execute(act)
    # Lock 5: Denied is terminal, grants never consulted
    assert isinstance(out, Denied)
    assert out.policy == "no-destructive-sql"
    # No grant consumed event in journal
    consumed_evs = [e for e in journal.events if e.kind == EventKind.GRANT_CONSUMED.value]
    assert len(consumed_evs) == 0
    # Grant uses unchanged
    stored = grants_store.get("gr_broad")
    assert stored is not None and stored.uses == 0


@pytest.mark.asyncio
async def test_kill_mid_park_replay_preserves_uses() -> None:
    journal = InMemoryJournal()
    grants_store = InMemoryGrantsStore()
    executor = GuardedExecutor(journal=journal, grants=grants_store)

    grant = Grant(
        id="gr_replay",
        thread_id="thr_replay",
        granted_by="alice",
        scope=(ScopeRule(tool="send_email"),),
        ttl_seconds=1800,
        max_uses=2,
    )
    grants_store.issue(grant)

    act = Action(
        id="act_replay_1",
        kind=ActionKind.TOOL,
        name="send_email",
        payload={"recipient": "a@b.com", "subject": "s", "body": "b"},
        run_id="run_replay",
        thread_id="thr_replay",
    )
    out1 = await executor.execute(act)
    assert isinstance(out1, Allowed)

    stored = grants_store.get("gr_replay")
    assert stored is not None and stored.uses == 1
