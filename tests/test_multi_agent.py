"""Multi-agent + seam tests against real PostgreSQL.

Covers:
- Seam verdicts: allow, deny (terminal), escalate -> Pending, approved dispatch
- Journal trail shape per verdict (write-ahead intent + outcome event)
- Supervisor routing (ops / research -> finish)
- Multi-agent park/resume through the seam gate (approve + deny)
- Deterministic gate_id across park -> resume -> crash-restart
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from langchain_core.runnables import RunnableConfig
from langgraph.types import Command

from warden.models import (
    Action,
    ActionKind,
    Allowed,
    Denied,
    Error,
    GateDecision,
    GateRequest,
    GateVerdict,
    Pending,
)
from warden.checkpoint import CheckpointManager
from warden.multi_agent import build_multi_agent_graph
from warden.seam import GuardedExecutor, SequencingPolicy


def _config(thread_id: str) -> RunnableConfig:
    return {"configurable": {"thread_id": thread_id}}


def _fresh_thread() -> str:
    return f"multi-{uuid.uuid4().hex[:12]}"


class _MemoryJournal:
    """In-memory journal sink recording (event, payload) pairs in order."""

    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    async def append(self, event: str, payload: dict[str, Any], /) -> None:
        self.events.append((event, payload))


def _action(name: str = "send_email", policy_name: str | None = None) -> Action:
    return Action(
        id=str(uuid.uuid4()),
        kind=ActionKind.TOOL,
        name=name,
        payload={"to": "team@example.com", "subject": "weekly report"},
        run_id=str(uuid.uuid4()),
        thread_id="t1",
    )


# ---------------------------------------------------------------------------
# Seam verdicts
# ---------------------------------------------------------------------------


async def test_seam_allow_dispatches_and_journals() -> None:
    journal = _MemoryJournal()
    executor = GuardedExecutor(journal=journal)  # default policy: allow all

    outcome = await executor.execute(_action("list_orders"))

    assert isinstance(outcome, Allowed)
    assert outcome.result["ok"] is True
    events = [e for e, _ in journal.events]
    assert events == ["action_requested", "action_completed"]


async def test_seam_deny_terminal_silent_dispatch() -> None:
    """Deny must NOT dispatch (no dispatch sentinel) — terminal, lock 5."""
    journal = _MemoryJournal()
    executor = GuardedExecutor(
        policy=SequencingPolicy(deny_names=frozenset({"list_orders"})),
        journal=journal,
    )

    outcome = await executor.execute(_action("list_orders"))

    assert isinstance(outcome, Denied)
    assert outcome.policy == "temp_deny_list"
    events = [e for e, _ in journal.events]
    assert events == ["action_requested", "action_denied"]
    # No dispatch happened — the default dispatch would return {"ok": True}.
    assert not any(e == "action_completed" for e in events)


async def test_seam_deny_wins_over_escalate() -> None:
    executor = GuardedExecutor(
        policy=SequencingPolicy(
            deny_names=frozenset({"send_email"}),
            escalate_names=frozenset({"send_email"}),
        )
    )
    outcome = await executor.execute(_action("send_email"))
    assert isinstance(outcome, Denied)


async def test_seam_escalate_returns_pending_with_gate() -> None:
    journal = _MemoryJournal()
    dispatched: list[str] = []

    async def spy(action: Action) -> dict[str, Any]:
        dispatched.append(action.name)
        return {"ok": True, "name": action.name}

    executor = GuardedExecutor(
        policy=SequencingPolicy(escalate_names=frozenset({"send_email"})),
        journal=journal,
        dispatch=spy,
    )

    outcome = await executor.execute(_action("send_email"))

    assert isinstance(outcome, Pending)
    gate = outcome.gate_request
    assert gate.action.name == "send_email"
    assert gate.context["kind"] == "tool"
    events = [e for e, _ in journal.events]
    assert events == ["action_requested", "gate_requested"]
    # Nothing dispatched yet — the action is parked, not executed.
    assert dispatched == []


async def test_seam_policy_failure_is_fail_closed() -> None:
    """An engine bug must yield Error (fail-closed), never dispatch or raise."""

    class _BrokenPolicy(SequencingPolicy):
        """A policy whose evaluate raises — simulates an engine bug (lock 4).

        Inherits SequencingPolicy so it is a real subtype the executor will
        accept; the override is the bug under test.
        """

        def evaluate(self, action: Action) -> str:
            raise RuntimeError("engine exploded")

    journal = _MemoryJournal()
    executor = GuardedExecutor(
        policy=_BrokenPolicy(),
        journal=journal,
    )

    outcome = await executor.execute(_action("send_email"))

    assert isinstance(outcome, Error)
    assert "policy" in outcome.reason.lower()
    # The intent was journaled, nothing else ran.
    events = [e for e, _ in journal.events]
    assert events == ["action_requested"]
    assert not any(e == "action_completed" for e in events)


# ---------------------------------------------------------------------------
# Gate resolution (decide_after_human)
# ---------------------------------------------------------------------------


def _decision(gate: GateRequest, verdict: GateVerdict) -> GateDecision:
    return GateDecision(
        gate_id=gate.gate_id,
        verdict=verdict,
        reason="review",
        decided_by="alice",
    )


async def test_decide_after_human_approve_dispatches() -> None:
    dispatched: list[str] = []

    async def spy(action: Action) -> dict[str, Any]:
        dispatched.append(action.name)
        return {"ok": True, "name": action.name}

    journal = _MemoryJournal()
    executor = GuardedExecutor(
        policy=SequencingPolicy(escalate_names=frozenset({"send_email"})),
        journal=journal,
        dispatch=spy,
    )
    action = _action("send_email")
    outcome = await executor.execute(action)
    assert isinstance(outcome, Pending)
    gate = outcome.gate_request

    resolved = await executor.decide_after_human(gate, _decision(gate, GateVerdict.APPROVE))

    assert isinstance(resolved, Allowed)
    assert dispatched == ["send_email"]
    # Full trail: requested -> gate_requested -> gate_decided -> completed,
    # and the human's decision lands BEFORE the approved dispatch runs.
    events = [e for e, _ in journal.events]
    assert events.index("gate_decided") < events.index("action_completed")


async def test_decide_after_human_deny_is_terminal() -> None:
    """Human deny -> Denied, and dispatch is never reached."""
    dispatched: list[str] = []

    async def spy(action: Action) -> dict[str, Any]:
        dispatched.append(action.name)
        return {"ok": True}

    executor = GuardedExecutor(
        policy=SequencingPolicy(escalate_names=frozenset({"send_email"})),
        journal=_MemoryJournal(),
        dispatch=spy,
    )
    outcome = await executor.execute(_action("send_email"))
    assert isinstance(outcome, Pending)
    gate = outcome.gate_request

    resolved = await executor.decide_after_human(gate, _decision(gate, GateVerdict.DENY))

    assert isinstance(resolved, Denied)
    assert resolved.policy == "human_denied"
    assert dispatched == []


async def test_approve_does_not_re_escalate() -> None:
    """The infinite-loop regression: approval IS the allow verdict."""
    executor = GuardedExecutor(
        policy=SequencingPolicy(escalate_names=frozenset({"send_email"})),
        journal=_MemoryJournal(),
    )
    outcome = await executor.execute(_action("send_email"))
    assert isinstance(outcome, Pending)
    gate = outcome.gate_request

    resolved = await executor.decide_after_human(gate, _decision(gate, GateVerdict.APPROVE))
    assert type(resolved) is not Pending


# ---------------------------------------------------------------------------
# Supervisor routing + multi-agent flow
# ---------------------------------------------------------------------------


async def test_supervisor_routes_research_and_finishes() -> None:
    executor = GuardedExecutor()
    graph = build_multi_agent_graph(executor)

    result = await graph.ainvoke({"task": "summarize token costs"}, _config(_fresh_thread()))

    msgs = result["messages"]
    assert any("Research:" in m for m in msgs)
    assert any("Run complete" in m for m in msgs)


async def test_supervisor_routes_ops_to_gate_then_completes_on_approve(pg_uri: str) -> None:
    """Gate park/resume needs a checkpointer — interrupt() without one raises."""
    thread_id = _fresh_thread()
    j = _MemoryJournal()
    executor = GuardedExecutor(
        policy=SequencingPolicy(escalate_names=frozenset({"send_email"})),
        journal=j,
    )
    async with CheckpointManager.create(pg_uri) as mgr:
        graph = build_multi_agent_graph(executor, checkpointer=mgr.checkpointer)
        await _run_gate_flow(graph, thread_id, j)


async def test_multi_agent_deny_flow_marks_denied() -> None:
    thread_id = _fresh_thread()
    executor = GuardedExecutor(
        policy=SequencingPolicy(deny_names=frozenset({"send_email"}))
    )
    graph = build_multi_agent_graph(executor)

    # Deny happens inside the seam — no park at all.
    result = await graph.ainvoke({"task": "email the weekly report"}, _config(thread_id))
    assert "__interrupt__" not in result
    assert any("denied" in m.lower() for m in result["messages"])
    assert result["dispatched"] == []


async def test_legacy_ttl_path_uses_one_policy_for_grant_and_enforcement() -> None:
    """Regression: the legacy `lease_ttl_seconds` knob must reach BOTH the
    supervisor's grant and the ops custody check through the same private
    policy. Before the fix, ops fell back to the module default (300s) so a
    non-default TTL could grant a short lease that ops still honored.

    Use ttl=0 (dead on arrival) + an escalating seam policy: the ops node
    must refuse custody BEFORE crossing the seam, so even an escalate-listed
    action never parks, never journals, never dispatches.
    """
    thread_id = _fresh_thread()
    journal = _MemoryJournal()
    executor = GuardedExecutor(
        policy=SequencingPolicy(escalate_names=frozenset({"send_email"})),
        journal=journal,
    )
    # Legacy path: no shared policy, ttl knob only.
    graph = build_multi_agent_graph(executor, lease_ttl_seconds=0.0)
    result = await graph.ainvoke(
        {"task": "email the weekly report"}, _config(thread_id)
    )
    assert "__interrupt__" not in result, "dead custody must never park"
    assert any("refusing to dispatch" in m for m in result["messages"])
    assert result["dispatched"] == []
    assert journal.events == [], "custody check precedes execute()"
    assert any("Run complete" in m for m in result["messages"])


async def test_legacy_ttl_path_survives_park_resume_when_inside_ttl(pg_uri: str) -> None:
    """Positive companion: a non-zero legacy TTL must let an in-TTL approve
    dispatch — the same private policy must grant a live lease AND enforce it
    on the ops side, so the seam gate is reached and the approved dispatch
    runs.
    """
    thread_id = _fresh_thread()
    journal = _MemoryJournal()
    executor = GuardedExecutor(
        policy=SequencingPolicy(escalate_names=frozenset({"send_email"})),
        journal=journal,
    )
    config = _config(thread_id)
    async with CheckpointManager.create(pg_uri) as mgr:
        graph = build_multi_agent_graph(executor, checkpointer=mgr.checkpointer, lease_ttl_seconds=300.0)
        result = await graph.ainvoke(
            {"task": "email the weekly report"}, config
        )
        assert "__interrupt__" in result
        gate_id = result["__interrupt__"][0].value["gate_id"]

        resumed = await graph.ainvoke(
            Command(resume={"verdict": "approve", "reason": "ok", "decided_by": "alice"}),
            config,
        )
        assert resumed["dispatched"] == ["send_email"]
        assert resumed["approvals"] == [f"gate {gate_id} -> approve"]
        events = [e for e, _ in journal.events]
        assert events.index("gate_decided") < events.index("action_completed")


# ---------------------------------------------------------------------------
# Park / resume + crash-recovery through the multi-agent graph
# ---------------------------------------------------------------------------


async def test_gate_id_stable_across_park_resume_restart(pg_uri: str) -> None:
    """thread_id-derived gate id must survive park, resume, and full restart."""
    thread_id = _fresh_thread()
    config = _config(thread_id)
    executor = GuardedExecutor(
        policy=SequencingPolicy(escalate_names=frozenset({"send_email"})),
        journal=_MemoryJournal(),
    )

    # Phase 1: park, capture the human-visible gate id, tear everything down.
    async with CheckpointManager.create(pg_uri) as mgr:
        graph = build_multi_agent_graph(executor, checkpointer=mgr.checkpointer)
        result = await graph.ainvoke({"task": "email the weekly report"}, config)
        assert "__interrupt__" in result
        parked_gate_id = result["__interrupt__"][0].value["gate_id"]

    # Phase 2: fresh graph + manager (simulated crash-restart), same thread.
    async with CheckpointManager.create(pg_uri) as mgr2:
        graph2 = build_multi_agent_graph(executor, checkpointer=mgr2.checkpointer)
        resumed = await graph2.ainvoke(
            Command(resume={"verdict": "approve", "decided_by": "alice"}), config
        )
        approvals = resumed.get("approvals", [])
        assert approvals == [f"gate {parked_gate_id} -> approve"]


async def _run_gate_flow(
    graph: Any, thread_id: str, journal: _MemoryJournal
) -> None:
    """Park on the ops gate, resume approve, assert the full tracked trail."""
    config = _config(thread_id)
    result = await graph.ainvoke({"task": "email the weekly report"}, config)
    assert "__interrupt__" in result
    gate_id = result["__interrupt__"][0].value["gate_id"]

    resumed = await graph.ainvoke(
        Command(resume={"verdict": "approve", "reason": "ok", "decided_by": "alice"}),
        config,
    )
    assert any("dispatched" in m for m in resumed["messages"])
    assert resumed["dispatched"] == ["send_email"]
    assert resumed["approvals"] == [f"gate {gate_id} -> approve"]
    events = [e for e, _ in journal.events]
    assert events.index("gate_decided") < events.index("action_completed")
