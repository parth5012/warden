"""Lease evaluation tests — unit (pure clock) + graph integration (real PG).

Unit coverage: grant/evaluate verdicts, fail-closed on absent/corrupt state,
expiry boundary, thread/holder mismatch, idempotent re-acquire (no TTL
extension on resume), no stealing, serialization round-trip.

Integration coverage: supervisor grants a lease through the real graph,
ops refuses to dispatch when the lease is expired (fail-closed), and an
approve that arrives within the TTL still dispatches after park/resume.
"""

from __future__ import annotations

import asyncio
import sys
import uuid
from typing import Any

import pytest
from langchain_core.runnables import RunnableConfig
from langgraph.types import Command

from warden.checkpoint import CheckpointManager
from warden.leases import (
    Lease,
    LeaseNotHeld,
    LeaseVerdict,
    evaluate,
    expires_at,
    grant,
    reacquire,
    remaining,
    require,
)
from warden.multi_agent import build_multi_agent_graph
from warden.seam import GuardedExecutor, SequencingPolicy

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


class _MemoryJournal:
    """In-memory journal sink recording (event, payload) pairs in order."""

    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    async def append(self, event: str, payload: dict[str, Any], /) -> None:
        self.events.append((event, payload))


def _config(thread_id: str) -> RunnableConfig:
    return {"configurable": {"thread_id": thread_id}}


def _fresh_thread() -> str:
    return f"lease-{uuid.uuid4().hex[:12]}"


# ---------------------------------------------------------------------------
# Unit: evaluate verdicts (injected clock — no sleeping)
# ---------------------------------------------------------------------------


def _leased(t: float, ttl: float = 60.0, holder: str = "ops", thread: str = "t1") -> Lease:
    return grant(holder, thread, ttl, purpose="test", now=lambda: t)


def test_held_within_ttl() -> None:
    lease = _leased(t=100.0, ttl=60.0)
    assert evaluate(lease, "ops", "t1", now=lambda: 130.0) is LeaseVerdict.HELD


def test_expired_at_and_after_ttl_boundary() -> None:
    lease = _leased(t=100.0, ttl=60.0)
    # age == ttl is already expired (age >= ttl)
    assert evaluate(lease, "ops", "t1", now=lambda: 160.0) is LeaseVerdict.EXPIRED
    assert evaluate(lease, "ops", "t1", now=lambda: 159.999) is LeaseVerdict.HELD


def test_zero_ttl_is_never_held() -> None:
    lease = _leased(t=100.0, ttl=0.0)
    assert evaluate(lease, "ops", "t1", now=lambda: 100.0) is LeaseVerdict.EXPIRED


def test_absent_lease_fails_closed() -> None:
    assert evaluate(None, "ops", "t1") is LeaseVerdict.NOT_HELD
    assert evaluate({}, "ops", "t1") is LeaseVerdict.NOT_HELD


def test_corrupt_lease_fails_closed() -> None:
    junk: list[dict[str, Any]] = [
        {"holder": 42, "thread_id": "t1", "acquired_at": 1.0, "ttl_seconds": 5.0},
        {"holder": "ops", "thread_id": None, "acquired_at": 1.0, "ttl_seconds": 5.0},
        {"holder": "ops", "thread_id": "t1", "acquired_at": "1.0", "ttl_seconds": 5.0},
        {"holder": "ops", "thread_id": "t1", "acquired_at": True, "ttl_seconds": 5.0},
        {"holder": "ops", "thread_id": "t1", "acquired_at": 1.0, "ttl_seconds": "5"},
        "not-a-dict",  # type: ignore[list-item]
    ]
    for bad in junk:
        assert evaluate(bad, "ops", "t1", now=lambda: 2.0) is LeaseVerdict.NOT_HELD


def test_wrong_holder_cannot_use_someone_elses_lease() -> None:
    lease = _leased(t=100.0, holder="ops")
    assert evaluate(lease, "research", "t1", now=lambda: 101.0) is LeaseVerdict.NOT_HELD


def test_wrong_thread_cannot_use_another_runs_lease() -> None:
    lease = _leased(t=100.0, thread="t9")
    assert evaluate(lease, "ops", "t1", now=lambda: 101.0) is LeaseVerdict.NOT_HELD


def test_bool_ttl_warranty() -> None:
    """isinstance(ttl, bool) guard: True must not silently become ttl=1s."""
    raw = {"holder": "ops", "thread_id": "t1", "acquired_at": 100.0, "ttl_seconds": True}
    assert evaluate(raw, "ops", "t1", now=lambda: 100.5) is LeaseVerdict.NOT_HELD


# ---------------------------------------------------------------------------
# Unit: require / remaining / expires_at / serialization
# ---------------------------------------------------------------------------


def test_require_returns_lease_when_held_and_raises_otherwise() -> None:
    lease = _leased(t=100.0, ttl=60.0)
    assert require(lease, "ops", "t1", now=lambda: 101.0) is lease
    with pytest.raises(LeaseNotHeld):
        require(lease, "ops", "t1", now=lambda: 999.0)
    with pytest.raises(LeaseNotHeld):
        require(None, "ops", "t1")
    # the raised error carries the verdict for journaling
    with pytest.raises(LeaseNotHeld) as exc_info:
        require(lease, "ops", "t1", now=lambda: 999.0)
    assert exc_info.value.verdict is LeaseVerdict.EXPIRED


def test_remaining_and_expires_at() -> None:
    lease = _leased(t=100.0, ttl=60.0)
    assert expires_at(lease) == pytest.approx(160.0)
    assert remaining(lease, now=lambda: 130.0) == pytest.approx(30.0)
    assert remaining(lease, now=lambda: 999.0) == 0.0


def test_state_round_trip() -> None:
    lease = _leased(t=100.0, ttl=60.0, holder="research", thread="th")
    rebuilt = Lease.from_state(lease.to_state())
    assert rebuilt == lease
    # and through an int-jsonb round trip
    raw = lease.to_state()
    raw["ttl_seconds"] = 60  # int after jsonb round trip
    assert Lease.from_state(raw) is not None


# ---------------------------------------------------------------------------
# Unit: reacquire (idempotence / no TTL extension / no stealing)
# ---------------------------------------------------------------------------


def test_reacquire_same_holder_live_lease_is_unchanged() -> None:
    """Resume must NOT extend the TTL — the custody clock keeps ticking."""
    lease = _leased(t=100.0, ttl=60.0, holder="ops")
    again = reacquire(lease, "ops", "t1", 60.0, now=lambda: 150.0)
    assert again is lease, "live re-acquire must return the SAME lease object"
    # and it still expires on the original clock
    assert evaluate(again, "ops", "t1", now=lambda: 160.0) is LeaseVerdict.EXPIRED


def test_reacquire_after_expiry_grants_fresh() -> None:
    lease = _leased(t=100.0, ttl=60.0, holder="ops")
    fresh = reacquire(lease, "ops", "t1", 60.0, now=lambda: 200.0)
    assert fresh is not None and fresh.holder == "ops"
    assert fresh.acquired_at == pytest.approx(200.0)


def test_reacquire_cannot_steal_live_lease() -> None:
    lease = _leased(t=100.0, ttl=60.0, holder="research")
    assert reacquire(lease, "ops", "t1", 60.0, now=lambda: 120.0) is None


def test_reacquire_other_thread_grants_fresh() -> None:
    """A lease held on another run is irrelevant here — grant fresh."""
    lease = _leased(t=100.0, ttl=60.0, holder="ops", thread="t9")
    fresh = reacquire(lease, "ops", "t1", 60.0, now=lambda: 101.0)
    assert fresh is not None and fresh.thread_id == "t1"


# ---------------------------------------------------------------------------
# Integration: leases ride the real graph + Postgres checkpointer
# ---------------------------------------------------------------------------


def _escalating_executor() -> GuardedExecutor:
    return GuardedExecutor(
        policy=SequencingPolicy(escalate_names=frozenset({"send_email"}))
    )


async def test_supervisor_grants_lease_and_ops_holds_it(pg_uri: str) -> None:
    thread_id = _fresh_thread()
    graph = build_multi_agent_graph(_escalating_executor())

    # plain research flow: supervisor grants lease; the research
    # specialist dispatches no tools, so the run completes without custody checks.
    result = await graph.ainvoke({"task": "summarize token costs"}, _config(thread_id))
    assert any("Run complete" in m for m in result["messages"])


async def test_expired_lease_fails_closed_before_dispatch(pg_uri: str) -> None:
    """With ttl=0 the granted lease is dead on arrival: ops must refuse to
    dispatch BEFORE crossing the seam — no journal entry, no gate, no email."""
    thread_id = _fresh_thread()
    journal = _MemoryJournal()
    executor = GuardedExecutor(
        policy=SequencingPolicy(escalate_names=frozenset({"send_email"})),
        journal=journal,
    )
    graph = build_multi_agent_graph(executor, lease_ttl_seconds=0.0)

    result = await graph.ainvoke({"task": "email the weekly report"}, _config(thread_id))

    assert "__interrupt__" not in result, "dead custody must never park for approval"
    assert any("refusing to dispatch" in m for m in result["messages"])
    assert result["dispatched"] == []
    # nothing crossed the seam at all: custody check precedes execute()
    assert journal.events == []
    # the supervisor still collected the run and ended it
    assert any("Run complete" in m for m in result["messages"])


async def test_resume_inside_ttl_still_dispatches(pg_uri: str) -> None:
    """Approve that arrives within the TTL dispatches (lease resumes intact)."""
    thread_id = _fresh_thread()
    executor = _escalating_executor()
    config = _config(thread_id)
    parked_gate_id: str | None = None
    async with CheckpointManager.create(pg_uri) as mgr:
        graph = build_multi_agent_graph(executor, checkpointer=mgr.checkpointer)
        result = await graph.ainvoke({"task": "email the weekly report"}, config)
        assert "__interrupt__" in result
        parked_gate_id = result["__interrupt__"][0].value["gate_id"]

        resumed = await graph.ainvoke(
            Command(resume={"verdict": "approve", "decided_by": "alice"}), config
        )
        approvals = resumed.get("approvals", [])
        assert approvals == [f"gate {parked_gate_id} -> approve"]
        # dispatch happened => the lease survived park->resume within TTL
        assert resumed.get("dispatched") == ["send_email"]
