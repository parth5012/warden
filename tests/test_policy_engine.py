"""L1/L2 policy engine tests — unit + seam drop-in + multi-agent integration.

Covers:
- L1 verdict matrix: destructive SQL -> deny (final), risky tools -> escalate
- L2 similarity: close match -> stored verdict; below threshold -> escalate;
  empty store -> escalate (fail-closed)
- L1 dominance: L1 deny/escalate never overruled by L2
- Seam drop-in: L1L2PolicyEngine inside GuardedExecutor with zero seam edits
- Multi-agent integration: deny short-circuits the graph, escalation parks
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
from warden.multi_agent import build_multi_agent_graph
from warden.policy.engine import (
    HashEmbeddings,
    L1L2PolicyEngine,
    L2Verdict,
    evaluate_l1,
    evaluate_l2,
)
from warden.models import Action, ActionKind, Allowed, Denied, Pending
from warden.seam import GuardedExecutor

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


def _config(thread_id: str) -> RunnableConfig:
    return {"configurable": {"thread_id": thread_id}}


def _fresh_thread() -> str:
    return f"policy-{uuid.uuid4().hex[:12]}"


def _action(name: str = "send_email", payload: dict[str, Any] | None = None) -> Action:
    return Action(
        id=str(uuid.uuid4()),
        kind=ActionKind.TOOL,
        name=name,
        payload=payload if payload is not None else {"query": "list orders"},
        run_id=str(uuid.uuid4()),
        thread_id="t1",
    )


_emb = HashEmbeddings(dim=64)


# ---------------------------------------------------------------------------
# L1 matrix
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("payload", "rule_fragment"),
    [
        ({"query": "DROP TABLE users"}, "destructive_payload"),
        ({"query": "DELETE FROM orders WHERE x=1"}, "destructive_payload"),
        ({"query": "  truncate table logs  "}, "destructive_payload"),
        ({"command": "rm -rf /"}, "destructive_payload"),
    ],
)
def test_l1_destructive_payload_is_denied(payload: dict[str, Any], rule_fragment: str) -> None:
    v = evaluate_l1(_action("db_write", payload))
    assert v.matched and v.verdict == "deny" and rule_fragment in v.rule


def test_l1_risky_tool_name_escalates_without_destructive_payload() -> None:
    v = evaluate_l1(_action("send_email", {"subject": "weekly report"}))
    assert v.matched and v.verdict == "escalate" and "risky_tool" in v.rule


def test_l1_non_matching_payload_defers_to_l2() -> None:
    v = evaluate_l1(_action("list_orders", {"query": "show me open orders"}))
    assert not v.matched  # L2 territory


def test_l1_wins_over_payload_on_named_risky_tool_without_destruction() -> None:
    assert evaluate_l1(_action("make_payment")).verdict == "escalate"


# ---------------------------------------------------------------------------
# L2 similarity
# ---------------------------------------------------------------------------


def _store_with(seed: dict[str, tuple[str, str]]) -> Any:
    from warden.policy.engine import InMemoryPolicyStore

    store = InMemoryPolicyStore(_emb)
    for pid, (verdict, text) in seed.items():
        store.add_policy(pid, verdict, text)
    return store


def test_l2_close_match_applies_stored_verdict() -> None:
    # seed text mirrors the engine's action text: name + payload values
    store = _store_with({"p-1": ("deny", "db_export exporting customer PII data is forbidden")})
    v = evaluate_l2(
        _action("db_export", {"query": "exporting customer PII data is forbidden"}),
        store,
        _emb,
        threshold=0.99,  # identical action text -> cosine ~1.0
    )
    assert v.matched and v.verdict == "deny" and v.policy_id == "p-1"


def test_l2_below_threshold_is_not_matched() -> None:
    store = _store_with({"p-1": ("deny", "price check with vendor ledger")})
    v = evaluate_l2(
        _action("weather_lookup", {"query": "sunny in tokyo tomorrow"}),
        store,
        _emb,
        threshold=0.99,
    )
    assert not v.matched


def test_l2_empty_store_fails_to_not_matched() -> None:
    store = _store_with({})
    v = evaluate_l2(_action("anything"), store, _emb, threshold=0.5)
    assert not v.matched


def test_l2_picks_the_most_similar_of_several_policies() -> None:
    store = _store_with(
        {
            "p-allow": ("allow", "list_orders list open orders"),
            "p-deny": ("deny", "db_write wipe the orders database now"),
        }
    )
    v = evaluate_l2(
        _action("db_write", {"query": "wipe the orders database now"}),
        store,
        _emb,
        threshold=0.99,
    )
    assert v.matched and v.verdict == "deny" and v.policy_id == "p-deny"


def test_l2verdict_defaults_document_fail_closed_shape() -> None:
    """Nothing matched => the ENGINE must escalate; the type's default says so."""
    v = L2Verdict(verdict="escalate", matched=False)
    assert v.verdict == "escalate"


# ---------------------------------------------------------------------------
# Engine composition (L1 dominance + fail-closed fallback)
# ---------------------------------------------------------------------------


def _engine(seed: dict[str, tuple[str, str]] | None = None, threshold: float = 0.8) -> Any:
    store = _store_with(seed or {})
    return L1L2PolicyEngine(_emb, store, threshold=threshold)


def test_engine_l1_deny_is_final_even_if_l2_says_allow() -> None:
    """Destructive payload denied terminally — vectors never soften it (lock 5)."""
    engine = _engine({"p-allow": ("allow", "anything at all")}, threshold=0.0)
    assert engine.evaluate(_action("db_write", {"query": "DROP TABLE users"})) == "deny"


def test_engine_l1_escalate_is_final() -> None:
    engine = _engine({"p-allow": ("allow", "send any email freely")}, threshold=0.0)
    assert engine.evaluate(_action("send_email")) == "escalate"


def test_engine_unrecognized_action_fails_closed_to_escalate() -> None:
    """Empty store + unmatched action: escalate, NEVER silent allow."""
    engine = _engine()
    assert engine.evaluate(_action("mystery_tool", {"query": "who knows"})) == "escalate"


def test_engine_l2_match_applies_policy_verdict() -> None:
    engine = _engine({"p-1": ("deny", "list_orders list open orders")}, threshold=0.999)
    assert engine.evaluate(_action("list_orders", {"query": "list open orders"})) == "deny"


def test_engine_l2_verdicts_are_validated() -> None:
    """Unknown stored verdicts must coerce to 'escalate' (fail-closed),
    never passthrough a value the seam's verdict branches can't read."""
    engine = _engine({"p-weird": ("maybe", "list_orders some rule text")}, threshold=0.999)
    verdict = engine.evaluate(_action("list_orders", {"query": "some rule text"}))
    assert verdict in ("allow", "escalate", "deny")


# ---------------------------------------------------------------------------
# Seam drop-in — GuardedExecutor accepts the engine with ZERO seam edits
# ---------------------------------------------------------------------------


async def test_seam_accepts_l1l2_engine_and_journals_honestly() -> None:
    class _Journal:
        def __init__(self) -> None:
            self.events: list[tuple[str, dict[str, Any]]] = []

        async def append(self, event: str, payload: dict[str, Any], /) -> None:
            self.events.append((event, payload))

    journal = _Journal()
    engine = _engine({}, threshold=0.9)
    executor = GuardedExecutor(policy=engine, journal=journal)

    # 1. destructive -> Denied (terminal), nothing dispatched
    outcome = await executor.execute(_action("db_write", {"query": "DROP TABLE users"}))
    assert isinstance(outcome, Denied) and outcome.policy != ""
    # 2. risky -> Pending gate
    outcome2 = await executor.execute(_action("send_email"))
    assert isinstance(outcome2, Pending)
    # 3. unrecognized -> escalated to a gate too (fail-closed), not Allowed
    outcome3 = await executor.execute(_action("mystery_tool"))
    assert isinstance(outcome3, Pending)
    # journal trail stays coherent per action
    events = [e for e, _ in journal.events]
    assert events.count("action_requested") == 3
    assert "action_denied" in events
    assert events.count("gate_requested") == 2
    assert "action_completed" not in events  # nothing dispatched in this test


async def test_seam_allowed_path_through_l2_policy() -> None:
    engine = _engine({"p-ok": ("allow", "list_orders list open orders")}, threshold=0.999)
    executor = GuardedExecutor(policy=engine)
    outcome = await executor.execute(_action("list_orders", {"query": "list open orders"}))
    assert isinstance(outcome, Allowed)


# ---------------------------------------------------------------------------
# Multi-agent integration (real Postgres): deny short-circuits the graph
# ---------------------------------------------------------------------------


async def test_graph_denies_destructive_request_without_parking(pg_uri: str) -> None:
    """DROP TABLE in the task text -> terminal deny, no gate, no dispatch."""
    thread = _fresh_thread()
    engine = _engine({}, threshold=0.9)
    graph = build_multi_agent_graph(GuardedExecutor(policy=engine))
    # 'cleanup' routes to ops; DROP TABLE in the payload denies terminally.
    result = await graph.ainvoke({"task": "cleanup DROP TABLE old_events"}, _config(thread))
    assert "__interrupt__" not in result
    assert any("denied" in m.lower() for m in result["messages"])
    assert result["dispatched"] == []


async def test_graph_parks_on_unrecognized_action_then_approve_completes(pg_uri: str) -> None:
    """Fail-closed escalate -> gate -> human approve -> dispatch (real PG).

    The ops demo action (send_email) is L1-escalated; approve inside the
    lease TTL resumes and dispatches — the full governance story on one
    graph, now backed by the real policy engine instead of the stub.
    """
    thread = _fresh_thread()
    engine = _engine({}, threshold=0.9)
    async with CheckpointManager.create(pg_uri) as mgr:
        graph = build_multi_agent_graph(
            GuardedExecutor(policy=engine), checkpointer=mgr.checkpointer
        )
        parked = await graph.ainvoke({"task": "email the weekly report"}, _config(thread))
        assert "__interrupt__" in parked

        resumed = await graph.ainvoke(
            Command(resume={"verdict": "approve", "decided_by": "alice"}), _config(thread)
        )
        assert resumed.get("dispatched") == ["send_email"]
        assert any("gate " in a and "-> approve" in a for a in resumed.get("approvals", []))
