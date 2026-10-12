"""HITL web-flow tests — named keys, inbox projection, decision endpoint.

Layers:
- NamedKeys (lock 8): parse env, key->principal (never client-supplied), errors
- GateRegistry: pure projection over journaled events (request/decide/
  idempotency/unknown), pending vs decided views, resume_value contract
- HTTP via same-loop ASGITransport: /inbox JSON+HTMX, /gates/{id}/decision
  auth (401 unknown key / 401 missing), 422 bad verdict, 404 unknown gate,
  409 double-decide, and the happy path's journal-before-resume ordering
- Real-Postgres e2e: a genuinely parked graph whose gate is resolved THROUGH
  the endpoint — approve dispatches, deny aborts —journaled by real seam events
"""

from __future__ import annotations

import asyncio
import sys
import uuid
from typing import Any

import httpx
import pytest
from langchain_core.runnables import RunnableConfig
from langgraph.types import Command

from warden.checkpoint import CheckpointManager
from warden.hitl.gates import (
    ApproverError,
    GateRegistry,
    NamedKeys,
    normalize_verdict,
)
from warden.multi_agent import build_multi_agent_graph
from warden.seam import GuardedExecutor, SequencingPolicy
from warden.streaming import WardenJournalBus

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


def _config(thread_id: str) -> RunnableConfig:
    return {"configurable": {"thread_id": thread_id}}


def _fresh() -> str:
    return f"gate-{uuid.uuid4().hex[:10]}"


def _client(app: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    )


async def _park_and_build(pg_uri: str) -> tuple[Any, WardenJournalBus, str]:
    """Park a real graph on the seam gate; return (graph, bus, thread_id)."""
    bus = WardenJournalBus()
    executor = GuardedExecutor(
        policy=SequencingPolicy(escalate_names=frozenset({"send_email"})),
        journal=bus,
    )
    from warden.multi_agent import build_multi_agent_graph as _build

    graph = _build(executor)  # no checkpointer here; real tests pass mgr's
    return graph, bus, _fresh()


# ---------------------------------------------------------------------------
# Named keys (lock 8)
# ---------------------------------------------------------------------------


def test_named_keys_parse_env() -> None:
    keys = NamedKeys.from_env("alice=s3cret, bob=hunter2 ,")
    assert keys.principal_for("s3cret") == "alice"
    assert keys.principal_for("hunter2") == "bob"


def test_named_keys_reject_bad_shapes() -> None:
    with pytest.raises(ApproverError):
        NamedKeys.from_env("")
    with pytest.raises(ApproverError):
        NamedKeys.from_env("alice=")
    with pytest.raises(ApproverError):
        NamedKeys.from_env("noequals")
    with pytest.raises(ApproverError):
        NamedKeys.from_env("will=it,blends=bad,=nope")


def test_principal_unknown_key_raises_not_client_text() -> None:
    keys = NamedKeys.from_env("alice=s3cret")
    with pytest.raises(ApproverError):
        keys.principal_for("not-a-key")
    with pytest.raises(ApproverError):
        keys.principal_for_header(None)
    with pytest.raises(ApproverError):
        keys.principal_for_header("  ")
    # A client SUPPLYING a name never attributes to it — identity is the key.
    with pytest.raises(ApproverError):
        keys.principal_for_header("mallory")


# ---------------------------------------------------------------------------
# GateRegistry projection
# ---------------------------------------------------------------------------


def _evt(event: str, payload: dict[str, Any]) -> Any:
    from datetime import datetime, timezone

    from warden.streaming import WardenEvent

    return WardenEvent(
        id=0, event=event, payload=payload,
        ts=datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
    )


def test_registry_pending_then_decided() -> None:
    reg = GateRegistry()
    reg.consume(_evt("gate_requested", {"gate_id": "g1", "actor": "send_email", "thread_id": "t1"}))
    assert [v.gate_id for v in reg.pending()] == ["g1"]

    reg.consume(_evt("gate_decided", {"gate_id": "g1", "verdict": "approve", "decided_by": "alice"}))
    assert reg.pending() == []
    asserted = reg.must_get("g1")
    assert asserted.verdict == "approve" and asserted.decided_by == "alice"


def test_registry_idempotent_request_and_unknown_decide() -> None:
    reg = GateRegistry()
    req = _evt("gate_requested", {"gate_id": "g1", "actor": "a", "thread_id": "t"})
    reg.consume(req)
    reg.consume(_evt("gate_requested", {"gate_id": "g1", "actor": "a", "thread_id": "t"}))
    assert len(reg.pending()) == 1
    reg.consume(_evt("gate_decided", {"gate_id": "nope", "verdict": "approve", "decided_by": "x"}))
    assert reg.get("nope") is None


def test_registry_double_decision_guard() -> None:
    reg = GateRegistry()
    reg.consume(_evt("gate_requested", {"gate_id": "g1", "actor": "a", "thread_id": "t"}))
    reg.consume(_evt("gate_decided", {"gate_id": "g1", "verdict": "deny", "decided_by": "bob"}))
    with pytest.raises(ValueError, match="already decided"):
        reg.assert_pending("g1")


def test_resume_value_contract_shape() -> None:
    value = GateRegistry.resume_value("g1", "approve", "alice", "ok")
    assert value == {"verdict": "approve", "reason": "ok", "decided_by": "alice"}


def test_normalize_verdict_accepts_synonyms_rejects_junk() -> None:
    assert normalize_verdict("Approve ") == "approve"
    assert normalize_verdict("ALLOW") == "approve"
    assert normalize_verdict("reject") == "deny"
    with pytest.raises(ApproverError):
        normalize_verdict("maybe")


def test_registry_builds_from_journal_bus_history() -> None:
    bus = WardenJournalBus()

    async def build() -> None:
        await bus.append("gate_requested", {"gate_id": "g1", "actor": "send_email", "thread_id": "t1"})
        reg = GateRegistry.from_bus(bus)
        assert [v.gate_id for v in reg.pending()] == ["g1"]

    asyncio.new_event_loop().run_until_complete(build()) if False else None
    asyncio.run(build())


# ---------------------------------------------------------------------------
# HTTP surface (real routes, injected fixtures)
# ---------------------------------------------------------------------------


async def test_inbox_json_and_htmx_from_journal() -> None:
    from warden.app import main as app_main

    bus = WardenJournalBus()
    await bus.append("gate_requested", {"gate_id": "g9", "actor": "send_email", "thread_id": "t9", "payload": {"to": "team@example.com"}})
    app_main.state.bus = bus
    app_main.state.registry = GateRegistry.from_bus(bus)
    app_main.state.approver_keys = NamedKeys.from_env("alice=alpha,bob=beta")
    app_main.state.manager = None
    app_main.state.graph = None
    try:
        async with _client(app_main.app) as client:
            r = await client.get("/inbox")
            assert r.status_code == 200
            body = r.json()
            assert [g["gate_id"] for g in body["pending"]] == ["g9"]

            r = await client.get("/inbox", headers={"accept": "text/html"})
            assert r.status_code == 200
            assert "gate-card" in r.text
            assert "send_email" in r.text
    finally:
        app_main.state.bus = WardenJournalBus()


async def test_decision_auth_and_validation_errors() -> None:
    from warden.app import main as app_main

    bus = WardenJournalBus()
    await bus.append("gate_requested", {"gate_id": "g1", "actor": "send_email", "thread_id": "t1"})
    app_main.state.bus = bus
    app_main.state.approver_keys = NamedKeys.from_env("alice=alpha,bob=beta")
    app_main.state.graph = None  # auth/validation paths resolve before resume
    try:
        async with _client(app_main.app) as client:
            # missing key
            r = await client.post("/gates/g1/decision", json={"verdict": "approve", "reason": " r"})
            assert r.status_code == 401
            # unknown key
            r = await client.post(
                "/gates/g1/decision", json={"verdict": "approve"},
                headers={"Warden-Key": "mallory"},
            )
            assert r.status_code == 401
            # bad verdict
            r = await client.post(
                "/gates/g1/decision", json={"verdict": "maybe"},
                headers={"Warden-Key": "alpha"},
            )
            assert r.status_code == 422
            # unknown gate
            r = await client.post(
                "/gates/zzz/decision", json={"verdict": "approve"},
                headers={"Warden-Key": "alpha"},
            )
            assert r.status_code == 404
            # journal untouched by failed attempts: still pending
            assert [v.gate_id for v in GateRegistry.from_bus(bus).pending()] == ["g1"]
    finally:
        app_main.state.bus = WardenJournalBus()


async def test_decision_journals_before_resume_and_double_decide_409() -> None:
    """Without a graph (parked-run resume N/A), the decision still journals."""
    from warden.app import main as app_main

    bus = WardenJournalBus()
    await bus.append("gate_requested", {"gate_id": "g1", "actor": "send_email", "thread_id": ""})
    app_main.state.bus = bus
    app_main.state.approver_keys = NamedKeys.from_env("alice=alpha")
    app_main.state.graph = None
    try:
        async with _client(app_main.app) as client:
            r = await client.post(
                "/gates/g1/decision",
                json={"verdict": "approve", "reason": "ship it"},
                headers={"Warden-Key": "alpha"},
            )
            assert r.status_code == 200
            body = r.json()
            assert body["decided_by"] == "alice" and body["verdict"] == "approve"
            assert body["resumed"] is None  # no graph: no parked run to resume

            events = [e.event for e in bus.history()]
            assert "gate_decided" in events

            # double-decide -> 409, and the journal is not rewritten
            r = await client.post(
                "/gates/g1/decision",
                json={"verdict": "deny", "reason": "changed my mind"},
                headers={"Warden-Key": "alpha"},
            )
            assert r.status_code == 409
            decided_events = [e for e in bus.history() if e.event == "gate_decided"]
            assert len(decided_events) == 1
            assert decided_events[0].payload["verdict"] == "approve"
    finally:
        app_main.state.bus = WardenJournalBus()


# ---------------------------------------------------------------------------
# Real-Postgres e2e: endpoint resolves a genuinely parked graph
# ---------------------------------------------------------------------------


def _unused_parked_helper() -> None:
    """(kept intentionally empty) — replaced by the inline e2e parking below."""


async def test_web_approval_completes_parked_run(pg_uri: str) -> None:
    """Full locked flow: seam gate -> journal -> inbox -> POST decision ->
    Command(resume) -> dispatch. Approve dispatches; a second run denies."""
    from warden.app import main as app_main

    thread = _fresh()
    async with CheckpointManager.create(pg_uri) as mgr:
        bus = WardenJournalBus()
        executor = GuardedExecutor(
            policy=SequencingPolicy(escalate_names=frozenset({"send_email"})),
            journal=bus,
        )
        graph = build_multi_agent_graph(executor, checkpointer=mgr.checkpointer)

        # Park via the real seam.
        parked = await graph.ainvoke({"task": "email the weekly report"}, _config(thread))
        assert "__interrupt__" in parked
        gate_id = parked["__interrupt__"][0].value["gate_id"]

        app_main.state.bus = bus
        app_main.state.approver_keys = NamedKeys.from_env("alice=alpha")
        app_main.state.manager = mgr
        app_main.state.graph = graph
        try:
            async with _client(app_main.app) as client:
                # Inbox shows the pending gate (projected from the real seam journal)
                r = await client.get("/inbox")
                pend = r.json()["pending"]
                assert gate_id in [g["gate_id"] for g in pend]

                # Approve with bob's key (identity = key, not client text)
                r = await client.post(
                    f"/gates/{gate_id}/decision",
                    json={"verdict": "approve", "reason": "approved by alice"},
                    headers={"Warden-Key": "alpha"},
                )
                assert r.status_code == 200
                resumed = r.json()["resumed"]
                assert resumed is not None
                assert resumed["dispatched"] == ["send_email"]
                assert any("gate " in a and "-> approve" in a for a in resumed["approvals"])

                # Journal-first proof: the approved dispatch event exists now
                events = [e.event for e in bus.history()]
                di = events.index("gate_decided")
                ci = events.index("action_completed")
                assert di < ci
        finally:
            app_main.state.bus = WardenJournalBus()
            app_main.state.graph = None
            app_main.state.manager = None


async def test_web_denial_aborts_parked_run(pg_uri: str) -> None:
    """Web deny -> no dispatch, run completes unexecuted (lock 5 terminal)."""
    from warden.app import main as app_main

    thread = _fresh()
    async with CheckpointManager.create(pg_uri) as mgr:
        bus = WardenJournalBus()
        executor = GuardedExecutor(
            policy=SequencingPolicy(escalate_names=frozenset({"send_email"})),
            journal=bus,
        )
        graph = build_multi_agent_graph(executor, checkpointer=mgr.checkpointer)
        parked = await graph.ainvoke({"task": "email the weekly report"}, _config(thread))
        assert "__interrupt__" in parked
        gate_id = parked["__interrupt__"][0].value["gate_id"]

        app_main.state.bus = bus
        app_main.state.approver_keys = NamedKeys.from_env("bob=beta")
        app_main.state.manager = mgr
        app_main.state.graph = graph
        try:
            async with _client(app_main.app) as client:
                r = await client.post(
                    f"/gates/{gate_id}/decision",
                    json={"verdict": "deny", "reason": "not today"},
                    headers={"Warden-Key": "beta"},
                )
                assert r.status_code == 200
                resumed = r.json()["resumed"]
                assert resumed is not None
                assert resumed["dispatched"] == []
                # deny is denied: the gate trail says so
                assert any("gate " in a and "-> deny" in a for a in resumed["approvals"])
        finally:
            app_main.state.bus = WardenJournalBus()
            app_main.state.graph = None
            app_main.state.manager = None
