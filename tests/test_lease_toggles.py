"""Lease toggle tests — runtime enforcement knob end to end.

Layers:
- LeasePolicy units: toggle off -> HELD unconditionally; on -> fail-closed
  evaluate; to_state shape
- Graph integration (real Postgres): toggling enforcement OFF/ON at runtime
  changes ops behavior WITHOUT rebuilding the graph; TTL change applies to
  the next route
- HTTP: GET/POST /toggles/lease + per-run lease card (JSON + HTMX partial)
  via same-loop ASGITransport against the REAL routes with injected fixtures
"""

from __future__ import annotations

import asyncio
import sys
import uuid
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from langchain_core.runnables import RunnableConfig
from langgraph.types import Command

from warden.checkpoint import CheckpointManager
from warden.leases import Lease, LeasePolicy, LeaseVerdict
from warden.multi_agent import build_multi_agent_graph
from warden.seam import GuardedExecutor, SequencingPolicy
from warden.streaming import WardenJournalBus

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


def _config(thread_id: str) -> RunnableConfig:
    return {"configurable": {"thread_id": thread_id}}


def _fresh() -> str:
    return f"toggle-{uuid.uuid4().hex[:10]}"


def _escalating() -> GuardedExecutor:
    return GuardedExecutor(
        policy=SequencingPolicy(escalate_names=frozenset({"send_email"}))
    )


# ---------------------------------------------------------------------------
# LeasePolicy units
# ---------------------------------------------------------------------------


def test_toggle_off_holds_unconditionally() -> None:
    policy = LeasePolicy(enabled=False)
    # Even a corrupt/absent/wrong-holder lease evaluates HELD when OFF:
    assert policy.check(None, "ops", "t1") is LeaseVerdict.HELD
    assert policy.check({"holder": "who"}, "other", "zzz") is LeaseVerdict.HELD


def test_toggle_on_is_fail_closed_evaluate() -> None:
    policy = LeasePolicy(enabled=True)
    assert policy.check(None, "ops", "t1") is LeaseVerdict.NOT_HELD
    expired = Lease("ops", "t1", acquired_at=100.0, ttl_seconds=5.0)
    assert policy.check(expired, "ops", "t1", now=lambda: 999.0) is LeaseVerdict.EXPIRED
    live = Lease("ops", "t1", acquired_at=100.0, ttl_seconds=5.0)
    assert policy.check(live, "ops", "t1", now=lambda: 101.0) is LeaseVerdict.HELD


def test_policy_state_shape_and_default() -> None:
    policy = LeasePolicy()
    assert policy.to_state() == {"enabled": True, "ttl_seconds": 300.0}
    policy.ttl_seconds = 2.5
    assert policy.grant_ttl() == 2.5


# ---------------------------------------------------------------------------
# Graph: runtime toggle without rebuild (real Postgres)
# ---------------------------------------------------------------------------


async def test_toggle_off_at_runtime_skips_custody_check(pg_uri: str) -> None:
    """ttl=0 dead custody + comply toggle OFF: a NEW run dispatches (and
    gates on the policy, which is separate); custody is read live — the
    graph was NOT rebuilt."""
    policy = LeasePolicy(enabled=True, ttl_seconds=0.0)
    thread = _fresh()
    async with CheckpointManager.create(pg_uri) as mgr:
        graph = build_multi_agent_graph(
            _escalating(), checkpointer=mgr.checkpointer, lease_policy=policy
        )
        # Sanity on the same knob: with ON, dead custody refuses BEFORE the
        # gate (no interrupt); assert that first to prove the wire is real.
        refused = await graph.ainvoke({"task": "email the weekly report"}, _config(thread))
        assert "__interrupt__" not in refused
        assert any("refusing to dispatch" in m for m in refused["messages"])

        # Toggle OFF at runtime: dead-on-arrival custody no longer blocks.
        policy.enabled = False
        thread2 = _fresh()
        allowed = await graph.ainvoke({"task": "email the weekly report"}, _config(thread2))
        # Same graph object — nothing rebuilt. Ops passed custody, so the
        # seam's own policy gate (escalate) is what parks the run now.
        assert "__interrupt__" in allowed


async def test_toggle_off_then_on_restores_fail_closed(pg_uri: str) -> None:
    """The knob is symmetric: OFF passes custody (parks at the seam gate);
    ON re-arms the custody refusal on a fresh thread."""
    policy = LeasePolicy(enabled=False, ttl_seconds=0.0)
    thread = _fresh()
    async with CheckpointManager.create(pg_uri) as mgr:
        graph = build_multi_agent_graph(
            _escalating(), checkpointer=mgr.checkpointer, lease_policy=policy
        )
        allowed = await graph.ainvoke({"task": "email the weekly report"}, _config(thread))
        assert "__interrupt__" in allowed, "OFF custody lets the run reach the gate"

        # Toggle back ON for a fresh thread: custody is again enforced.
        policy.enabled = True
        thread2 = _fresh()
        refused = await graph.ainvoke({"task": "email the weekly report"}, _config(thread2))
        assert "__interrupt__" not in refused
        assert any("refusing to dispatch" in m for m in refused["messages"])
        assert refused.get("dispatched") == []


async def test_ttl_change_applies_to_next_route(pg_uri: str) -> None:
    """ granted ttl is read live: big-after-start gives the gate room."""
    policy = LeasePolicy(enabled=True, ttl_seconds=0.0)
    thread = _fresh()
    async with CheckpointManager.create(pg_uri) as mgr:
        graph = build_multi_agent_graph(
            _escalating(), checkpointer=mgr.checkpointer, lease_policy=policy
        )
        # Extend the TTL BEFORE the route: this run gets a real lease.
        policy.ttl_seconds = 300.0
        parked = await graph.ainvoke({"task": "email the weekly report"}, _config(thread))
        assert "__interrupt__" in parked
        resumed = await graph.ainvoke(
            Command(resume={"verdict": "approve", "decided_by": "alice"}), _config(thread)
        )
        assert resumed.get("dispatched") == ["send_email"]


# ---------------------------------------------------------------------------
# HTTP surface (real routes, injected fixtures, same-loop ASGITransport)
# ---------------------------------------------------------------------------


def _client(app: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    )


async def test_toggle_endpoints_round_trip() -> None:
    from warden.app import main as app_main

    # Inject fixtures (ASGITransport skips the lifespan).
    app_main.state.bus = WardenJournalBus()
    app_main.state.lease_policy = LeasePolicy(enabled=True, ttl_seconds=300.0)
    async with _client(app_main.app) as client:
        r = await client.get("/toggles/lease")
        assert r.status_code == 200
        assert r.json() == {"enabled": True, "ttl_seconds": 300.0}

        r = await client.post("/toggles/lease", json={"enabled": False})
        assert r.status_code == 200
        assert r.json() == {"enabled": False, "ttl_seconds": 300.0}

        r = await client.post("/toggles/lease", json={"ttl_seconds": 45.0})
        assert r.status_code == 200
        assert r.json() == {"enabled": False, "ttl_seconds": 45.0}

        # Partial body changes only provided keys (verify via read side).
        r = await client.get("/toggles/lease")
        assert r.json() == {"enabled": False, "ttl_seconds": 45.0}


async def test_toggle_rejects_invalid_ttl() -> None:
    from warden.app import main as app_main

    app_main.state.bus = WardenJournalBus()
    app_main.state.lease_policy = LeasePolicy()
    async with _client(app_main.app) as client:
        r = await client.post("/toggles/lease", json={"ttl_seconds": 0})
        assert r.status_code == 422
        # The policy is untouched by the failed write.
        assert app_main.state.lease_policy.ttl_seconds == 300.0


# ---------------------------------------------------------------------------
# Per-run lease card (real Postgres graph behind the endpoint)
# ---------------------------------------------------------------------------


async def test_run_lease_card_json_and_htmx_partial(pg_uri: str) -> None:
    from warden.app import main as app_main

    policy = LeasePolicy(enabled=True, ttl_seconds=300.0)
    thread = _fresh()
    async with CheckpointManager.create(pg_uri) as mgr:
        graph = build_multi_agent_graph(
            _escalating(), checkpointer=mgr.checkpointer, lease_policy=policy
        )
        # Drive one parked run so state carries a live ops lease.
        parked = await graph.ainvoke({"task": "email the weekly report"}, _config(thread))
        assert "__interrupt__" in parked

        app_main.state.bus = WardenJournalBus()
        app_main.state.lease_policy = policy
        app_main.state.manager = mgr
        app_main.state.graph = graph
        try:
            async with _client(app_main.app) as client:
                # JSON side
                r = await client.get(f"/runs/{thread}/lease")
                assert r.status_code == 200
                body = r.json()
                assert body["lease"]["holder"] == "ops"
                assert body["verdict"] == "held"
                assert body["policy"]["enabled"] is True
                assert body["remains_seconds"] > 0.0

                # HTMX partial side
                r = await client.get(
                    f"/runs/{thread}/lease", headers={"accept": "text/html"}
                )
                assert r.status_code == 200
                text = r.text
                assert "lease-card" in text
                assert "ops" in text
                assert "enforcement ON" in text
                assert "left" in text
        finally:
            app_main.state.manager = None
            app_main.state.graph = None
