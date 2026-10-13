"""Integration tests for audit search kinds and thread timeline rendering."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.main import create_app
from warden.grants import (
    Grant,
    InMemoryGrantsStore,
    ScopeRule,
    set_grants_store,
)
from warden.journal import EventKind, JournalEvent

client = TestClient(create_app())


@pytest.fixture(autouse=True)
def clean_stores() -> None:
    set_grants_store(InMemoryGrantsStore())


def test_audit_search_by_grant_kinds() -> None:
    # 1. Search kind=grant_issued
    res_issued = client.get("/api/audit?kind=grant_issued")
    assert res_issued.status_code == 200
    events_issued = res_issued.json()["events"]
    assert len(events_issued) >= 1
    assert all(e["kind"] == "grant_issued" for e in events_issued)

    # 2. Search kind=grant_consumed
    res_consumed = client.get("/api/audit?kind=grant_consumed")
    assert res_consumed.status_code == 200
    events_consumed = res_consumed.json()["events"]
    assert len(events_consumed) >= 1
    assert all(e["kind"] == "grant_consumed" for e in events_consumed)

    # 3. Search kind=grant_revoked
    res_revoked = client.get("/api/audit?kind=grant_revoked")
    assert res_revoked.status_code == 200
    events_revoked = res_revoked.json()["events"]
    assert len(events_revoked) >= 1
    assert all(e["kind"] == "grant_revoked" for e in events_revoked)


def test_grant_using_thread_decision_graph_causal_order() -> None:
    # Query decision graph for demo thread
    res = client.get("/api/runs/grant-demo-thread/graph")
    assert res.status_code == 200
    data = res.json()
    assert data["thread_id"] == "grant-demo-thread"
    nodes = data["nodes"]
    edges = data["edges"]

    # Verify causal sequence: grant_issued -> action_requested -> grant_consumed -> action_completed -> grant_revoked
    kinds = [n["kind"] for n in nodes]
    assert kinds == [
        "grant_issued",
        "action_requested",
        "grant_consumed",
        "action_completed",
        "grant_revoked",
    ]
    assert len(edges) == len(nodes) - 1
    for i in range(len(edges)):
        assert edges[i]["from"] == nodes[i]["id"]
        assert edges[i]["to"] == nodes[i + 1]["id"]


def test_run_detail_renders_grant_timeline() -> None:
    res = client.get("/runs/grant-demo-thread")
    assert res.status_code == 200
    html = res.text.lower()
    # Verifies grant timeline items render
    assert "timeline events" in html
    assert "grant_issued" in html
    assert "grant_consumed" in html
    assert "grant_revoked" in html


def test_dynamic_grant_lifecycle_decision_graph_causal_order() -> None:
    from app.audit import JOURNAL_STORE

    thread = "thr_dyn_causal"
    events = [
        JournalEvent(
            id="ev_d1",
            run_id=f"run_{thread}",
            thread_id=thread,
            action_id=None,
            checkpoint_step=1,
            actor="approver:alice",
            status="Issued",
            description="Grant issued",
            payload={"grant_id": "gr_1", "max_uses": 2},
            kind=EventKind.GRANT_ISSUED.value,
            ts="2026-10-12T10:00:00Z",
        ),
        JournalEvent(
            id="ev_d2",
            run_id=f"run_{thread}",
            thread_id=thread,
            action_id="act_1",
            checkpoint_step=2,
            actor="agent",
            status="Proposed",
            description="Action 1",
            payload={},
            kind=EventKind.ACTION_REQUESTED.value,
            ts="2026-10-12T10:00:01Z",
        ),
        JournalEvent(
            id="ev_d3",
            run_id=f"run_{thread}",
            thread_id=thread,
            action_id="act_1",
            checkpoint_step=2,
            actor="GuardedExecutor",
            status="Consumed",
            description="Use 1 consumed",
            payload={"uses_left": 1},
            kind=EventKind.GRANT_CONSUMED.value,
            ts="2026-10-12T10:00:02Z",
        ),
        JournalEvent(
            id="ev_d4",
            run_id=f"run_{thread}",
            thread_id=thread,
            action_id="act_1",
            checkpoint_step=2,
            actor="GuardedExecutor",
            status="Completed",
            description="Action 1 completed",
            payload={},
            kind=EventKind.ACTION_COMPLETED.value,
            ts="2026-10-12T10:00:03Z",
        ),
        JournalEvent(
            id="ev_d5",
            run_id=f"run_{thread}",
            thread_id=thread,
            action_id="act_2",
            checkpoint_step=3,
            actor="agent",
            status="Proposed",
            description="Action 2",
            payload={},
            kind=EventKind.ACTION_REQUESTED.value,
            ts="2026-10-12T10:00:04Z",
        ),
        JournalEvent(
            id="ev_d6",
            run_id=f"run_{thread}",
            thread_id=thread,
            action_id="act_2",
            checkpoint_step=3,
            actor="GuardedExecutor",
            status="Consumed",
            description="Use 2 consumed (exhausted)",
            payload={"uses_left": 0},
            kind=EventKind.GRANT_CONSUMED.value,
            ts="2026-10-12T10:00:05Z",
        ),
        JournalEvent(
            id="ev_d7",
            run_id=f"run_{thread}",
            thread_id=thread,
            action_id="act_2",
            checkpoint_step=3,
            actor="GuardedExecutor",
            status="Completed",
            description="Action 2 completed",
            payload={},
            kind=EventKind.ACTION_COMPLETED.value,
            ts="2026-10-12T10:00:06Z",
        ),
        JournalEvent(
            id="ev_d8",
            run_id=f"run_{thread}",
            thread_id=thread,
            action_id="act_3",
            checkpoint_step=4,
            actor="agent",
            status="Proposed",
            description="Action 3",
            payload={},
            kind=EventKind.ACTION_REQUESTED.value,
            ts="2026-10-12T10:00:07Z",
        ),
        JournalEvent(
            id="ev_d9",
            run_id=f"run_{thread}",
            thread_id=thread,
            action_id="act_3",
            checkpoint_step=4,
            actor="GuardedExecutor",
            status="Pending",
            description="Gate parked after grant exhaustion",
            payload={"gate_id": "gate_1"},
            kind=EventKind.GATE_REQUESTED.value,
            ts="2026-10-12T10:00:08Z",
        ),
    ]
    for ev in events:
        JOURNAL_STORE.append(ev)

    res = client.get(f"/api/runs/{thread}/graph")
    assert res.status_code == 200
    data = res.json()
    assert data["thread_id"] == thread
    nodes = data["nodes"]
    edges = data["edges"]

    # Verify causal order of nodes
    node_kinds = [n["kind"] for n in nodes]
    assert node_kinds == [
        "grant_issued",
        "action_requested",
        "grant_consumed",
        "action_completed",
        "action_requested",
        "grant_consumed",
        "action_completed",
        "action_requested",
        "gate_requested",
    ]

    # Verify causal chain edges
    assert len(edges) == len(nodes) - 1
    for i in range(len(edges)):
        assert edges[i]["from"] == nodes[i]["id"]
        assert edges[i]["to"] == nodes[i + 1]["id"]
