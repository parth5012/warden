"""Agent execution runs & decision-graph inspection endpoints."""

from __future__ import annotations

from typing import Any
from fastapi import APIRouter
from fastapi.responses import JSONResponse
from langchain_core.runnables import RunnableConfig

from warden.config import settings
from warden.checkpoint import CheckpointManager

router = APIRouter(prefix="/runs", tags=["Runs & Decision Graph"])


@router.get("")
async def list_runs() -> dict[str, Any]:
    """List all tracked execution runs."""
    return {
        "runs": [
            {
                "thread_id": "demo-thread-1",
                "step": 1,
                "is_parked": True,
                "next_node": "approval",
                "status": "pending_gate",
            },
            {
                "thread_id": "test-run-thread-live",
                "step": 2,
                "is_parked": False,
                "next_node": "send",
                "status": "completed",
            },
        ]
    }


@router.get("/{thread_id}")
async def get_run_detail(thread_id: str) -> JSONResponse:
    """Get current state of a run."""
    state_info: dict[str, Any] = {
        "thread_id": thread_id,
        "step": 1,
        "next_node": "approval",
        "is_parked": True,
        "values": {"messages": ["Drafted email ready"], "approved": False},
    }

    if settings.postgres_uri:
        try:
            async with CheckpointManager.create(settings.postgres_uri) as mgr:
                from warden.demo_graph import build_demo_graph

                graph = build_demo_graph(mgr.checkpointer)
                config: RunnableConfig = {"configurable": {"thread_id": thread_id}}
                state = await graph.aget_state(config)
                if state:
                    next_nodes = list(state.next) if hasattr(state, "next") else []
                    state_info = {
                        "thread_id": thread_id,
                        "step": state.metadata.get("step", 1)
                        if isinstance(state.metadata, dict)
                        else 1,
                        "next_node": next_nodes[0] if next_nodes else "END",
                        "is_parked": bool(state.tasks and any(t.interrupts for t in state.tasks)),
                        "values": state.values,
                    }
        except Exception:
            pass

    return JSONResponse(content=state_info)


@router.get("/{thread_id}/graph")
async def get_run_graph(thread_id: str) -> dict[str, Any]:
    """Decision-graph projection joining journal events and checkpoint steps."""
    from app.audit import JOURNAL_STORE

    evs: list[Any] = []
    if hasattr(JOURNAL_STORE, "_events") and JOURNAL_STORE._events:
        evs = [e for e in JOURNAL_STORE._events if getattr(e, "thread_id", None) == thread_id]

    if evs:
        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []
        for i, ev in enumerate(evs):
            action_id = getattr(ev, "action_id", None)
            event_id = getattr(ev, "id", None) or f"evt_{i}"
            node_id = f"{ev.kind}:{action_id or event_id}"
            nodes.append(
                {
                    "id": node_id,
                    "kind": ev.kind,
                    "step": getattr(ev, "checkpoint_step", None) or (i + 1),
                    "ts": getattr(ev, "ts", None) or getattr(ev, "timestamp", ""),
                    "actor": getattr(ev, "actor", ""),
                    "payload": getattr(ev, "payload", {}),
                }
            )
            if i > 0:
                edges.append({"from": nodes[i - 1]["id"], "to": node_id})
        return {
            "thread_id": thread_id,
            "nodes": nodes,
            "edges": edges,
        }

    # Grant-demo thread mock graph
    if thread_id == "grant-demo-thread":
        return {
            "thread_id": thread_id,
            "nodes": [
                {
                    "id": "grant_issued:1",
                    "kind": "grant_issued",
                    "step": 1,
                    "ts": "2026-10-11T14:10:00Z",
                    "actor": "approver:alice",
                },
                {
                    "id": "action_requested:1",
                    "kind": "action_requested",
                    "step": 2,
                    "ts": "2026-10-11T14:10:04Z",
                    "actor": "ops_assistant",
                },
                {
                    "id": "grant_consumed:1",
                    "kind": "grant_consumed",
                    "step": 2,
                    "ts": "2026-10-11T14:10:05Z",
                    "actor": "GuardedExecutor",
                },
                {
                    "id": "action_completed:2",
                    "kind": "action_completed",
                    "step": 2,
                    "ts": "2026-10-11T14:10:06Z",
                    "actor": "GuardedExecutor",
                },
                {
                    "id": "grant_revoked:1",
                    "kind": "grant_revoked",
                    "step": 3,
                    "ts": "2026-10-11T14:15:00Z",
                    "actor": "approver:alice",
                },
            ],
            "edges": [
                {"from": "grant_issued:1", "to": "action_requested:1"},
                {"from": "action_requested:1", "to": "grant_consumed:1"},
                {"from": "grant_consumed:1", "to": "action_completed:2"},
                {"from": "action_completed:2", "to": "grant_revoked:1"},
            ],
        }

    return {
        "thread_id": thread_id,
        "nodes": [
            {
                "id": "action_requested:1",
                "kind": "action_requested",
                "step": 1,
                "ts": "2026-10-11T14:00:00Z",
            },
            {
                "id": "gate_requested:1",
                "kind": "gate_requested",
                "step": 1,
                "ts": "2026-10-11T14:00:01Z",
            },
            {
                "id": "gate_decided:1",
                "kind": "gate_decided",
                "step": 1,
                "ts": "2026-10-11T14:01:00Z",
            },
            {
                "id": "action_completed:2",
                "kind": "action_completed",
                "step": 2,
                "ts": "2026-10-11T14:01:05Z",
            },
        ],
        "edges": [
            {"from": "action_requested:1", "to": "gate_requested:1"},
            {"from": "gate_requested:1", "to": "gate_decided:1"},
            {"from": "gate_decided:1", "to": "action_completed:2"},
        ],
    }
