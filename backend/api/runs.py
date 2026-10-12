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
