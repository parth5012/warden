"""Frontend view routes rendering server-side HTML via Jinja2 & HTMX."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from langchain_core.runnables import RunnableConfig

from warden.config import settings
from warden.checkpoint import CheckpointManager

_FRONTEND_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(_FRONTEND_DIR / "templates"))

router = APIRouter(tags=["Frontend Views"])


@router.get("/", response_class=HTMLResponse)
async def dashboard_view(request: Request) -> HTMLResponse:
    """Render operator dashboard overview."""
    stats = {
        "pending_gates": 0,
        "total_actions": 12,
        "total_tokens": 1420,
        "estimated_cost": 0.0028,
    }
    recent_runs: list[dict[str, Any]] = [
        {
            "thread_id": "demo-thread-1",
            "next_node": "approval",
            "is_parked": True,
            "approved": None,
        },
        {
            "thread_id": "test-run-thread-live",
            "next_node": "send",
            "is_parked": False,
            "approved": True,
        },
    ]
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "active_tab": "dashboard",
            "stats": stats,
            "recent_runs": recent_runs,
            "pending_count": stats["pending_gates"],
        },
    )


@router.get("/inbox", response_class=HTMLResponse)
async def inbox_view(request: Request) -> HTMLResponse:
    """Render operator approvals inbox."""
    pending_gates: list[dict[str, Any]] = [
        {
            "id": "gate-req-001",
            "thread_id": "demo-thread-1",
            "action_name": "send_email",
            "ask": "Approve sending weekly report email to external team?",
            "payload": {
                "action": "send_email",
                "recipient": "team@example.com",
                "body": "Weekly ops report ready",
            },
            "created_at": "Just now",
        }
    ]
    return templates.TemplateResponse(
        request,
        "inbox.html",
        {
            "active_tab": "inbox",
            "pending_gates": pending_gates,
            "pending_count": len(pending_gates),
        },
    )


@router.get("/runs", response_class=HTMLResponse)
async def runs_view(request: Request, thread_id: str | None = None) -> HTMLResponse:
    """Render runs list."""
    runs: list[dict[str, Any]] = [
        {
            "thread_id": "demo-thread-1",
            "step": 1,
            "is_parked": True,
            "summary": "Parked at approval node for email verification",
        },
        {
            "thread_id": "test-run-thread-live",
            "step": 2,
            "is_parked": False,
            "summary": "Completed email dispatch via Groq draft",
        },
    ]
    if thread_id:
        runs = [r for r in runs if thread_id.lower() in r["thread_id"].lower()]

    return templates.TemplateResponse(
        request,
        "runs.html",
        {
            "active_tab": "runs",
            "runs": runs,
            "filter_thread_id": thread_id or "",
            "pending_count": 1,
        },
    )


@router.get("/runs/{thread_id}", response_class=HTMLResponse)
async def run_detail_view(request: Request, thread_id: str) -> HTMLResponse:
    """Render single run inspection with checkpoint state and step timeline."""
    state_info: dict[str, Any] = {
        "step": 1,
        "next_node": "approval",
        "is_parked": True,
        "values": {
            "messages": [
                "Drafted email via Groq: 'Subject: Daily Metrics' for team@example.com"
            ],
            "approved": False,
        },
    }
    history: list[dict[str, Any]] = [
        {
            "step": 1,
            "next_node": "approval",
            "thread_id": thread_id,
            "checkpoint_id": "chk-001",
            "created_at": "2026-10-11T14:00:00Z",
        }
    ]

    # If live PostgreSQL is connected, attempt to fetch live state info
    if settings.postgres_uri:
        try:
            async with CheckpointManager.create(settings.postgres_uri) as mgr:
                from warden.demo_graph import build_demo_graph

                graph = build_demo_graph(mgr.checkpointer)
                config: RunnableConfig = {"configurable": {"thread_id": thread_id}}
                state = await graph.aget_state(config)
                if state and hasattr(state, "values") and state.values:
                    next_nodes = list(state.next) if hasattr(state, "next") else []
                    state_info = {
                        "step": state.metadata.get("step", 1)
                        if isinstance(state.metadata, dict)
                        else 1,
                        "next_node": next_nodes[0] if next_nodes else "END",
                        "is_parked": bool(
                            state.tasks and any(t.interrupts for t in state.tasks)
                        ),
                        "values": dict(state.values),
                    }
        except Exception:
            pass

    return templates.TemplateResponse(
        request,
        "run_detail.html",
        {
            "active_tab": "runs",
            "thread_id": thread_id,
            "state_info": state_info,
            "history": history,
            "pending_count": 1 if state_info.get("is_parked") else 0,
        },
    )


@router.get("/audit", response_class=HTMLResponse)
async def audit_view(request: Request, q: str | None = None) -> HTMLResponse:
    """Render searchable audit explorer."""
    events: list[dict[str, Any]] = [
        {
            "ts": "2026-10-11T14:05:00Z",
            "kind": "action_allowed",
            "actor": "ops_assistant",
            "thread_id": "test-run-thread-live",
            "payload": "{action: send_email, status: sent}",
        },
        {
            "ts": "2026-10-11T14:01:00Z",
            "kind": "gate_requested",
            "actor": "ops_assistant",
            "thread_id": "demo-thread-1",
            "payload": "{policy: escalate_external_email, gate: gate-req-001}",
        },
        {
            "ts": "2026-10-11T13:50:00Z",
            "kind": "action_denied",
            "actor": "ops_assistant",
            "thread_id": "security-test-1",
            "payload": "{action: drop_table, policy: no_destructive_sql}",
        },
    ]
    if q:
        events = [
            e
            for e in events
            if q.lower() in str(e["payload"]).lower()
            or q.lower() in e["kind"].lower()
            or q.lower() in e["thread_id"].lower()
        ]

    return templates.TemplateResponse(
        request,
        "audit.html",
        {
            "active_tab": "audit",
            "events": events,
            "query": q or "",
            "pending_count": 1,
        },
    )


@router.get("/policies", response_class=HTMLResponse)
async def policies_view(request: Request) -> HTMLResponse:
    """Render active policy rules list."""
    policies: list[dict[str, Any]] = [
        {
            "name": "no_destructive_sql",
            "action": "deny",
            "version": 1,
            "description": "Terminal block on DROP TABLE, TRUNCATE, and DELETE without WHERE clauses.",
        },
        {
            "name": "escalate_external_email",
            "action": "escalate",
            "version": 1,
            "description": "Requires human operator approval before sending emails to external recipients.",
        },
        {
            "name": "sandbox_shell_commands",
            "action": "allow",
            "version": 1,
            "description": "Enforce subprocess sandbox with strict timeout and scrubbed environment.",
        },
    ]
    return templates.TemplateResponse(
        request,
        "policies.html",
        {
            "active_tab": "policies",
            "policies": policies,
            "pending_count": 1,
        },
    )
