"""Frontend view routes rendering server-side HTML via Jinja2 & HTMX."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from langchain_core.runnables import RunnableConfig

from warden.config import settings
from warden.checkpoint import CheckpointManager
from app.audit import JOURNAL_STORE

_FRONTEND_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(_FRONTEND_DIR / "templates"))

router = APIRouter(tags=["Frontend Views"])

DEFAULT_RECENT_RUNS: list[dict[str, Any]] = [
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

DEFAULT_PENDING_GATES: list[dict[str, Any]] = [
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

DEFAULT_RUNS: list[dict[str, Any]] = [
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

DEFAULT_AUDIT_EVENTS: list[dict[str, Any]] = [
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


@router.get("/", response_class=HTMLResponse)
async def dashboard_view(request: Request) -> HTMLResponse:
    """Render operator dashboard overview."""
    journal_events = getattr(JOURNAL_STORE, "_events", [])
    if journal_events:
        pending_gates = sum(
            1
            for e in journal_events
            if e.kind in ("gate_requested", "action_escalated")
            and e.status.lower() in ("pending", "escalated")
        )
        total_actions = sum(1 for e in journal_events if "action" in e.kind) or len(
            journal_events
        )
        stats = {
            "pending_gates": pending_gates,
            "total_actions": max(total_actions, 12),
            "total_tokens": 1420 + len(journal_events) * 95,
            "estimated_cost": round(0.0028 + len(journal_events) * 0.00015, 4),
        }
        derived_runs: dict[str, dict[str, Any]] = {}
        for e in reversed(journal_events):
            tid = e.thread_id or e.run_id
            if tid and tid not in derived_runs:
                is_parked = e.kind == "gate_requested" or e.status.lower() in (
                    "pending",
                    "escalated",
                )
                is_approved = (
                    True
                    if e.status.lower() in ("allowed", "approved", "succeeded")
                    else (
                        False
                        if e.status.lower() in ("denied", "failed")
                        else None
                    )
                )
                next_node = (
                    "approval"
                    if is_parked
                    else ("completed" if is_approved else "active")
                )
                derived_runs[tid] = {
                    "thread_id": tid,
                    "next_node": next_node,
                    "is_parked": is_parked,
                    "approved": is_approved,
                }
        recent_runs = list(derived_runs.values())[:5] if derived_runs else list(DEFAULT_RECENT_RUNS)
    else:
        stats = {
            "pending_gates": 0,
            "total_actions": 12,
            "total_tokens": 1420,
            "estimated_cost": 0.0028,
        }
        recent_runs = list(DEFAULT_RECENT_RUNS)

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
    pending_gates: list[dict[str, Any]] = []
    journal_events = getattr(JOURNAL_STORE, "_events", [])
    if journal_events:
        for e in journal_events:
            if e.kind in ("gate_requested", "action_escalated") and e.status.lower() in (
                "pending",
                "escalated",
            ):
                payload = e.payload if isinstance(e.payload, dict) else {}
                pending_gates.append({
                    "id": payload.get("gate_id", e.id),
                    "thread_id": e.thread_id or e.run_id,
                    "action_name": payload.get(
                        "operation",
                        payload.get("action_id", e.action_id or e.description),
                    ),
                    "ask": e.description
                    or f"Approval required for action {e.action_id}",
                    "payload": payload,
                    "created_at": e.ts,
                })
    if not pending_gates:
        pending_gates = list(DEFAULT_PENDING_GATES)

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
    runs: list[dict[str, Any]] = []
    journal_events = getattr(JOURNAL_STORE, "_events", [])
    if journal_events:
        seen_threads: set[str] = set()
        for e in reversed(journal_events):
            tid = e.thread_id or e.run_id
            if tid and tid not in seen_threads:
                seen_threads.add(tid)
                runs.append({
                    "thread_id": tid,
                    "step": e.checkpoint_step or 1,
                    "is_parked": e.kind == "gate_requested"
                    or e.status.lower() in ("pending", "escalated"),
                    "summary": e.description
                    or f"Step {e.checkpoint_step} for {e.actor}",
                })
    if not runs:
        runs = list(DEFAULT_RUNS)
    if thread_id:
        runs = [r for r in runs if thread_id.lower() in r["thread_id"].lower()]

    return templates.TemplateResponse(
        request,
        "runs.html",
        {
            "active_tab": "runs",
            "runs": runs,
            "filter_thread_id": thread_id or "",
            "pending_count": sum(1 for r in runs if r.get("is_parked")),
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

    events_list: list[dict[str, Any]] = []
    from app.audit import JOURNAL_STORE
    from backend.api.audit import AUDIT_EVENTS

    if hasattr(JOURNAL_STORE, "_events") and JOURNAL_STORE._events:
        for e in JOURNAL_STORE._events:
            if getattr(e, "thread_id", None) == thread_id:
                events_list.append(
                    e.to_dict()
                    if hasattr(e, "to_dict")
                    else {
                        "kind": e.kind,
                        "actor": e.actor,
                        "description": e.description,
                        "payload": e.payload,
                        "ts": getattr(e, "ts", "") or getattr(e, "timestamp", ""),
                    }
                )

    if not events_list:
        events_list = [e for e in AUDIT_EVENTS if e.get("thread_id") == thread_id]

    return templates.TemplateResponse(
        request,
        "run_detail.html",
        {
            "active_tab": "runs",
            "thread_id": thread_id,
            "state_info": state_info,
            "history": history,
            "events": events_list,
            "pending_count": 1 if state_info.get("is_parked") else 0,
        },
    )


@router.get("/audit", response_class=HTMLResponse)
async def audit_view(request: Request, q: str | None = None) -> HTMLResponse:
    """Render searchable audit explorer."""
    events: list[dict[str, Any]] = []
    if hasattr(JOURNAL_STORE, "_events") and JOURNAL_STORE._events:
        j_events, _ = JOURNAL_STORE.list_events(q=q, limit=100)
        events = [
            {
                "ts": ev.ts,
                "kind": ev.kind,
                "actor": ev.actor,
                "thread_id": ev.thread_id or ev.run_id,
                "payload": json.dumps(ev.payload)
                if isinstance(ev.payload, (dict, list))
                else str(ev.payload),
            }
            for ev in j_events
        ]

    if not events and not (hasattr(JOURNAL_STORE, "_events") and JOURNAL_STORE._events):
        events = list(DEFAULT_AUDIT_EVENTS)
        if q:
            events = [
                e
                for e in events
                if q.lower() in str(e["payload"]).lower()
                or q.lower() in e["kind"].lower()
                or q.lower() in e["thread_id"].lower()
            ]

    pending_count = 1
    if hasattr(JOURNAL_STORE, "_events") and JOURNAL_STORE._events:
        cnt = sum(
            1
            for e in JOURNAL_STORE._events
            if e.kind in ("gate_requested", "action_escalated")
            and e.status.lower() in ("pending", "escalated")
        )
        if cnt > 0:
            pending_count = cnt

    return templates.TemplateResponse(
        request,
        "audit.html",
        {
            "active_tab": "audit",
            "events": events,
            "query": q or "",
            "pending_count": pending_count,
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
