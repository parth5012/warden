"""Execution Traces Management Router for Aegis.

Visualizes LangGraph execution threads, node transitions, checkpoints,
and human-in-the-loop park/interrupt states.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
templates = Jinja2Templates(directory=TEMPLATES_DIR)

router = APIRouter(tags=["Execution Traces"])

# ==============================================================================
# EXECUTION TRACES DATA STORE (LangGraph Thread Runs)
# ==============================================================================

TRACES_STORE: List[Dict[str, Any]] = [
    {
        "thread_id": "thread_code_419",
        "run_id": "run_7129e3",
        "agent": "CodeAgent",
        "agent_model": "claude-3-5-sonnet",
        "status": "PARKED_HITL",
        "status_label": "Parked at Interception Gate",
        "status_class": "thread-parked",
        "current_step": 3,
        "checkpoint_id": "chk_c419_3_e8f2",
        "has_pending_gate": True,
        "pending_gate_id": "gate_7129e3",
        "started_at": (datetime.now(timezone.utc) - timedelta(minutes=6)).isoformat(),
        "total_latency_ms": 940,
        "total_tokens": 4820,
        "input_prompt": "Clean up obsolete cache directories and temporary test artifacts in /workspace/tmp",
        "nodes": [
            {"step": 1, "node": "draft_action", "kind": "action_requested", "status": "allowed", "duration_ms": 280, "note": "Generated 5 file deletion targets"},
            {"step": 2, "node": "guard_seam", "kind": "policy_evaluated", "status": "escalate", "duration_ms": 45, "note": "Triggered L1 Rule SEC-FS-04 (>3 file deletes)"},
            {"step": 3, "node": "park_interrupt", "kind": "gate_requested", "status": "pending", "duration_ms": 15, "note": "Thread parked in Postgres Saver awaiting operator verdict"},
        ],
        "state_snapshot": {
            "pending_action_id": "act_7129e3",
            "operation": "FILE_BATCH_DELETE",
            "target_resource": "/workspace/tmp/",
            "files_count": 5,
            "diff_summary": "-5 files (-48.3 MB)",
            "checkpoint_seq": 3,
            "thread_owner": "CodeAgent",
        },
    },
    {
        "thread_id": "thread_db_104",
        "run_id": "run_8812c4",
        "agent": "DBAgent",
        "agent_model": "gpt-4o",
        "status": "COMPLETED",
        "status_label": "Execution Completed",
        "status_class": "thread-completed",
        "current_step": 4,
        "checkpoint_id": "chk_d104_4_a19b",
        "has_pending_gate": False,
        "pending_gate_id": None,
        "started_at": (datetime.now(timezone.utc) - timedelta(minutes=24)).isoformat(),
        "total_latency_ms": 1380,
        "total_tokens": 6120,
        "input_prompt": "Verify customer billing index partition across PostgreSQL cluster",
        "nodes": [
            {"step": 1, "node": "generate_sql", "kind": "action_requested", "status": "allowed", "duration_ms": 410, "note": "Generated EXPLAIN ANALYZE index query"},
            {"step": 2, "node": "guard_seam", "kind": "policy_evaluated", "status": "allowed", "duration_ms": 32, "note": "L1 SQL AST parsed: Read-only query allowed"},
            {"step": 3, "node": "sandbox_exec", "kind": "action_completed", "status": "allowed", "duration_ms": 890, "note": "Query executed in isolated replica"},
            {"step": 4, "node": "commit_checkpoint", "kind": "checkpoint_created", "status": "allowed", "duration_ms": 48, "note": "Final state committed"},
        ],
        "state_snapshot": {
            "query_type": "SELECT",
            "rows_inspected": 14200,
            "cost": 18.42,
            "checkpoint_seq": 4,
            "thread_owner": "DBAgent",
        },
    },
    {
        "thread_id": "thread_sec_991",
        "run_id": "run_9918a2",
        "agent": "CodeAgent",
        "agent_model": "claude-3-5-sonnet",
        "status": "FAILED",
        "status_label": "Denied by Policy (Terminal)",
        "status_class": "thread-failed",
        "current_step": 2,
        "checkpoint_id": "chk_s991_2_bb02",
        "has_pending_gate": False,
        "pending_gate_id": None,
        "started_at": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
        "total_latency_ms": 310,
        "total_tokens": 1250,
        "input_prompt": "Inspect system password hashes in /etc/shadow for debugging",
        "nodes": [
            {"step": 1, "node": "draft_action", "kind": "action_requested", "status": "allowed", "duration_ms": 260, "note": "Tool proposed read_file('/etc/shadow')"},
            {"step": 2, "node": "guard_seam", "kind": "action_denied", "status": "denied", "duration_ms": 50, "note": "Terminal Deny SEC-HOST-00 (Lock 5 Invariant)"},
        ],
        "state_snapshot": {
            "target_resource": "/etc/shadow",
            "verdict": "DENIED",
            "reason": "Mutation or read of host security configuration forbidden",
            "terminal_lock": 5,
        },
    },
    {
        "thread_id": "thread_ops_702",
        "run_id": "run_7021e1",
        "agent": "OpsAssistant",
        "agent_model": "gpt-4o-mini",
        "status": "RUNNING",
        "status_label": "Executing in Sandbox",
        "status_class": "thread-running",
        "current_step": 2,
        "checkpoint_id": "chk_o702_2_77ef",
        "has_pending_gate": False,
        "pending_gate_id": None,
        "started_at": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
        "total_latency_ms": 540,
        "total_tokens": 2100,
        "input_prompt": "Collect disk usage telemetry from staging worker nodes",
        "nodes": [
            {"step": 1, "node": "dispatch_agent", "kind": "action_requested", "status": "allowed", "duration_ms": 320, "note": "Proposed df -h inspection"},
            {"step": 2, "node": "sandbox_exec", "kind": "action_started", "status": "running", "duration_ms": 220, "note": "Subprocess active in cgroups v2 sandbox"},
        ],
        "state_snapshot": {
            "command": "df -h",
            "isolation": "subprocess_cgroups",
            "thread_owner": "OpsAssistant",
        },
    },
]


@router.get("/traces", response_class=HTMLResponse)
async def get_traces_page(
    request: Request,
    status: Optional[str] = Query("all", description="Filter: all, PARKED_HITL, RUNNING, COMPLETED, FAILED"),
    agent: Optional[str] = Query("all", description="Agent filter: all, CodeAgent, DBAgent, OpsAssistant"),
    q: Optional[str] = Query(None, description="Search query"),
):
    """Render Execution Traces console."""
    filtered = list(TRACES_STORE)

    if status and status.lower() != "all":
        filtered = [t for t in filtered if t["status"].lower() == status.lower()]

    if agent and agent.lower() != "all":
        filtered = [t for t in filtered if t["agent"].lower() == agent.lower()]

    if q:
        query = q.strip().lower()
        filtered = [
            t for t in filtered
            if query in t["thread_id"].lower()
            or query in t["run_id"].lower()
            or query in t["agent"].lower()
            or query in t["input_prompt"].lower()
            or query in t["checkpoint_id"].lower()
        ]

    metrics = {
        "total_threads": len(TRACES_STORE),
        "parked_count": sum(t["status"] == "PARKED_HITL" for t in TRACES_STORE),
        "running_count": sum(t["status"] == "RUNNING" for t in TRACES_STORE),
        "completed_count": sum(t["status"] == "COMPLETED" for t in TRACES_STORE),
        "failed_count": sum(t["status"] == "FAILED" for t in TRACES_STORE),
        "avg_latency": int(sum(t["total_latency_ms"] for t in TRACES_STORE) / max(1, len(TRACES_STORE))),
    }

    context = {
        "request": request,
        "active_page": "traces",
        "traces": filtered,
        "metrics": metrics,
        "selected_status": status or "all",
        "selected_agent": agent or "all",
        "q": q or "",
        "demo_mode": True,
    }

    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(
            request=request,
            name="components/traces_table_fragment.html",
            context=context,
        )

    return templates.TemplateResponse(
        request=request,
        name="traces.html",
        context=context,
    )


@router.get("/traces/{thread_id}", response_class=HTMLResponse)
async def get_trace_detail(request: Request, thread_id: str):
    """Return step-by-step trace detail fragment for modal or drawer inspection."""
    trace = next((t for t in TRACES_STORE if t["thread_id"] == thread_id), None)
    if not trace:
        raise HTTPException(status_code=404, detail="Trace thread not found")

    return templates.TemplateResponse(
        request=request,
        name="components/trace_detail_fragment.html",
        context={"request": request, "trace": trace},
    )
