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

from backend.api import get_audit_journal

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


def _llm_usage_traces(events: list[Any]) -> list[Dict[str, Any]]:
    """Project redacted LLM usage journal events into per-run trace records."""
    grouped: dict[tuple[str, str], Dict[str, Any]] = {}
    for event in events:
        event_kind = event.get("kind") if isinstance(event, dict) else getattr(event, "kind", None)
        if event_kind != "llm_usage":
            continue
        payload = event.get("payload", {}) if isinstance(event, dict) else getattr(event, "payload", {})
        if not isinstance(payload, dict):
            continue
        run_id = str(payload.get("run_id") or (event.get("run_id") if isinstance(event, dict) else getattr(event, "run_id", "")) or "")
        thread_id = str(payload.get("thread_id") or (event.get("thread_id") if isinstance(event, dict) else getattr(event, "thread_id", "")) or "")
        if not run_id or not thread_id:
            continue

        key = (run_id, thread_id)
        timestamp = payload.get("timestamp") or (event.get("ts") if isinstance(event, dict) else getattr(event, "ts", None))
        if isinstance(timestamp, datetime):
            timestamp = timestamp.isoformat()
        trace = grouped.get(key)
        if trace is None:
            model = str(payload.get("model") or "unknown")
            trace = {
                "thread_id": thread_id,
                "run_id": run_id,
                "agent": str(payload.get("actor") or "Agent"),
                "agent_model": f"{payload.get('provider') or 'unknown'}/{model}",
                "status": "COMPLETED",
                "status_label": "Guarded LLM execution completed",
                "status_class": "thread-completed",
                "current_step": 0,
                "checkpoint_id": f"llm-{thread_id}",
                "has_pending_gate": False,
                "pending_gate_id": None,
                "started_at": str(timestamp or ""),
                "total_latency_ms": 0,
                "total_tokens": 0,
                "input_tokens": 0,
                "output_tokens": 0,
                "total_cost_usd": 0.0,
                "input_prompt": "Prompt body omitted from traces; token and cost metadata only.",
                "nodes": [],
                "state_snapshot": {"llm_usage_records": 0},
            }
            grouped[key] = trace

        outcome = str(payload.get("outcome_kind") or "unknown").lower()
        prompt_tokens = int(payload.get("prompt_tokens") or 0)
        completion_tokens = int(payload.get("completion_tokens") or 0)
        calculated_cost = payload.get("calculated_cost_usd")
        is_preflight_estimate = calculated_cost is None
        if calculated_cost is None:
            calculated_cost = payload.get("estimated_cost_usd")
        cost = float(calculated_cost or 0.0)
        latency_ms = int(payload.get("latency_ms") or 0)
        trace["current_step"] += 1
        trace["total_latency_ms"] += latency_ms
        trace["total_tokens"] += int(payload.get("total_tokens") or prompt_tokens + completion_tokens)
        trace["input_tokens"] += prompt_tokens
        trace["output_tokens"] += completion_tokens
        trace["total_cost_usd"] += cost
        trace["state_snapshot"]["llm_usage_records"] = trace["current_step"]
        trace["nodes"].append({
            "step": trace["current_step"],
            "node": "guarded_llm_call",
            "kind": "llm_usage",
            "status": "failed" if outcome == "error" else "completed",
            "duration_ms": latency_ms,
            "note": (
                f"{payload.get('provider') or 'unknown'}/{payload.get('model') or 'unknown'} · "
                f"{prompt_tokens} input + {completion_tokens} output tokens · "
                f"${cost:.6f} {'preflight estimate' if is_preflight_estimate else 'usage-based calculation'} · {outcome}"
            ),
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": int(payload.get("total_tokens") or prompt_tokens + completion_tokens),
            "cost_usd": cost,
        })
        if outcome == "error":
            trace.update(
                status="FAILED",
                status_label="Guarded LLM execution failed",
                status_class="thread-failed",
            )
    return sorted(grouped.values(), key=lambda item: item["started_at"], reverse=True)


@router.get("/traces", response_class=HTMLResponse)
async def get_traces_page(
    request: Request,
    status: Optional[str] = Query("all", description="Filter: all, PARKED_HITL, RUNNING, COMPLETED, FAILED"),
    agent: Optional[str] = Query("all", description="Agent filter: all, CodeAgent, DBAgent, OpsAssistant"),
    q: Optional[str] = Query(None, description="Search query"),
):
    """Render Execution Traces console."""
    journal_events = await get_audit_journal().query()
    traces = _llm_usage_traces(journal_events) + list(TRACES_STORE)
    filtered = list(traces)

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
        "total_threads": len(traces),
        "parked_count": sum(t["status"] == "PARKED_HITL" for t in traces),
        "running_count": sum(t["status"] == "RUNNING" for t in traces),
        "completed_count": sum(t["status"] == "COMPLETED" for t in traces),
        "failed_count": sum(t["status"] == "FAILED" for t in traces),
        "avg_latency": int(sum(t["total_latency_ms"] for t in traces) / max(1, len(traces))),
    }

    context = {
        "request": request,
        "active_page": "traces",
        "traces": filtered,
        "metrics": metrics,
        "selected_status": status or "all",
        "selected_agent": agent or "all",
        "q": q or "",
        "demo_mode": not bool(_llm_usage_traces(journal_events)),
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
    events = await get_audit_journal().query()
    trace = next(
        (item for item in _llm_usage_traces(events) if item["thread_id"] == thread_id),
        None,
    )
    if trace is None:
        trace = next((item for item in TRACES_STORE if item["thread_id"] == thread_id), None)
    if not trace:
        raise HTTPException(status_code=404, detail="Trace thread not found")

    return templates.TemplateResponse(
        request=request,
        name="components/trace_detail_fragment.html",
        context={"request": request, "trace": trace},
    )
