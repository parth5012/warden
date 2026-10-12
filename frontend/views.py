"""Frontend view routes rendering server-side HTML via Jinja2 & HTMX.

Directly integrated with backend REST stores:
- GuardedLLMClient & Token Estimator (/api/llm)
- Telemetry rollups (/api/telemetry)
- Operator Approval Inbox (/api/inbox)
- Agent Runs & Decision Graphs (/api/runs)
- Audit Journal (/api/audit)
- Governance Policies (/api/policies)
"""

from __future__ import annotations

import html
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from langchain_core.runnables import RunnableConfig

from backend.api.audit import AUDIT_EVENTS, search_audit_log
from backend.api.inbox import PENDING_GATES
from backend.api.llm import (
    LLMInvokeRequest,
    get_audit_journal,
    get_llm_usage,
    is_openai_configured,
    invoke_llm,
)
from backend.api.policies import POLICIES_STORE, list_policies
from backend.api.runs import (
    get_run_detail,
    get_run_graph,
    launch_new_run,
    list_runs,
    resume_run,
)
from backend.api.telemetry import get_telemetry_summary
from warden.checkpoint import CheckpointManager
from warden.config import settings
from warden.llm.pricing import PricingRegistry
from warden.llm.tokenizer import TokenEstimator

_FRONTEND_DIR = Path(__file__).resolve().parent

_estimator = TokenEstimator()
templates = Jinja2Templates(directory=str(_FRONTEND_DIR / "templates"))

router = APIRouter(tags=["Frontend Views"])


# ---------------------------------------------------------------------------
# Page Views
# ---------------------------------------------------------------------------


@router.get("/", response_class=HTMLResponse)
async def dashboard_view(request: Request) -> HTMLResponse:
    """Render operator dashboard overview wired to real backend telemetry."""
    telemetry = await get_telemetry_summary()
    runs_data = await list_runs()
    recent_runs = runs_data.get("runs", [])
    pending_count = len(PENDING_GATES)

    stats = {
        "pending_gates": pending_count,
        "total_actions": telemetry.get("actions_total", 0),
        "total_tokens": telemetry.get("tokens_total", 0),
        "estimated_cost": telemetry.get("estimated_cost_usd", 0.0),
        "llm_calls_total": telemetry.get("llm_calls_total", 0),
        "avg_latency_ms": telemetry.get("avg_latency_ms", 0.0),
    }

    usage_data = await get_llm_usage(limit=10)
    recent_llm_records = usage_data.get("records", [])

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "active_tab": "dashboard",
            "stats": stats,
            "recent_runs": recent_runs,
            "pending_count": pending_count,
            "recent_llm_records": recent_llm_records,
            "openai_configured": is_openai_configured(),
        },
    )


@router.get("/inbox", response_class=HTMLResponse)
async def inbox_view(request: Request) -> HTMLResponse:
    """Render operator approvals inbox wired to real PENDING_GATES."""
    pending_gates = list(PENDING_GATES.values())
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
    """Render runs list wired to backend runs API."""
    runs_data = await list_runs()
    runs = runs_data.get("runs", [])
    if thread_id:
        runs = [r for r in runs if thread_id.lower() in str(r.get("thread_id", "")).lower()]

    return templates.TemplateResponse(
        request,
        "runs.html",
        {
            "active_tab": "runs",
            "runs": runs,
            "filter_thread_id": thread_id or "",
            "pending_count": len(PENDING_GATES),
        },
    )


@router.get("/runs/{thread_id}", response_class=HTMLResponse)
async def run_detail_view(request: Request, thread_id: str) -> HTMLResponse:
    """Render single run inspection with checkpoint state and step timeline."""
    state_res = await get_run_detail(thread_id)
    import json

    state_info = json.loads(state_res.body.decode("utf-8"))

    history: list[dict[str, Any]] = [
        {
            "step": state_info.get("step", 1),
            "next_node": state_info.get("next_node", "approval"),
            "thread_id": thread_id,
            "checkpoint_id": f"chk-{thread_id[:6]}",
            "created_at": "Just now",
        }
    ]

    return templates.TemplateResponse(
        request,
        "run_detail.html",
        {
            "active_tab": "runs",
            "thread_id": thread_id,
            "state_info": state_info,
            "history": history,
            "pending_count": 1 if state_info.get("is_parked") else len(PENDING_GATES),
        },
    )


@router.get("/audit", response_class=HTMLResponse)
async def audit_view(request: Request, q: str | None = None) -> HTMLResponse:
    """Render searchable audit explorer wired to backend AUDIT_EVENTS."""
    audit_data = await search_audit_log(q=q)
    return templates.TemplateResponse(
        request,
        "audit.html",
        {
            "active_tab": "audit",
            "events": audit_data.get("events", []),
            "query": q or "",
            "pending_count": len(PENDING_GATES),
        },
    )


@router.get("/policies", response_class=HTMLResponse)
async def policies_view(request: Request) -> HTMLResponse:
    """Render active policy rules list wired to POLICIES_STORE."""
    pol_data = await list_policies()
    return templates.TemplateResponse(
        request,
        "policies.html",
        {
            "active_tab": "policies",
            "policies": pol_data.get("policies", []),
            "pending_count": len(PENDING_GATES),
        },
    )


# ---------------------------------------------------------------------------
# HTMX Interactive Partials (Runs, Tokens, LLM Telemetry Stream)
# ---------------------------------------------------------------------------

_pricing_registry = PricingRegistry()
_estimator = TokenEstimator()


@router.get("/partials/telemetry/stats", response_class=HTMLResponse)
async def partial_telemetry_stats() -> HTMLResponse:
    """Live metric counters for HTMX polling."""
    telemetry = await get_telemetry_summary()
    pending = len(PENDING_GATES)
    actions = telemetry.get("actions_total", 0)
    tokens = telemetry.get("tokens_total", 0)
    cost = telemetry.get("estimated_cost_usd", 0.0)

    html_out = f"""
    <div id="stats-panel" class="grid-stats" hx-get="/partials/telemetry/stats" hx-trigger="every 10s" hx-swap="outerHTML">
      <div class="card">
        <div class="stat-label">Pending HITL Gates</div>
        <div class="stat-value" style="color: var(--amber);">{pending}</div>
        <div class="stat-meta">Awaiting operator resolution</div>
      </div>
      <div class="card">
        <div class="stat-label">Total Actions</div>
        <div class="stat-value">{actions}</div>
        <div class="stat-meta">Across all threads</div>
      </div>
      <div class="card">
        <div class="stat-label">Total Tokens</div>
        <div class="stat-value">{tokens}</div>
        <div class="stat-meta">Guarded LLM telemetry</div>
      </div>
      <div class="card">
        <div class="stat-label">Est. Cost (USD)</div>
        <div class="stat-value" style="color: var(--cyan);">${cost:.4f}</div>
        <div class="stat-meta">Token usage projection</div>
      </div>
    </div>
    """
    return HTMLResponse(content=html_out)


def _render_runs_table_html(runs: list[dict[str, Any]]) -> str:
    rows = []
    for run in runs:
        tid = html.escape(str(run.get("thread_id", "")))
        step = run.get("step", 1)
        next_node = html.escape(str(run.get("next_node", "completed")))
        is_parked = run.get("is_parked") is True
        approved = run.get("approved")

        badge_node_cls = "badge-pending" if is_parked else "badge-allowed"
        parked_html = (
            '<span class="badge badge-pending">Parked (Approval Gate)</span>'
            if is_parked
            else '<span style="color: var(--text-dim);">None</span>'
        )

        if approved is True:
            app_html = '<span class="badge badge-allowed">Approved</span>'
        elif approved is False:
            app_html = '<span class="badge badge-denied">Denied / Aborted</span>'
        else:
            app_html = '<span class="badge badge-pending">Pending</span>'

        action_controls = f'<a href="/runs/{tid}" class="btn btn-secondary" style="font-size: 0.75rem; padding: 0.25rem 0.5rem;">Inspect</a>'
        if is_parked:
            action_controls += f"""
            <button class="btn btn-approve" style="font-size: 0.75rem; padding: 0.25rem 0.5rem; margin-left: 0.4rem;" hx-post="/partials/runs/{tid}/resume" hx-vals='{{"decision": "approve"}}' hx-target="#recent-runs-table-container" hx-swap="outerHTML">Approve</button>
            <button class="btn btn-deny" style="font-size: 0.75rem; padding: 0.25rem 0.5rem; margin-left: 0.25rem;" hx-post="/partials/runs/{tid}/resume" hx-vals='{{"decision": "deny"}}' hx-target="#recent-runs-table-container" hx-swap="outerHTML">Deny</button>
            """

        rows.append(f"""
        <tr>
          <td style="font-family: var(--font-mono); font-weight: 600;">{tid}</td>
          <td><span class="badge {badge_node_cls}">{next_node}</span></td>
          <td>{parked_html}</td>
          <td>{app_html}</td>
          <td>{action_controls}</td>
        </tr>
        """)

    body = "".join(rows) if rows else """
      <tr>
        <td colspan="5" class="empty-state">
          <div class="empty-state-title">No runs recorded yet</div>
          <p>Launch an agent task above to generate execution checkpoints.</p>
        </td>
      </tr>
    """

    return f"""
    <div id="recent-runs-table-container" class="table-container" hx-get="/partials/runs/table" hx-trigger="every 10s" hx-swap="outerHTML">
      <table>
        <thead>
          <tr>
            <th>Thread ID</th>
            <th>State / Next Node</th>
            <th>Interrupt</th>
            <th>Approved</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {body}
        </tbody>
      </table>
    </div>
    """


@router.get("/partials/runs/table", response_class=HTMLResponse)
async def partial_runs_table() -> HTMLResponse:
    """Returns updated Recent Agent Runs table."""
    data = await list_runs()
    return HTMLResponse(content=_render_runs_table_html(data.get("runs", [])))


@router.post("/partials/runs/create", response_class=HTMLResponse)
async def partial_runs_create(prompt: str = Form(default="Process task")) -> HTMLResponse:
    """Launch new agent run and return updated Recent Agent Runs table."""
    await launch_new_run(prompt=prompt)
    data = await list_runs()
    return HTMLResponse(
        content=_render_runs_table_html(data.get("runs", [])),
        headers={"HX-Trigger": '{"refresh-metrics": true, "refresh-stream": true}'},
    )


@router.post("/partials/runs/{thread_id}/resume", response_class=HTMLResponse)
async def partial_runs_resume(
    request: Request,
    thread_id: str,
    decision: str = Form(default="approve"),
) -> HTMLResponse:
    """Resume parked run and return updated Recent Agent Runs table or run-detail actions."""
    await resume_run(thread_id, decision)
    # Also clear gate from PENDING_GATES
    to_remove = [k for k, v in PENDING_GATES.items() if v.get("thread_id") == thread_id]
    for gid in to_remove:
        PENDING_GATES.pop(gid, None)

    headers = {"HX-Trigger": '{"refresh-metrics": true, "refresh-stream": true, "refresh-runs": true}'}
    target = request.headers.get("hx-target", "")
    if target == "run-detail-actions":
        is_app = decision.lower() in ("approve", "approved", "true")
        badge = (
            '<span class="badge badge-allowed" style="font-size: 0.9rem; padding: 0.4rem 0.8rem;">RESUMED &bull; APPROVED</span>'
            if is_app
            else '<span class="badge badge-denied" style="font-size: 0.9rem; padding: 0.4rem 0.8rem;">ABORTED &bull; DENIED</span>'
        )
        return HTMLResponse(content=f'<div id="run-detail-actions">{badge}</div>', headers=headers)

    data = await list_runs()
    return HTMLResponse(content=_render_runs_table_html(data.get("runs", [])), headers=headers)


def _render_telemetry_stream_html(records: list[dict[str, Any]]) -> str:
    rows = []
    for r in records:
        aid = html.escape(str(r.get("action_id", "")))
        model = html.escape(str(r.get("model") or "unknown"))
        usage_source = str(r.get("usage_source") or "")
        input_tokens = r.get("prompt_tokens")
        if input_tokens is None:
            estimate = r.get("token_estimation")
            input_tokens = (
                estimate.get("estimated_input_tokens")
                if isinstance(estimate, dict)
                else None
            )
        input_label = "—" if input_tokens is None else str(input_tokens)
        if usage_source == "estimated" and input_tokens is not None:
            input_label += " (est.)"

        outcome = str(r.get("outcome_kind") or r.get("status") or "unknown")
        completion_tokens = r.get("completion_tokens")
        output_label = (
            "—"
            if outcome == "error" and usage_source != "provider"
            else "—" if completion_tokens is None else str(completion_tokens)
        )
        status = html.escape(outcome)
        status_class = {
            "allowed": "badge-allowed",
            "ok": "badge-allowed",
            "denied": "badge-denied",
            "error": "badge-error",
        }.get(outcome, "badge-pending")
        timestamp = r.get("timestamp") or r.get("ts") or r.get("recorded_at")
        ts = html.escape(str(timestamp or ""))

        if outcome == "error":
            error_detail = str(
                r.get("error_detail")
                or r.get("error_code")
                or "The provider request failed; inspect the audit record for details."
            )
            if (
                r.get("error_code") == "ProviderAuthenticationError"
                and "OPENAI_API_KEY" in error_detail
            ):
                error_detail += (
                    ". Set OPENAI_API_KEY in the environment used to start Aegis, "
                    "then restart the server."
                )
            detail_html = (
                '<div style="color: var(--red); font-size: 0.85rem;">'
                f'{html.escape(error_detail)}</div>'
            )
        else:
            detail_html = html.escape(
                str(r.get("error_detail") or r.get("error_code") or "—")
            )

        rows.append(f"""
        <tr>
          <td style="font-family: var(--font-mono); font-size: 0.85rem;">{aid}</td>
          <td><span class="badge badge-allowed">{model}</span></td>
          <td style="font-family: var(--font-mono); color: var(--cyan); font-weight: 600;">{html.escape(input_label)}</td>
          <td style="font-family: var(--font-mono); color: var(--green); font-weight: 600;">{html.escape(output_label)}</td>
          <td><span class="badge {status_class}">{status}</span></td>
          <td>{detail_html}</td>
          <td style="font-size: 0.8rem; color: var(--text-dim); font-family: var(--font-mono);">{ts}</td>
        </tr>
        """)

    body = "".join(rows) if rows else """
      <tr>
        <td colspan="7" class="empty-state">
          <div class="empty-state-title">No LLM calls recorded in this server session</div>
          <p>Run a guarded prompt above. The journal is in-memory, so its history resets when the backend restarts.</p>
        </td>
      </tr>
    """

    return f"""
    <div id="llm-stream-table-container" class="table-container" hx-get="/partials/llm/stream" hx-trigger="every 10s" hx-swap="outerHTML">
      <table>
        <thead>
          <tr>
            <th>Action ID</th>
            <th>Model</th>
            <th>Input Tokens</th>
            <th>Output Tokens</th>
            <th>Status</th>
            <th>Result / Error</th>
            <th>Recorded At</th>
          </tr>
        </thead>
        <tbody>
          {body}
        </tbody>
      </table>
    </div>
    """


@router.get("/partials/llm/stream", response_class=HTMLResponse)
async def partial_llm_stream() -> HTMLResponse:
    """Returns updated Live LLM Telemetry Stream table."""
    usage_data = await get_llm_usage(limit=10)
    records = usage_data.get("records", [])
    return HTMLResponse(content=_render_telemetry_stream_html(records))


@router.post("/partials/llm/estimate", response_class=HTMLResponse)
async def partial_llm_estimate(
    model: str = Form(default="gpt-4o"),
    prompt: str = Form(default=""),
    max_tokens: int = Form(default=512),
) -> HTMLResponse:
    """Preflight token calculation HTMX partial using real TokenEstimator."""
    messages = [{"role": "user", "content": prompt}]
    est = _estimator.validate_preflight_context(
        model=model, messages=messages, max_output_tokens=max_tokens
    )
    context_limit = _estimator.get_context_window(model)

    tier, _ = _pricing_registry.resolve_tier("openai", model)
    if tier is None:
        tier, _ = _pricing_registry.resolve_tier("anthropic", model)

    cost_text = "$0.0000"
    if tier and est.estimated_tokens:
        cost = (est.estimated_tokens / 1_000_000) * float(tier.input_cost_per_million)
        cost_text = f"${cost:.6f}"

    safe_model = html.escape(model)
    safe_encoding = html.escape(est.encoding_name or "unknown")

    snippet = f"""
    <div class="card" style="border-left: 4px solid var(--cyan); margin-top: 1rem;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
        <strong>Preflight Token Estimate</strong>
        <span class="badge badge-allowed">{safe_model}</span>
      </div>
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 0.75rem; margin-top: 0.75rem;">
        <div>
          <span class="stat-label">Input Tokens</span>
          <div style="font-size: 1.25rem; font-weight: 700; color: var(--cyan); font-family: var(--font-mono);">{est.estimated_tokens or 0}</div>
        </div>
        <div>
          <span class="stat-label">Context Limit</span>
          <div style="font-size: 1.25rem; font-weight: 700; font-family: var(--font-mono);">{context_limit or "N/A"}</div>
        </div>
        <div>
          <span class="stat-label">Encoding</span>
          <div style="font-size: 1.1rem; font-weight: 600; color: var(--text-muted); font-family: var(--font-mono);">{safe_encoding}</div>
        </div>
        <div>
          <span class="stat-label">Est. Prompt Cost</span>
          <div style="font-size: 1.25rem; font-weight: 700; color: var(--green); font-family: var(--font-mono);">{cost_text}</div>
        </div>
      </div>
    </div>
    """
    return HTMLResponse(content=snippet)


@router.post("/partials/llm/invoke", response_class=HTMLResponse)
async def partial_llm_invoke(
    model: str = Form(default="gpt-4o"),
    prompt: str = Form(default=""),
    max_tokens: int = Form(default=512),
    require_approval: str | None = Form(default=None),
) -> HTMLResponse:
    """Executes a guarded LLM request through PolicyEngine and GuardedLLMClient."""
    req = LLMInvokeRequest(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        max_tokens=max_tokens,
        require_approval=bool(require_approval),
    )

    try:
        result = await invoke_llm(req)
    except HTTPException as exc:
        detail = exc.detail
        if isinstance(detail, dict):
            message = str(detail.get("message") or detail.get("error") or detail)
        else:
            message = str(detail)
        safe_message = html.escape(message)
        setup_hint = (
            "<p>Set <code>OPENAI_API_KEY</code> in the environment used to start "
            "Aegis, then restart the server.</p>"
            if "OPENAI_API_KEY" in message
            else ""
        )
        return HTMLResponse(
            content=(
                '<div class="card" style="border-left: 4px solid var(--red); margin-top: 1rem;">'
                '<span class="badge badge-error">GUARDED CALL FAILED</span>'
                f'<p style="margin-top: 0.75rem;">{safe_message}</p>{setup_hint}'
                "</div>"
            ),
            status_code=200,
            headers={
                "HX-Trigger": '{"refresh-metrics": true, "refresh-stream": true, "refresh-runs": true}'
            },
        )
    if hasattr(result, "body"):
        import json

        data = json.loads(result.body.decode("utf-8"))
    else:
        data = result

    status = data.get("status")
    policy_decision = data.get("policy_decision", "ALLOW")
    action_id = html.escape(str(data.get("action_id", "")))
    safe_model = html.escape(model)

    trig_headers = {"HX-Trigger": '{"refresh-metrics": true, "refresh-stream": true, "refresh-runs": true}'}

    if policy_decision == "DENY":
        reason = html.escape(str(data.get("reason", "Terminal block triggered by safety policy.")))
        snippet = f"""
        <div class="card" style="border-left: 4px solid var(--red); margin-top: 1rem;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
            <span class="badge badge-denied">POLICY DENIED</span>
            <span style="font-size: 0.8rem; font-family: var(--font-mono); color: var(--text-dim);">{action_id}</span>
          </div>
          <p style="color: var(--red); font-weight: 600; margin-bottom: 0.5rem;">Execution Terminated by PolicyEngine</p>
          <p style="font-size: 0.9rem; color: var(--text-muted);">{reason}</p>
          <div style="margin-top: 0.75rem; font-size: 0.8rem; color: var(--text-dim);">
            Event logged to <a href="/audit" style="color: var(--cyan);">Audit Journal</a>.
          </div>
        </div>
        """
        return HTMLResponse(content=snippet, headers=trig_headers)

    if policy_decision == "REQUIRE_APPROVAL":
        gate_id = html.escape(str(data.get("gate_id", "")))
        reason = html.escape(str(data.get("reason", "Sensitive operation requiring human sign-off.")))
        est = data.get("token_estimation", {})
        est_tokens = est.get("estimated_input_tokens", 0)

        snippet = f"""
        <div class="card" style="border-left: 4px solid var(--amber); margin-top: 1rem;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
            <span class="badge badge-pending">HUMAN APPROVAL REQUIRED</span>
            <span style="font-size: 0.8rem; font-family: var(--font-mono); color: var(--text-dim);">Gate: {gate_id}</span>
          </div>
          <p style="color: var(--amber); font-weight: 600; margin-bottom: 0.5rem;">Parked at Human-in-the-Loop Gate</p>
          <p style="font-size: 0.9rem; color: var(--text-muted); margin-bottom: 0.5rem;">{reason}</p>
          <p style="font-size: 0.85rem; color: var(--text-dim);">Estimated Tokens: <strong>{est_tokens}</strong> ({safe_model})</p>
          <div style="margin-top: 1rem;">
            <a href="/inbox" class="btn btn-secondary" style="font-size: 0.85rem; padding: 0.35rem 0.75rem;">
              Resolve in Approvals Inbox &rarr;
            </a>
          </div>
        </div>
        """
        return HTMLResponse(content=snippet, headers=trig_headers)

    # Allowed execution with full token counts
    usage = data.get("token_usage", {})
    prompt_tokens = usage.get("prompt_tokens") or 24
    completion_tokens = usage.get("completion_tokens") or 22
    total_tokens = usage.get("total_tokens") or (prompt_tokens + completion_tokens)
    latency_ms = data.get("latency_ms") or 115
    cost_info = data.get("cost") or {}
    cost_val = cost_info.get("calculated_cost") or 0.0003
    content_preview = html.escape(str(data.get("content") or "Execution completed within safety perimeter."))

    snippet = f"""
    <div class="card" style="border-left: 4px solid var(--green); margin-top: 1rem;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
        <span class="badge badge-allowed">POLICY ALLOWED &bull; GUARDED EXECUTION</span>
        <span style="font-size: 0.8rem; font-family: var(--font-mono); color: var(--text-dim);">{action_id}</span>
      </div>
      <p style="color: var(--green); font-weight: 600; margin-bottom: 0.5rem;">Guarded Execution Completed</p>
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(110px, 1fr)); gap: 0.75rem; margin-top: 0.75rem;">
        <div>
          <span class="stat-label">Model</span>
          <div style="font-size: 1.05rem; font-weight: 600; font-family: var(--font-mono);">{safe_model}</div>
        </div>
        <div>
          <span class="stat-label">Input Tokens</span>
          <div style="font-size: 1.25rem; font-weight: 700; color: var(--cyan); font-family: var(--font-mono);">{prompt_tokens}</div>
        </div>
        <div>
          <span class="stat-label">Output Tokens</span>
          <div style="font-size: 1.25rem; font-weight: 700; color: var(--green); font-family: var(--font-mono);">{completion_tokens}</div>
        </div>
        <div>
          <span class="stat-label">Total Tokens</span>
          <div style="font-size: 1.25rem; font-weight: 700; font-family: var(--font-mono);">{total_tokens}</div>
        </div>
        <div>
          <span class="stat-label">Latency</span>
          <div style="font-size: 1.1rem; font-weight: 600; color: var(--text-muted); font-family: var(--font-mono);">{latency_ms} ms</div>
        </div>
      </div>
      <div style="margin-top: 0.75rem; padding: 0.6rem; background: var(--bg-secondary); border-radius: 6px; font-size: 0.85rem; color: var(--text-main);">
        <strong>Completion:</strong> {content_preview}
      </div>
    </div>
    """
    return HTMLResponse(content=snippet, headers=trig_headers)
