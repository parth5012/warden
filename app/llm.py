"""Aegis UI for the guarded LLM execution and approval workflow."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from backend.api.inbox import PENDING_GATES
from backend.api.llm import (
    GROQ_MODELS,
    LLMInvokeRequest,
    TokenEstimateRequest,
    estimate_tokens,
    get_llm_usage,
    invoke_llm,
    is_groq_configured,
    is_pending_llm_gate,
    resolve_pending_llm_gate,
)
from warden.config import settings
from warden.models import Allowed, Denied, Error

_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
_templates = Jinja2Templates(directory=_TEMPLATES_DIR)
router = APIRouter(tags=["Guarded LLM UI"])


def _response_payload(response: JSONResponse) -> dict[str, Any]:
    payload = json.loads(response.body)
    return payload if isinstance(payload, dict) else {"detail": payload}


def _error_message(detail: Any) -> str:
    if isinstance(detail, dict):
        return str(detail.get("message") or detail.get("detail") or detail.get("error") or detail)
    return str(detail or "The guarded request failed.")


@router.get("/llm", response_class=HTMLResponse)
async def guarded_llm_page(request: Request) -> HTMLResponse:
    usage = await get_llm_usage(limit=20)
    return _templates.TemplateResponse(
        request=request,
        name="llm.html",
        context={
            "active_page": "llm",
            "pending_count": sum(
                1 for gate_id in PENDING_GATES if is_pending_llm_gate(gate_id)
            ),
            "configured": is_groq_configured(),
            "models": GROQ_MODELS,
            "default_model": settings.groq_model,
            "summary": usage["summary"],
            "records": usage["records"],
        },
    )


@router.post("/llm/estimate", response_class=HTMLResponse)
async def estimate_guarded_llm(
    model: str = Form(...),
    prompt: str = Form(...),
    max_tokens: int = Form(default=512, ge=1, le=32768),
) -> HTMLResponse:
    clean_prompt = prompt.strip()
    if not clean_prompt:
        raise HTTPException(status_code=400, detail="Enter a prompt to estimate.")

    result = await estimate_tokens(
        TokenEstimateRequest(
            model=model,
            messages=[{"role": "user", "content": clean_prompt}],
            max_output_tokens=max_tokens,
        )
    )
    if not result["is_supported"]:
        content = (
            '<div class="llm-result llm-result-error" role="alert"><strong>Estimate unavailable</strong>'
            f'<p>{html.escape(str(result.get("note") or "This model is not supported."))}</p></div>'
        )
    else:
        content = (
            '<div class="llm-result llm-result-info" role="status">'
            f'<strong>Preflight estimate · {html.escape(model)}</strong>'
            f'<p>Input: {result["estimated_input_tokens"]} tokens · '
            f'Output cap: {max_tokens} · Estimated total: {result["estimated_total_tokens"]} '
            f'· Context: {result["context_window_limit"]} · {html.escape(str(result["encoding"]))}</p>'
            '<small>No provider call was made.</small></div>'
        )
    return HTMLResponse(content=content)


@router.post("/llm/invoke", response_class=HTMLResponse)
async def invoke_guarded_llm(
    model: str = Form(...),
    prompt: str = Form(...),
    max_tokens: int = Form(default=512, ge=1, le=32768),
    require_approval: str | None = Form(default=None),
) -> HTMLResponse:
    clean_prompt = prompt.strip()
    if not clean_prompt:
        raise HTTPException(status_code=400, detail="Enter a prompt to run.")

    try:
        result = await invoke_llm(
            LLMInvokeRequest(
                model=model,
                provider="groq",
                messages=[{"role": "user", "content": clean_prompt}],
                max_tokens=max_tokens,
                require_approval=require_approval == "true",
            )
        )
    except HTTPException as exc:
        message = _error_message(exc.detail)
        content = (
            '<div class="llm-result llm-result-error" role="alert">'
            '<strong>Guarded request failed</strong>'
            f'<p>{html.escape(message)}</p>'
            '<small>Review policy, provider configuration, limits, and the audit log.</small></div>'
        )
        return HTMLResponse(content=content, status_code=200)

    if isinstance(result, JSONResponse):
        result = _response_payload(result)

    if result.get("status") == "denied":
        content = (
            '<div class="llm-result llm-result-error" role="alert">'
            '<strong>Blocked by policy · DENY</strong>'
            f'<p>{html.escape(str(result.get("reason") or "Policy denied this request."))}</p>'
            f'<small>Policy: {html.escape(str(result.get("policy_name") or "unknown"))} · '
            f'Action: {html.escape(str(result.get("action_id") or ""))}</small></div>'
        )
        return HTMLResponse(content=content)

    if result.get("status") == "pending_approval":
        gate_id = str(result.get("gate_id") or "")
        content = (
            '<div class="llm-result llm-result-pending" role="status">'
            '<strong>Human approval required · provider not called</strong>'
            f'<p>{html.escape(str(result.get("reason") or "This request is waiting for an operator."))}</p>'
            f'<small>Gate: {html.escape(gate_id)} · '
            '<a href="/inbox">Review in the Interception Gate</a></small></div>'
        )
        return HTMLResponse(
            content=content,
            headers={"HX-Trigger": "llm-usage-updated"},
        )

    if result.get("status") != "ok":
        detail = result.get("error_detail") or result.get("error_code") or "Provider call failed."
        return HTMLResponse(
            content=(
                '<div class="llm-result llm-result-error" role="alert">'
                '<strong>Guarded request failed</strong>'
                f'<p>{html.escape(str(detail))}</p></div>'
            ),
            headers={"HX-Trigger": "llm-usage-updated"},
        )

    usage = result.get("token_usage") or {}
    cost = result.get("cost") or {}
    content = (
        '<div class="llm-result llm-result-success" role="status">'
        '<strong>Guarded LLM call completed · ALLOW</strong>'
        f'<pre>{html.escape(str(result.get("completion") or "(Provider returned no text completion.)"))}</pre>'
        f'<p>{usage.get("prompt_tokens", "—")} input · '
        f'{usage.get("completion_tokens", "—")} output · '
        f'{usage.get("total_tokens", "—")} total tokens · '
        f'{result.get("latency_ms", "—")} ms · '
        f'${cost.get("calculated_cost_usd", cost.get("estimated_cost_usd", 0))}</p>'
        f'<small>Action {html.escape(str(result.get("action_id") or ""))} · '
        f'{html.escape(str(usage.get("source") or "usage unavailable"))}</small></div>'
    )
    return HTMLResponse(content=content, headers={"HX-Trigger": "llm-usage-updated"})


@router.get("/llm/stream", response_class=HTMLResponse)
async def guarded_llm_usage_stream() -> HTMLResponse:
    usage = await get_llm_usage(limit=20)
    records = usage["records"]
    if not records:
        rows = '<tr><td colspan="6" class="empty-state">No guarded LLM calls have been recorded yet.</td></tr>'
    else:
        rendered_rows: list[str] = []
        for record in records:
            model = html.escape(str(record.get("model") or "unknown"))
            outcome = html.escape(str(record.get("outcome_kind") or "unknown"))
            tokens = record.get("total_tokens")
            source = html.escape(str(record.get("usage_source") or ""))
            recorded = html.escape(str(record.get("timestamp") or record.get("ts") or ""))
            action_id = html.escape(str(record.get("action_id") or ""))
            cost = record.get("calculated_cost_usd", record.get("estimated_cost_usd"))
            cost_label = "—" if cost is None else f"${float(cost):.6f}"
            rendered_rows.append(
                "<tr>"
                f"<td>{action_id}</td><td>{model}</td><td>{outcome}</td>"
                f"<td>{html.escape(str(tokens if tokens is not None else '—'))} {source}</td>"
                f"<td>{cost_label}</td><td>{recorded}</td></tr>"
            )
        rows = "".join(rendered_rows)
    return HTMLResponse(
        content=(
            '<div id="llm-usage-table" hx-get="/llm/stream" '
            'hx-trigger="every 8s, llm-usage-updated from:body" hx-swap="outerHTML">'
            '<div class="table-responsive"><table class="table-custom">'
            '<thead><tr><th>Action</th><th>Model</th><th>Outcome</th><th>Tokens</th>'
            f'<th>Calculated cost</th><th>Recorded</th></tr></thead><tbody>{rows}</tbody>'
            '</table></div></div>'
        )
    )


@router.get("/inbox", response_class=HTMLResponse)
async def guarded_llm_inbox(request: Request) -> HTMLResponse:
    llm_gates = [
        gate
        for gate_id, gate in PENDING_GATES.items()
        if is_pending_llm_gate(gate_id)
    ]
    try:
        from app.projections import live_pending_gates

        tool_gates = live_pending_gates()
    except Exception:
        tool_gates = []
    legacy_tool_gates = [
        gate
        for gate_id, gate in PENDING_GATES.items()
        if not is_pending_llm_gate(gate_id)
    ]
    seen = {str(g.get("id")) for g in tool_gates}
    for gate in legacy_tool_gates:
        if str(gate.get("id")) not in seen:
            row = dict(gate)
            row.setdefault("source", "legacy")
            tool_gates.append(row)
    pending_count = len(llm_gates) + len(tool_gates)
    return _templates.TemplateResponse(
        request=request,
        name="llm_inbox.html",
        context={
            "active_page": "approvals",
            "pending_count": pending_count,
            "gates": llm_gates,
            "tool_gates": tool_gates,
        },
    )


@router.post("/inbox/tool/{gate_id}/resolve", response_class=HTMLResponse)
async def resolve_tool_gate_from_inbox(
    gate_id: str,
    decision: str = Form(...),
    approver: str = Form(default="operator"),
) -> HTMLResponse:
    """Approve/deny a journal-projected tool gate from the Interception Gate."""
    if decision not in {"approve", "deny"}:
        raise HTTPException(status_code=400, detail="Decision must be approve or deny.")
    from app.tool_gates import resolve_tool_gate

    result = await resolve_tool_gate(gate_id, decision, approver)
    if not result.get("ok"):
        error = str(result.get("error") or "resolve_failed")
        if error == "not_found":
            raise HTTPException(status_code=404, detail="Pending tool gate was not found.")
        if error == "action_not_found":
            raise HTTPException(
                status_code=410,
                detail="Original action is no longer available in the journal.",
            )
        raise HTTPException(
            status_code=502,
            detail=str(result.get("message") or "Tool gate resolution failed."),
        )
    outcome = str(result.get("outcome"))
    if outcome == "approved":
        badge, color = "RESOLVED: APPROVED", "var(--green)"
    elif outcome == "denied":
        badge, color = "RESOLVED: DENIED", "var(--red)"
    else:
        badge, color = "RESOLVED: DENIED BY POLICY", "var(--red)"
    return HTMLResponse(
        content=(
            '<div class="card" style="border-left: 4px solid '
            f'{color}; opacity: 0.85;">'
            '<div style="display: flex; justify-content: space-between; align-items: center;">'
            f'<div><span class="badge">{html.escape(badge)}</span>'
            f'<strong style="margin-left: 0.5rem;">{html.escape(str(result.get("action_name") or "tool"))}</strong>'
            f'<p style="margin: 0.25rem 0 0;">{html.escape(str(result.get("message") or ""))}</p></div>'
            f'<span style="font-size: 0.8rem; color: var(--text-dim);">Gate {html.escape(gate_id)} resolved</span>'
            "</div></div>"
        ),
        headers={"HX-Trigger": "dashboard-updated"},
    )


@router.post("/inbox/{gate_id}/resolve", response_class=HTMLResponse)
async def resolve_guarded_llm_gate(
    gate_id: str,
    decision: str = Form(...),
    approver_key: str = Form(...),
) -> HTMLResponse:
    if decision not in {"approve", "deny"}:
        raise HTTPException(status_code=400, detail="Decision must be approve or deny.")
    outcome = await resolve_pending_llm_gate(gate_id, decision, approver_key)
    if outcome is None:
        raise HTTPException(status_code=404, detail="Pending LLM approval was not found or has expired.")
    if isinstance(outcome, Error) and outcome.reason == "unauthorized_approver":
        raise HTTPException(status_code=403, detail="Approver credentials were rejected.")
    if isinstance(outcome, Denied) and decision == "approve":
        raise HTTPException(status_code=409, detail=outcome.reason)

    PENDING_GATES.pop(gate_id, None)
    if isinstance(outcome, Allowed):
        status = "approved; guarded call completed"
    elif isinstance(outcome, Error):
        status = f"approval consumed, but guarded execution failed: {outcome.reason}"
    else:
        status = "denied; no provider call was made"
    return HTMLResponse(
        content=(
            '<div class="llm-result llm-result-info" role="status">'
            f'Gate {html.escape(gate_id)} {html.escape(status)}. '
            '<a href="/llm">Return to Guarded LLM</a></div>'
        ),
        headers={"HX-Trigger": "llm-usage-updated"},
    )
