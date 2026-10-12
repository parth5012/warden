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
    gates = [
        gate
        for gate_id, gate in PENDING_GATES.items()
        if is_pending_llm_gate(gate_id)
    ]
    return _templates.TemplateResponse(
        request=request,
        name="llm_inbox.html",
        context={"active_page": "approvals", "pending_count": len(gates), "gates": gates},
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
