"""Operator approval inbox REST endpoints."""

from __future__ import annotations

import html
from typing import Any, Literal
from fastapi import APIRouter, Form, Header, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from warden.models import Denied, Error

router = APIRouter(prefix="/inbox", tags=["Approvals Inbox"])


class ResolveGateRequest(BaseModel):
    decision: Literal["approve", "deny"]
    reason: str | None = None


# In-memory mock gate store for MVP demo / testing
PENDING_GATES: dict[str, dict[str, Any]] = {
    "gate-req-001": {
        "id": "gate-req-001",
        "thread_id": "demo-thread-1",
        "action_name": "send_email",
        "ask": "Approve sending weekly report email to external team?",
        "payload": {
            "action": "send_email",
            "recipient": "team@example.com",
            "body": "Weekly ops report ready",
        },
        "created_at": "2026-10-11T14:00:00Z",
    }
}


@router.get("")
async def list_pending_gates() -> dict[str, Any]:
    """List all pending gate requests.

    Union of the journal projection (`gate_requested` minus resolutions —
    covers chat-tool escalations) and the legacy in-memory dict (LangGraph
    runs, LLM gates, demo seed).
    """
    try:
        from app.projections import all_pending_gates

        return {"pending_gates": all_pending_gates()}
    except Exception:
        return {"pending_gates": list(PENDING_GATES.values())}


@router.post("/{gate_id}/resolve")
async def resolve_gate(
    gate_id: str,
    request: Request,
    decision: str | None = Form(default=None),
    warden_key: str | None = Header(default=None, alias="Warden-Key"),
) -> Response:
    """Resolve a gate with 'approve' or 'deny'.

    Supports both JSON clients and HTMX form submissions.
    """
    if gate_id not in PENDING_GATES:
        # Journal-projected tool gate (e.g. chat escalation): resolve it for
        # real through the shared resolver instead of bouncing to chat.
        try:
            from app.tool_gates import resolve_tool_gate
        except Exception:
            return JSONResponse(
                status_code=404,
                content={"error": "not_found", "detail": f"Gate {gate_id} not found"},
            )

        # Determine decision first (Form or JSON body)
        _dec = decision
        _body_dec: str | None = None
        if not _dec:
            try:
                _body = await request.json()
                if isinstance(_body, dict) and "decision" in _body:
                    _body_dec = str(_body["decision"]).strip().lower()
            except Exception:
                pass
        _dec = _dec or _body_dec
        if _dec not in ("approve", "deny"):
            # Unknown gate and no usable decision: check whether it is a
            # journal-projected tool gate to give a precise status.
            from app.projections import live_pending_gates

            journal_hit = next(
                (g for g in live_pending_gates() if str(g.get("id")) == gate_id),
                None,
            )
            if journal_hit is not None:
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "invalid_decision",
                        "detail": "Decision must be either 'approve' or 'deny'",
                    },
                )
            return JSONResponse(
                status_code=404,
                content={"error": "not_found", "detail": f"Gate {gate_id} not found"},
            )
        try:
            _approver = warden_key or "operator"
            result = await resolve_tool_gate(gate_id, _dec, _approver)
        except Exception:
            result = {"ok": False, "error": "resolve_failed"}
        if not result.get("ok"):
            if result.get("error") == "not_found":
                return JSONResponse(
                    status_code=404,
                    content={"error": "not_found", "detail": f"Gate {gate_id} not found"},
                )
            return JSONResponse(
                status_code=502,
                content={
                    "error": str(result.get("error") or "resolve_failed"),
                    "detail": str(result.get("message") or "Tool gate resolution failed."),
                    "gate_id": gate_id,
                },
            )
        # Also drop any matching legacy entry (union dedupe safety).
        PENDING_GATES.pop(gate_id, None)
        if "text/html" in request.headers.get("accept", "") or "HX-Request" in request.headers:
            outcome = str(result.get("outcome"))
            status_color = "var(--green)" if outcome == "approved" else "var(--red)"
            badge_class = "badge-allowed" if outcome == "approved" else "badge-denied"
            return HTMLResponse(
                content=f"""
        <div class="card" style="border-left: 4px solid {status_color}; opacity: 0.85;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <span class="badge {badge_class}">RESOLVED: {html.escape(outcome.upper())}</span>
                    <strong style="margin-left: 0.5rem;">{html.escape(str(result.get("action_name") or "tool"))}</strong>
                </div>
                <span style="font-size: 0.8rem; color: var(--text-dim);">Gate {html.escape(gate_id)} resolved</span>
            </div>
        </div>
        """
            )
        return JSONResponse(
            content={
                "gate_id": gate_id,
                "status": "resolved",
                "decision": _dec,
                "outcome": result.get("outcome"),
                "action_id": result.get("action_id"),
                "approver": result.get("decided_by"),
            }
        )

    # Determine decision from Form or JSON body
    dec = decision
    if not dec:
        try:
            body = await request.json()
            if isinstance(body, dict) and "decision" in body:
                dec = str(body["decision"]).strip().lower()
        except Exception:
            pass

    if dec not in ("approve", "deny"):
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_decision",
                "detail": "Decision must be either 'approve' or 'deny'",
            },
        )

    from backend.api.llm import is_pending_llm_gate, resolve_pending_llm_gate

    is_llm_gate = is_pending_llm_gate(gate_id)
    if is_llm_gate:
        llm_outcome = await resolve_pending_llm_gate(gate_id, dec, warden_key)
        if isinstance(llm_outcome, Error):
            status_code = 403 if llm_outcome.reason == "unauthorized_approver" else 503
            return JSONResponse(
                status_code=status_code,
                content={"error": llm_outcome.reason, "gate_id": gate_id},
            )
        if llm_outcome is None:
            return JSONResponse(
                status_code=404,
                content={"error": "not_found", "detail": f"Gate {gate_id} not found"},
            )
        if isinstance(llm_outcome, Denied) and dec == "approve":
            if "expired" in llm_outcome.reason.lower():
                PENDING_GATES.pop(gate_id, None)
                return JSONResponse(
                    status_code=410,
                    content={
                        "error": "approval_expired",
                        "detail": llm_outcome.reason,
                        "gate_id": gate_id,
                    },
                )
            return JSONResponse(
                status_code=403 if "Approval rejected" in llm_outcome.reason else 409,
                content={
                    "error": "approval_rejected",
                    "detail": llm_outcome.reason,
                    "gate_id": gate_id,
                },
            )

    gate = PENDING_GATES.pop(gate_id)

    # If the gate belongs to an agent run, resume the execution graph
    if gate.get("thread_id") and not is_llm_gate:
        try:
            from backend.api.runs import resume_run
            await resume_run(gate["thread_id"], dec)
        except Exception:
            pass

    safe_dec = html.escape(dec)
    safe_gate_id = html.escape(gate_id)
    safe_action = html.escape(str(gate["action_name"]))

    # If requested via HTMX, return updated HTML snippet removing the card
    accept = request.headers.get("accept", "")
    if "text/html" in accept or "HX-Request" in request.headers:
        status_color = "var(--green)" if dec == "approve" else "var(--red)"
        badge_class = "badge-allowed" if dec == "approve" else "badge-denied"
        card_html = f"""
        <div class="card" style="border-left: 4px solid {status_color}; opacity: 0.85;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <span class="badge {badge_class}">RESOLVED: {safe_dec.upper()}</span>
                    <strong style="margin-left: 0.5rem;">{safe_action}</strong>
                </div>
                <span style="font-size: 0.8rem; color: var(--text-dim);">Gate {safe_gate_id} resolved</span>
            </div>
        </div>
        """
        return HTMLResponse(content=card_html)

    return JSONResponse(
        content={
            "gate_id": gate_id,
            "status": "resolved",
            "decision": dec,
            "action_name": gate["action_name"],
            "approver": (
                "authenticated operator"
                if is_llm_gate
                else warden_key or "operator"
            ),
        }
    )
