"""Grants HTTP endpoints and UI management router for Warden.

Implements:
- POST /grants: issue task-scoped grant (validation ranges: TTL 5..240 min, max-uses 1..50).
- GET /grants: query live grants by thread_id.
- POST /grants/{id}/revoke: revoke grant (404 unknown, 409 already terminal).
- JSON-clean responses with HTMX partial rendering support (lock 12).
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Form, Header, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from app.audit import JOURNAL_STORE
from warden.grants import (
    Grant,
    GrantStatus,
    ScopeRule,
    get_grants_store,
)
from warden.journal import EventKind, JournalEvent

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
templates = Jinja2Templates(directory=TEMPLATES_DIR)

router = APIRouter(tags=["User Grants"])


class ScopeRuleModel(BaseModel):
    tool: str
    constraints: dict[str, Any] = Field(default_factory=dict)


class CreateGrantRequest(BaseModel):
    thread_id: str
    tool: Optional[str] = None
    constraints: Optional[dict[str, Any]] = None
    scope: Optional[list[ScopeRuleModel]] = None
    ttl_minutes: int = Field(default=30, ge=5, le=240)
    max_uses: int = Field(default=5, ge=1, le=50)
    reason: str = ""


def _grant_to_dict(grant: Grant) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    created_utc = grant.created_at if grant.created_at.tzinfo else grant.created_at.replace(tzinfo=timezone.utc)
    elapsed_sec = int((now - created_utc).total_seconds())
    rem_sec = max(0, grant.ttl_seconds - elapsed_sec)

    status = grant.status.value
    if status == "active" and rem_sec <= 0:
        status = "expired"

    return {
        "id": grant.id,
        "thread_id": grant.thread_id,
        "granted_by": grant.granted_by,
        "scope": [{"tool": r.tool, "constraints": r.constraints} for r in grant.scope],
        "ttl_seconds": grant.ttl_seconds,
        "ttl_minutes": grant.ttl_seconds // 60,
        "ttl_remaining_sec": rem_sec,
        "time_display": f"{rem_sec // 60}m {rem_sec % 60}s" if status == "active" else status.upper(),
        "max_uses": grant.max_uses,
        "uses": grant.uses,
        "uses_left": max(0, grant.max_uses - grant.uses),
        "status": status,
        "created_at": created_utc.isoformat(),
        "reason": grant.reason,
    }


def derive_scope_from_payload(tool_name: str, payload: dict[str, Any]) -> ScopeRule:
    """Derive scope rule constraints narrowed from an action's payload."""
    constraints: dict[str, Any] = {}

    # SQL table derivation (canonical key: sql; legacy fallback: statement)
    if "table" in payload:
        constraints["table"] = str(payload["table"])
    elif "sql" in payload or "statement" in payload:
        from warden.policy.layers_static import is_scoped_drop_table

        sql_text = str(payload.get("sql", payload.get("statement", "")))
        is_scoped, table_name = is_scoped_drop_table(sql_text)
        if is_scoped and table_name:
            constraints["table"] = table_name

    # Service derivation
    if "service" in payload:
        constraints["service"] = str(payload["service"])
    elif "service_name" in payload:
        constraints["service"] = str(payload["service_name"])

    # Path prefix derivation
    if "path" in payload:
        p = str(payload["path"])
        p_dir = str(Path(p).parent)
        if not p_dir.endswith("/"):
            p_dir += "/"
        constraints["path_prefix"] = p_dir
    elif "target_resource" in payload:
        r = str(payload["target_resource"])
        if not r.endswith("/"):
            r += "/"
        constraints["path_prefix"] = r

    return ScopeRule(tool=tool_name, constraints=constraints)


@router.post("/grants")
async def issue_grant(
    request: Request,
    warden_key: Optional[str] = Header(None, alias="Warden-Key"),
) -> Any:
    """Issue a new temporary capability grant.

    Supports both JSON bodies and HTML Form requests.
    Validates TTL range (5..240 min) and max_uses range (1..50).
    """
    body: dict[str, Any] = {}
    content_type = request.headers.get("content-type", "")

    if "application/json" in content_type:
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body")
    else:
        form = await request.form()
        body = dict(form)

    thread_id = str(body.get("thread_id", "")).strip()
    if not thread_id:
        raise HTTPException(status_code=422, detail="thread_id is required")

    try:
        ttl_minutes = int(body.get("ttl_minutes", 30))
        if not (5 <= ttl_minutes <= 240):
            raise HTTPException(status_code=422, detail="ttl_minutes must be between 5 and 240")
    except (ValueError, TypeError):
        raise HTTPException(status_code=422, detail="ttl_minutes must be an integer between 5 and 240")

    try:
        max_uses = int(body.get("max_uses", 5))
        if not (1 <= max_uses <= 50):
            raise HTTPException(status_code=422, detail="max_uses must be between 1 and 50")
    except (ValueError, TypeError):
        raise HTTPException(status_code=422, detail="max_uses must be an integer between 1 and 50")

    reason = str(body.get("reason", "")).strip()
    granted_by = warden_key or str(body.get("granted_by") or "operator")

    # Scope rule resolution
    scope_rules: list[ScopeRule] = []
    if "scope" in body and isinstance(body["scope"], list):
        for r in body["scope"]:
            if isinstance(r, dict) and "tool" in r:
                scope_rules.append(ScopeRule(tool=str(r["tool"]), constraints=dict(r.get("constraints", {}))))
    elif "tool" in body:
        tool_name = str(body["tool"])
        constraints_raw = body.get("constraints", {})
        if isinstance(constraints_raw, str):
            try:
                constraints = json.loads(constraints_raw)
            except Exception:
                constraints = {}
        elif isinstance(constraints_raw, dict):
            constraints = constraints_raw
        else:
            constraints = {}
        scope_rules.append(ScopeRule(tool=tool_name, constraints=constraints))
    else:
        scope_rules.append(ScopeRule(tool="*"))

    grant_id = f"gr_{uuid.uuid4().hex[:8]}"
    now = datetime.now(timezone.utc)
    grant = Grant(
        id=grant_id,
        thread_id=thread_id,
        granted_by=granted_by,
        scope=tuple(scope_rules),
        ttl_seconds=ttl_minutes * 60,
        max_uses=max_uses,
        uses=0,
        status=GrantStatus.ACTIVE,
        created_at=now,
        reason=reason,
    )

    store = get_grants_store()
    issued = store.issue(grant)

    # Journal the grant issuance event
    JOURNAL_STORE.append(
        JournalEvent(
            id=f"ev_grant_{uuid.uuid4().hex[:6]}",
            run_id=f"run_{thread_id}",
            thread_id=thread_id,
            action_id=None,
            checkpoint_step=None,
            actor=f"approver:{granted_by}",
            status="Issued",
            description=f"Grant {grant_id} issued by {granted_by} ({ttl_minutes}m, {max_uses} uses)",
            payload={
                "grant_id": grant_id,
                "scope": [{"tool": r.tool, "constraints": r.constraints} for r in scope_rules],
                "ttl_minutes": ttl_minutes,
                "max_uses": max_uses,
                "reason": reason,
            },
            kind=EventKind.GRANT_ISSUED.value,
            ts=now.isoformat(),
        )
    )

    grant_dict = _grant_to_dict(issued)

    if request.headers.get("HX-Request"):
        if hasattr(store, "_grants"):
            all_grants = list(getattr(store, "_grants").values())
        else:
            all_grants = [issued]
        all_dicts = [_grant_to_dict(g) for g in all_grants]
        return templates.TemplateResponse(
            request=request,
            name="components/grants_table_fragment.html",
            context={"grants": all_dicts, "thread_id": thread_id},
        )

    return JSONResponse(status_code=201, content=grant_dict)


@router.get("/grants")
async def list_grants(
    request: Request,
    thread_id: Optional[str] = Query(None, description="Filter grants by thread_id"),
) -> Any:
    """List grants, optionally filtered by thread_id."""
    store = get_grants_store()
    if thread_id:
        grants = store.list_for_thread(thread_id)
    else:
        # If in-memory adapter exposes _grants
        if hasattr(store, "_grants"):
            grants = list(getattr(store, "_grants").values())
        else:
            grants = []

    result = [_grant_to_dict(g) for g in grants]

    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(
            request=request,
            name="components/grants_table_fragment.html",
            context={"grants": result, "thread_id": thread_id},
        )

    return JSONResponse(content=result)


@router.get("/grants-view", response_class=HTMLResponse)
async def grants_console_page(request: Request) -> HTMLResponse:
    """Render full Grants governance page."""
    store = get_grants_store()
    if hasattr(store, "_grants"):
        grants = list(getattr(store, "_grants").values())
    else:
        grants = []
    result = [_grant_to_dict(g) for g in grants]
    return templates.TemplateResponse(
        request=request,
        name="grants.html",
        context={"request": request, "active_page": "grants", "grants": result},
    )


@router.post("/grants/{grant_id}/revoke")
async def revoke_grant(
    request: Request,
    grant_id: str,
    warden_key: Optional[str] = Header(None, alias="Warden-Key"),
) -> Any:
    """Revoke an active grant. Returns 404 if not found, 409 if already terminal."""
    store = get_grants_store()
    grant = store.get(grant_id)
    if grant is None:
        raise HTTPException(status_code=404, detail="Grant not found")

    if grant.status in (GrantStatus.EXHAUSTED, GrantStatus.EXPIRED, GrantStatus.REVOKED):
        raise HTTPException(
            status_code=409,
            detail=f"Grant is already terminal (status: {grant.status.value})",
        )

    revoker = warden_key or "operator"
    revoked = store.revoke(grant_id, revoked_by=revoker)
    assert revoked is not None

    # Journal the revocation
    JOURNAL_STORE.append(
        JournalEvent(
            id=f"ev_rev_{uuid.uuid4().hex[:6]}",
            run_id=f"run_{grant.thread_id}",
            thread_id=grant.thread_id,
            action_id=None,
            checkpoint_step=None,
            actor=f"approver:{revoker}",
            status="Revoked",
            description=f"Grant {grant_id} revoked by {revoker}",
            payload={"grant_id": grant_id, "revoked_by": revoker},
            kind=EventKind.GRANT_REVOKED.value,
            ts=datetime.now(timezone.utc).isoformat(),
        )
    )

    result = _grant_to_dict(revoked)

    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(
            request=request,
            name="components/grant_row.html",
            context={"grant": result},
        )

    return JSONResponse(content=result)
