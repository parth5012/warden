"""Ephemeral Leases Management Router for Aegis.

DEPRECATED (grill lock 2026-10-13): supervisor-minted custody leases were
dropped per DECISIONS.md #3 in favor of human-issued user grants
(`src/warden/grants.py`, `/grants`). This router renders a demo-only
in-memory list (LEASES_STORE) that is never consulted by GuardedExecutor.
Kept for visual reference; new capability flows must use /grants.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
templates = Jinja2Templates(directory=TEMPLATES_DIR)

router = APIRouter(tags=["Ephemeral Leases"])


def _demo_token(lease_id: str) -> str:
    """Derive a deterministic demo-only token from the lease id (no real secret)."""
    return "aegis_sec_" + hashlib.sha256(f"demo:{lease_id}".encode()).hexdigest()[:16]


# ==============================================================================
# EPHEMERAL LEASES DATA STORE
# ==============================================================================

LEASES_STORE: List[Dict[str, Any]] = [
    {
        "id": "LSE-901",
        "agent": "DBAgent",
        "agent_model": "gpt-4o",
        "scope": "db:ddl_admin",
        "scope_description": "Execute database schema migrations and non-destructive index modifications",
        "granted_by": "Raghav (SecOps Lead)",
        "granted_at": (datetime.now(timezone.utc) - timedelta(minutes=15)).isoformat(),
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=45)).isoformat(),
        "ttl_minutes": 60,
        "max_operations": 5,
        "operations_used": 2,
        "status": "ACTIVE",
        "risk_tier": "Critical",
        "justification": "Perform schema indexing update for Q4 analytics pipeline (INC-8891)",
        "hmac_token": _demo_token("LSE-901"),
    },
    {
        "id": "LSE-842",
        "agent": "CodeAgent",
        "agent_model": "claude-3-5-sonnet",
        "scope": "fs:write_restricted",
        "scope_description": "Direct mutation of project build configurations and artifact directories",
        "granted_by": "Alice (Security Approver)",
        "granted_at": (datetime.now(timezone.utc) - timedelta(minutes=50)).isoformat(),
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
        "ttl_minutes": 60,
        "max_operations": 10,
        "operations_used": 8,
        "status": "ACTIVE",
        "risk_tier": "High",
        "justification": "Emergency hotfix compile for upstream dependency vulnerability CVE-2026-319",
        "hmac_token": _demo_token("LSE-842"),
    },
    {
        "id": "LSE-773",
        "agent": "KubeAgent",
        "agent_model": "claude-3-5-haiku",
        "scope": "k8s:debug_exec",
        "scope_description": "Attach ephemeral debug container to isolated sandbox staging namespace",
        "granted_by": "System Auto-Policy (L1 Policy SEC-K8S-01)",
        "granted_at": (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat(),
        "expires_at": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),
        "ttl_minutes": 60,
        "max_operations": 3,
        "operations_used": 3,
        "status": "EXPIRED",
        "risk_tier": "Elevated",
        "justification": "Automated diagnostic collection for crashed runner pod in cluster-us-east-1",
        "hmac_token": _demo_token("LSE-773"),
    },
    {
        "id": "LSE-612",
        "agent": "OpsAssistant",
        "agent_model": "gpt-4o-mini",
        "scope": "net:api_outbound",
        "scope_description": "Send telemetry Webhook and alert notification to external PagerDuty endpoint",
        "granted_by": "Raghav (SecOps Lead)",
        "granted_at": (datetime.now(timezone.utc) - timedelta(hours=5)).isoformat(),
        "expires_at": (datetime.now(timezone.utc) - timedelta(hours=4)).isoformat(),
        "ttl_minutes": 60,
        "max_operations": 20,
        "operations_used": 4,
        "status": "REVOKED",
        "risk_tier": "High",
        "justification": "Broadcast emergency maintenance window alerts",
        "hmac_token": _demo_token("LSE-612"),
    },
]


def _compute_lease_ttl(lease: Dict[str, Any]) -> Dict[str, Any]:
    """Helper to calculate real-time seconds remaining and progress bar percentage."""
    now = datetime.now(timezone.utc)
    try:
        expires_at = datetime.fromisoformat(lease["expires_at"])
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
    except Exception:
        expires_at = now

    diff_sec = int((expires_at - now).total_seconds())

    if lease["status"] == "ACTIVE" and diff_sec <= 0:
        lease["status"] = "EXPIRED"

    if lease["status"] == "ACTIVE":
        rem_min = max(0, diff_sec // 60)
        rem_sec = max(0, diff_sec % 60)
        time_display = f"{rem_min}m {rem_sec}s"
        total_sec = max(1, lease.get("ttl_minutes", 60) * 60)
        pct_left = max(0, min(100, int((diff_sec / total_sec) * 100)))
        if pct_left > 50:
            color = "green"
        elif pct_left > 20:
            color = "amber"
        else:
            color = "red"
    elif lease["status"] == "REVOKED":
        time_display = "REVOKED"
        pct_left = 0
        color = "red"
    else:
        time_display = "EXPIRED"
        pct_left = 0
        color = "red"

    return {
        **lease,
        "ttl_remaining_sec": max(0, diff_sec),
        "time_display": time_display,
        "pct_left": pct_left,
        "meter_color": color,
    }


@router.get("/leases", response_class=HTMLResponse)
async def get_leases_page(
    request: Request,
    status: Optional[str] = Query("all", description="Status filter: all, active, expired, revoked"),
    agent: Optional[str] = Query("all", description="Agent filter: all, DBAgent, CodeAgent, KubeAgent, OpsAssistant"),
    q: Optional[str] = Query(None, description="Search query"),
):
    """Render Ephemeral Leases governance console."""
    computed_leases = [_compute_lease_ttl(l) for l in LEASES_STORE]
    filtered = list(computed_leases)

    if status and status.lower() != "all":
        filtered = [l for l in filtered if l["status"].lower() == status.lower()]

    if agent and agent.lower() != "all":
        filtered = [l for l in filtered if l["agent"].lower() == agent.lower()]

    if q:
        query = q.strip().lower()
        filtered = [
            l for l in filtered
            if query in l["id"].lower()
            or query in l["agent"].lower()
            or query in l["scope"].lower()
            or query in l["justification"].lower()
            or query in l["granted_by"].lower()
        ]

    metrics = {
        "total": len(LEASES_STORE),
        "active_count": sum(l["status"] == "ACTIVE" for l in computed_leases),
        "expired_count": sum(l["status"] == "EXPIRED" for l in computed_leases),
        "revoked_count": sum(l["status"] == "REVOKED" for l in computed_leases),
        "total_ops_used": sum(l.get("operations_used", 0) for l in computed_leases),
    }

    context = {
        "request": request,
        "active_page": "leases",
        "leases": filtered,
        "metrics": metrics,
        "selected_status": status or "all",
        "selected_agent": agent or "all",
        "q": q or "",
        "demo_mode": True,
    }

    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(
            request=request,
            name="components/leases_table_fragment.html",
            context=context,
        )

    return templates.TemplateResponse(
        request=request,
        name="leases.html",
        context=context,
    )


@router.post("/leases/{lease_id}/revoke", response_class=HTMLResponse)
async def revoke_lease(request: Request, lease_id: str):
    """Revoke an active ephemeral lease immediately via HTMX."""
    lease = next((l for l in LEASES_STORE if l["id"] == lease_id), None)
    if not lease:
        raise HTTPException(status_code=404, detail="Lease not found")

    if _compute_lease_ttl(lease)["status"] != "ACTIVE":
        raise HTTPException(status_code=409, detail="Lease is not active")
    lease["status"] = "REVOKED"
    updated_lease = _compute_lease_ttl(lease)

    # Re-render the full leases table fragment so metrics & row state stay synchronized
    computed_leases = [_compute_lease_ttl(l) for l in LEASES_STORE]
    metrics = {
        "total": len(LEASES_STORE),
        "active_count": sum(l["status"] == "ACTIVE" for l in computed_leases),
        "expired_count": sum(l["status"] == "EXPIRED" for l in computed_leases),
        "revoked_count": sum(l["status"] == "REVOKED" for l in computed_leases),
        "total_ops_used": sum(l.get("operations_used", 0) for l in computed_leases),
    }
    return templates.TemplateResponse(
        request=request,
        name="components/leases_table_fragment.html",
        context={
            "request": request,
            "leases": computed_leases,
            "metrics": metrics,
            "selected_status": "all",
            "selected_agent": "all",
            "q": "",
            "demo_mode": True,
        },
    )


@router.post("/leases", response_class=HTMLResponse)
async def issue_new_lease(
    request: Request,
    agent: str = Form(...),
    scope: str = Form(...),
    ttl_minutes: int = Form(30, ge=5, le=240),
    max_operations: int = Form(5, ge=1, le=50),
    justification: str = Form(...),
):
    """Issue a new ephemeral capability lease."""
    lease_num = len(LEASES_STORE) + 902
    lease_id = f"LSE-{lease_num}"
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=ttl_minutes)

    token_payload = f"{lease_id}:{agent}:{scope}:{now.isoformat()}"
    token_hash = hashlib.sha256(token_payload.encode()).hexdigest()[:16]

    new_lease = {
        "id": lease_id,
        "agent": agent,
        "agent_model": "gpt-4o" if "DB" in agent else "claude-3-5-sonnet",
        "scope": scope,
        "scope_description": f"Authorized capability grant for {scope}",
        "granted_by": "Raghav (SecOps Lead)",
        "granted_at": now.isoformat(),
        "expires_at": expires_at.isoformat(),
        "ttl_minutes": ttl_minutes,
        "max_operations": max_operations,
        "operations_used": 0,
        "status": "ACTIVE",
        "risk_tier": "High" if "admin" in scope or "exec" in scope else "Elevated",
        "justification": justification,
        "hmac_token": f"aegis_sec_{token_hash}",
    }

    LEASES_STORE.insert(0, new_lease)

    if request.headers.get("HX-Request"):
        computed_leases = [_compute_lease_ttl(l) for l in LEASES_STORE]
        metrics = {
            "total": len(LEASES_STORE),
            "active_count": sum(l["status"] == "ACTIVE" for l in computed_leases),
            "expired_count": sum(l["status"] == "EXPIRED" for l in computed_leases),
            "revoked_count": sum(l["status"] == "REVOKED" for l in computed_leases),
            "total_ops_used": sum(l.get("operations_used", 0) for l in computed_leases),
        }
        return templates.TemplateResponse(
            request=request,
            name="components/leases_table_fragment.html",
            context={
                "request": request,
                "leases": computed_leases,
                "metrics": metrics,
                "selected_status": "all",
                "selected_agent": "all",
                "q": "",
                "demo_mode": True,
            },
        )

    return RedirectResponse(url="/leases", status_code=303)
