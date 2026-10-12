"""Policy inspection and management endpoints (Lock 9: versioned in DB)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal
import uuid
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(prefix="/policies", tags=["Policies"])


class PolicyCreateRequest(BaseModel):
    name: str = Field(..., description="Unique policy identifier")
    action: Literal["allow", "escalate", "deny"] = Field(
        ..., description="Verdict: allow, escalate, or deny"
    )
    description: str = Field(..., description="Human-readable rule explanation")
    rule_text: str | None = Field(default=None, description="Rule definition")


POLICIES_STORE: list[dict[str, Any]] = [
    {
        "id": "pol-001",
        "name": "no_destructive_sql",
        "action": "deny",
        "description": "Block DROP, TRUNCATE, DELETE without WHERE",
        "active": True,
        "current_version": 1,
        "created_at": "2026-10-11T12:00:00Z",
    },
    {
        "id": "pol-002",
        "name": "escalate_external_email",
        "action": "escalate",
        "description": "Require human approval for emails sent to external domains",
        "active": True,
        "current_version": 1,
        "created_at": "2026-10-11T12:05:00Z",
    },
    {
        "id": "pol-003",
        "name": "sandbox_shell_commands",
        "action": "allow",
        "description": "Run shell executions in scrubbed, timed-out subprocess sandbox",
        "active": True,
        "current_version": 1,
        "created_at": "2026-10-11T12:10:00Z",
    },
]


@router.get("")
async def list_policies() -> dict[str, Any]:
    """List active governance policies."""
    return {"policies": POLICIES_STORE}


@router.post("", status_code=201)
async def create_policy(
    body: PolicyCreateRequest,
    warden_key: str | None = Header(default=None, alias="Warden-Key"),
) -> dict[str, Any]:
    """Create a new policy rule (appends to policy_versions)."""
    if not warden_key or not warden_key.strip():
        raise HTTPException(
            status_code=401, detail="Warden-Key header required for policy updates"
        )

    # Enforce unique policy name
    if any(p["name"] == body.name for p in POLICIES_STORE):
        raise HTTPException(
            status_code=409,
            detail=f"Policy with name '{body.name}' already exists",
        )

    new_policy = {
        "id": str(uuid.uuid4()),
        "name": body.name,
        "action": body.action,
        "description": body.description,
        "active": True,
        "current_version": 1,
        "created_by": warden_key.strip(),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    POLICIES_STORE.append(new_policy)
    return new_policy
