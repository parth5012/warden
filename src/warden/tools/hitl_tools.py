"""HITL escalation tools: ESCALATE -> Pending (no side effects here).

Lock 2: this module never calls interrupt(). It builds the GateRequest
preview; the graph node's re-entry helper parks via interrupt() and
CheckpointManager.resume() continues after a human decision.
Lock 8: approver identity is a named key checked at the HTTP layer.
"""

from __future__ import annotations

import re
from typing import Any

from warden.models import Action, GateRequest
from warden.tools.base import ToolContext, ToolSpec, make_action

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_KNOWN_SERVICES = ("api-gateway", "orders", "worker", "postgres_primary")

SEND_EMAIL_SPEC = ToolSpec(
    name="send_email",
    description="Outbound messaging — requires human approval.",
    payload_schema={"recipient": "email", "subject": "str<=200", "body": "str<=5000"},
    execution_path="hitl",
    triggers_rule=True,
)

RESTART_SERVICE_SPEC = ToolSpec(
    name="restart_service",
    description="Service mutation — requires human approval.",
    payload_schema={"service_name": "str", "grace_period_sec": "int 0..120"},
    execution_path="hitl",
    triggers_rule=True,
)

POL_EGRESS = "POL_EGRESS_EXTERNAL_MSG"
POL_INFRA = "POL_INFRA_MUTATION"


def validate_send_email(payload: dict[str, Any]) -> None:
    recipient = payload.get("recipient")
    subject = payload.get("subject")
    body = payload.get("body")
    if not isinstance(recipient, str) or not _EMAIL_RE.match(recipient):
        raise ValueError("invalid recipient email")
    if not isinstance(subject, str) or not subject.strip() or len(subject) > 200:
        raise ValueError("subject must be 1..200 chars")
    if not isinstance(body, str) or not body.strip() or len(body) > 5000:
        raise ValueError("body must be 1..5000 chars")


def validate_restart_service(payload: dict[str, Any]) -> None:
    service = payload.get("service_name")
    grace = payload.get("grace_period_sec", 10)
    if not isinstance(service, str) or not service.strip():
        raise ValueError("service_name must be non-empty")
    if service not in _KNOWN_SERVICES:
        raise ValueError(f"unknown service: {service!r}")
    if not isinstance(grace, int) or not 0 <= grace <= 120:
        raise ValueError("grace_period_sec must be int in 0..120")


def preview_gate_request(action: Action, rule_id: str, reason: str) -> GateRequest:
    return GateRequest(
        gate_id=f"gate-{action.id}",
        action=action,
        context={"rule_id": rule_id, "reason": reason},
    )


async def run_send_email(payload: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    """No SMTP. Returns pending-preview for the graph node to park on."""
    validate_send_email(payload)
    action = make_action(SEND_EMAIL_SPEC, payload, ctx)
    gate = preview_gate_request(action, POL_EGRESS, "External egress requires human approval")
    return {
        "status": "pending",
        "gate_id": gate.gate_id,
        "gate_rule": POL_EGRESS,
        "message": "Requires human approval — park via run_gated/interrupt in graph node",
    }


async def run_restart_service(payload: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    validate_restart_service(payload)
    action = make_action(RESTART_SERVICE_SPEC, payload, ctx)
    gate = preview_gate_request(action, POL_INFRA, "Infrastructure mutation requires human approval")
    return {
        "status": "pending",
        "gate_id": gate.gate_id,
        "gate_rule": POL_INFRA,
        "message": "Requires human approval — park via run_gated/interrupt in graph node",
    }


__all__ = [
    "POL_EGRESS",
    "POL_INFRA",
    "RESTART_SERVICE_SPEC",
    "SEND_EMAIL_SPEC",
    "preview_gate_request",
    "run_restart_service",
    "run_send_email",
    "validate_restart_service",
    "validate_send_email",
]
