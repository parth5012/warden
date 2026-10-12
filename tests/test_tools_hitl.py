"""HITL tools: pending previews, no side effects."""

from __future__ import annotations

import pytest

from warden.models import ActionKind
from warden.tools.base import ToolContext, make_action
from warden.tools.hitl_tools import (
    POL_EGRESS,
    POL_INFRA,
    SEND_EMAIL_SPEC,
    preview_gate_request,
    run_restart_service,
    run_send_email,
)

CTX = ToolContext(run_id="run_h", thread_id="thr_h")


async def test_send_email_pending_rule() -> None:
    out = await run_send_email(
        {"recipient": "ops-team@example.com", "subject": "Incident", "body": "hello"}, CTX
    )
    assert out["status"] == "pending" and out["gate_rule"] == POL_EGRESS


async def test_send_email_bad_address() -> None:
    with pytest.raises(ValueError):
        await run_send_email({"recipient": "not-an-email", "subject": "s", "body": "b"}, CTX)


async def test_restart_pending_rule() -> None:
    out = await run_restart_service({"service_name": "postgres_primary", "grace_period_sec": 10}, CTX)
    assert out["status"] == "pending" and out["gate_rule"] == POL_INFRA


async def test_restart_grace_range() -> None:
    with pytest.raises(ValueError):
        await run_restart_service({"service_name": "orders", "grace_period_sec": 999}, CTX)


def test_gate_request_carries_action() -> None:
    action = make_action(
        SEND_EMAIL_SPEC,
        {"recipient": "a@b.co", "subject": "s", "body": "b"},
        CTX,
    )
    gate = preview_gate_request(action, POL_EGRESS, "reason")
    assert gate.action.id == action.id and action.kind == ActionKind.TOOL


async def test_no_side_effect_markers() -> None:
    out = await run_send_email({"recipient": "a@b.co", "subject": "s", "body": "b"}, CTX)
    assert "park via run_gated" in out["message"]
