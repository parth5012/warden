"""Tests for backend REST API endpoints and frontend Jinja/HTMX views."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from backend.main import create_app

client = TestClient(create_app())


# ---------------------------------------------------------------------------
# Backend REST API Tests
# ---------------------------------------------------------------------------


def test_api_health() -> None:
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}


def test_api_ready() -> None:
    res = client.get("/ready")
    assert res.status_code in (200, 503)
    data = res.json()
    assert "ready" in data
    assert "checkpoint_store" in data


def test_api_inbox_list_and_resolve() -> None:
    # List pending gates
    res = client.get("/api/inbox")
    assert res.status_code == 200
    gates = res.json().get("pending_gates", [])
    assert isinstance(gates, list)

    # Test resolving nonexistent gate
    res_404 = client.post("/api/inbox/nonexistent-gate/resolve", json={"decision": "deny"})
    assert res_404.status_code == 404

    # Resolve an existing gate if present
    if gates:
        gate_id = gates[0]["id"]

        # Test invalid decision -> 400
        res_invalid = client.post(
            f"/api/inbox/{gate_id}/resolve",
            json={"decision": "maybe"},
            headers={"Warden-Key": "alice"},
        )
        assert res_invalid.status_code == 400

        # Valid approve -> 200
        res_resolve = client.post(
            f"/api/inbox/{gate_id}/resolve",
            json={"decision": "approve"},
            headers={"Warden-Key": "alice"},
        )
        assert res_resolve.status_code == 200
        assert res_resolve.json()["status"] == "resolved"
        assert res_resolve.json()["approver"] == "alice"


def test_api_runs_and_graph() -> None:
    res = client.get("/api/runs")
    assert res.status_code == 200
    runs = res.json().get("runs", [])
    assert len(runs) >= 1

    thread_id = runs[0]["thread_id"]
    res_detail = client.get(f"/api/runs/{thread_id}")
    assert res_detail.status_code == 200
    assert res_detail.json()["thread_id"] == thread_id

    res_graph = client.get(f"/api/runs/{thread_id}/graph")
    assert res_graph.status_code == 200
    assert "nodes" in res_graph.json()
    assert "edges" in res_graph.json()


def test_api_audit_and_search() -> None:
    res = client.get("/api/audit")
    assert res.status_code == 200
    data = res.json()
    assert "events" in data
    assert data["total"] >= 1

    # Search filter
    res_search = client.get("/api/audit?q=send_email")
    assert res_search.status_code == 200
    for evt in res_search.json()["events"]:
        assert "send_email" in str(evt).lower()

    # Out of range limit validation
    res_bad_limit = client.get("/api/audit?limit=0")
    assert res_bad_limit.status_code == 422


def test_api_telemetry() -> None:
    res = client.get("/api/telemetry")
    assert res.status_code == 200
    data = res.json()
    assert "actions_total" in data
    assert "tokens_total" in data
    assert "estimated_cost_usd" in data


def test_api_policies_crud() -> None:
    res = client.get("/api/policies")
    assert res.status_code == 200
    assert "policies" in res.json()

    # Create without key -> 401
    res_unauth = client.post(
        "/api/policies",
        json={"name": "test_unique_rule", "action": "deny", "description": "test"},
    )
    assert res_unauth.status_code == 401

    # Create with key -> 201
    res_created = client.post(
        "/api/policies",
        json={"name": "test_unique_rule", "action": "deny", "description": "test rule"},
        headers={"Warden-Key": "alice"},
    )
    assert res_created.status_code == 201
    assert res_created.json()["name"] == "test_unique_rule"
    assert res_created.json()["created_by"] == "alice"

    # Duplicate creation -> 409
    res_dup = client.post(
        "/api/policies",
        json={"name": "test_unique_rule", "action": "deny", "description": "duplicate"},
        headers={"Warden-Key": "alice"},
    )
    assert res_dup.status_code == 409


# ---------------------------------------------------------------------------
# Frontend Views HTML Tests
# ---------------------------------------------------------------------------


def test_frontend_dashboard_view() -> None:
    res = client.get("/")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "Operator Dashboard" in res.text
    assert "Warden" in res.text


def test_frontend_inbox_view() -> None:
    res = client.get("/inbox")
    assert res.status_code == 200
    assert "Operator Approval Inbox" in res.text


def test_frontend_runs_and_detail_view() -> None:
    res = client.get("/runs")
    assert res.status_code == 200
    assert "Agent Execution Runs" in res.text

    res_detail = client.get("/runs/test-thread-detail")
    assert res_detail.status_code == 200
    assert "test-thread-detail" in res_detail.text


def test_frontend_audit_view() -> None:
    res = client.get("/audit")
    assert res.status_code == 200
    assert "Audit Journal Explorer" in res.text


def test_frontend_policies_view() -> None:
    res = client.get("/policies")
    assert res.status_code == 200
    assert "Governance Policies" in res.text


def test_frontend_static_css() -> None:
    res = client.get("/static/css/warden.css")
    assert res.status_code == 200
    assert "var(--bg-primary)" in res.text
