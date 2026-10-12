"""Integration tests for User Grants HTTP endpoints and UI workflows."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app
from warden.grants import (
    Grant,
    GrantStatus,
    InMemoryGrantsStore,
    ScopeRule,
    get_grants_store,
    set_grants_store,
)

client = TestClient(app)


@pytest.fixture(autouse=True)
def isolated_grants_store() -> None:
    """Ensure each test runs with a clean in-memory grants store."""
    store = InMemoryGrantsStore()
    set_grants_store(store)


def test_issue_grant_validation_ranges() -> None:
    # TTL below 5 minutes
    res_ttl_low = client.post("/grants", json={"thread_id": "thr_val", "ttl_minutes": 4})
    assert res_ttl_low.status_code == 422

    # TTL above 240 minutes
    res_ttl_high = client.post("/grants", json={"thread_id": "thr_val", "ttl_minutes": 241})
    assert res_ttl_high.status_code == 422

    # Max uses below 1
    res_uses_low = client.post("/grants", json={"thread_id": "thr_val", "max_uses": 0})
    assert res_uses_low.status_code == 422

    # Max uses above 50
    res_uses_high = client.post("/grants", json={"thread_id": "thr_val", "max_uses": 51})
    assert res_uses_high.status_code == 422

    # Missing thread_id
    res_no_thread = client.post("/grants", json={"ttl_minutes": 30, "max_uses": 5})
    assert res_no_thread.status_code == 422


def test_issue_grant_success_and_defaults() -> None:
    res = client.post(
        "/grants",
        json={
            "thread_id": "thr_ok",
            "tool": "batch_delete_files",
            "constraints": {"path_prefix": "/workspace/tmp/"},
            "reason": "Clean test scratch",
        },
        headers={"Warden-Key": "alice"},
    )
    assert res.status_code == 201
    data = res.json()
    assert data["thread_id"] == "thr_ok"
    assert data["granted_by"] == "alice"
    assert data["ttl_minutes"] == 30
    assert data["max_uses"] == 5
    assert data["uses"] == 0
    assert data["status"] == "active"
    assert len(data["scope"]) == 1
    assert data["scope"][0]["tool"] == "batch_delete_files"


def test_list_grants_and_thread_filtering() -> None:
    client.post("/grants", json={"thread_id": "thr_1", "tool": "send_email"})
    client.post("/grants", json={"thread_id": "thr_2", "tool": "restart_service"})

    # Filter thr_1
    res_1 = client.get("/grants?thread_id=thr_1")
    assert res_1.status_code == 200
    grants_1 = res_1.json()
    assert len(grants_1) == 1
    assert grants_1[0]["thread_id"] == "thr_1"

    # Filter thr_2
    res_2 = client.get("/grants?thread_id=thr_2")
    assert res_2.status_code == 200
    grants_2 = res_2.json()
    assert len(grants_2) == 1
    assert grants_2[0]["thread_id"] == "thr_2"


def test_revoke_grant_lifecycle_errors() -> None:
    # 404 on unknown ID
    res_404 = client.post("/grants/gr_unknown/revoke")
    assert res_404.status_code == 404

    # Create grant
    res_create = client.post("/grants", json={"thread_id": "thr_rev", "tool": "send_email"})
    grant_id = res_create.json()["id"]

    # First revoke succeeds
    res_rev = client.post(f"/grants/{grant_id}/revoke", headers={"Warden-Key": "security_admin"})
    assert res_rev.status_code == 200
    assert res_rev.json()["status"] == "revoked"

    # Second revoke returns 409 (already terminal)
    res_409 = client.post(f"/grants/{grant_id}/revoke")
    assert res_409.status_code == 409


def test_inbox_upgrade_grants_rest_of_task() -> None:
    # 1. Start a chat message that causes a gate escalation
    thread = "thr_inbox_upgrade"
    res_msg = client.post(
        "/chat/message",
        data={
            "message": "send the weekly report to ops-team@example.com",
            "agent_name": "OpsAssistant",
            "thread_id": thread,
        },
    )
    assert res_msg.status_code == 200
    html = res_msg.text
    assert "INTERCEPTION GATE ACTIVE" in html

    # Extract action ID
    import re
    match = re.search(r"Action ID:\s*(act_[a-f0-9]+)", html)
    assert match is not None
    action_id = match.group(1)

    # 2. Upgrade the parked action via Grant Rest of Task
    res_grant = client.post(
        f"/chat/actions/{action_id}/grant",
        data={"thread_id": thread, "ttl_minutes": "30", "max_uses": "5"},
        headers={"Warden-Key": "alice"},
    )
    assert res_grant.status_code == 200
    assert "TASK CAPABILITY GRANTED" in res_grant.text

    # 3. Verify grant was issued and consumed 1 use in GrantsStore
    store = get_grants_store()
    grants = store.list_for_thread(thread)
    assert len(grants) == 1
    assert grants[0].uses == 1
    assert grants[0].max_uses == 5


def test_revoke_then_act_reparks() -> None:
    # 1. Issue grant upfront
    thread = "thr_revoke_act"
    res_grant = client.post(
        "/grants",
        json={"thread_id": thread, "tool": "send_email", "ttl_minutes": 30, "max_uses": 5},
    )
    assert res_grant.status_code == 201
    grant_id = res_grant.json()["id"]

    # 2. Send email - auto-allowed under grant
    res_1 = client.post(
        "/chat/message",
        data={
            "message": "send the weekly report to ops-team@example.com",
            "agent_name": "OpsAssistant",
            "thread_id": thread,
        },
    )
    assert res_1.status_code == 200
    assert "INTERCEPTION GATE ACTIVE" not in res_1.text

    # 3. Revoke grant
    res_rev = client.post(f"/grants/{grant_id}/revoke")
    assert res_rev.status_code == 200

    # 4. Next email attempt - parks at gate because grant is revoked
    res_2 = client.post(
        "/chat/message",
        data={
            "message": "send the weekly report to ops-team@example.com",
            "agent_name": "OpsAssistant",
            "thread_id": thread,
        },
    )
    assert res_2.status_code == 200
    assert "INTERCEPTION GATE ACTIVE" in res_2.text


def test_task_start_form_upfront_grant() -> None:
    thread = "thr_upfront_form"
    res = client.post(
        "/chat/message",
        data={
            "message": "send the weekly report to ops-team@example.com",
            "agent_name": "OpsAssistant",
            "thread_id": thread,
            "attach_grant": "1",
            "grant_tool": "send_email",
            "grant_ttl": "45",
            "grant_uses": "3",
        },
        headers={"Warden-Key": "alice"},
    )
    assert res.status_code == 200
    # Because upfront grant was attached, action auto-allowed without parking!
    assert "INTERCEPTION GATE ACTIVE" not in res.text

    store = get_grants_store()
    grants = store.list_for_thread(thread)
    assert len(grants) == 1
    assert grants[0].granted_by == "alice"
    assert grants[0].ttl_seconds == 45 * 60
    assert grants[0].uses == 1
    assert grants[0].max_uses == 3


def test_inbox_upgrade_replay_and_range_guards() -> None:
    thread = "thr_inbox_guards"
    res_msg = client.post(
        "/chat/message",
        data={
            "message": "send the weekly report to ops-team@example.com",
            "agent_name": "OpsAssistant",
            "thread_id": thread,
        },
    )
    assert res_msg.status_code == 200
    import re
    match = re.search(r"Action ID:\s*(act_[a-f0-9]+)", res_msg.text)
    assert match is not None
    action_id = match.group(1)

    # Range validation on inbox upgrade
    res_bad_ttl = client.post(
        f"/chat/actions/{action_id}/grant",
        data={"thread_id": thread, "ttl_minutes": "4", "max_uses": "5"},
    )
    assert res_bad_ttl.status_code == 422

    # Successful upgrade
    res_ok = client.post(
        f"/chat/actions/{action_id}/grant",
        data={"thread_id": thread, "ttl_minutes": "30", "max_uses": "5"},
        headers={"Warden-Key": "alice"},
    )
    assert res_ok.status_code == 200

    # Replay protection: double clicking grant on already resolved action returns 409
    res_replay = client.post(
        f"/chat/actions/{action_id}/grant",
        data={"thread_id": thread, "ttl_minutes": "30", "max_uses": "5"},
    )
    assert res_replay.status_code == 409
