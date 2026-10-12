"""Tests for Login Decorators (@audit_login, @login_required) and WAL persistence."""

from __future__ import annotations

import asyncio
from typing import Any, Dict
import pytest
from starlette.testclient import TestClient

from app.main import app
from app.audit import JOURNAL_STORE
from warden.wrappers import (
    audit_context,
    audit_login,
    get_current_audit_context,
    login_audit,
    login_required,
    record_login_audit_db,
    redact_sensitive_data,
    require_login,
)


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


# ==============================================================================
# 1. ASYNC & SYNC @audit_login DECORATOR TESTS
# ==============================================================================

@pytest.mark.asyncio
async def test_async_audit_login_success() -> None:
    """Verifies that @audit_login logs write-ahead and success events to WAL."""
    initial_count = len(JOURNAL_STORE._events)

    @audit_login(auth_method="password", actor_arg="username")
    async def authenticate(username: str, password: str, client_ip: str | None = None) -> Dict[str, Any]:
        await asyncio.sleep(0.01)
        if password == "valid_pass_123":
            return {"authenticated": True, "user": username}
        raise PermissionError("Bad credentials")

    res = await authenticate(username="alice_operator", password="valid_pass_123", client_ip="192.168.1.50")
    assert res["authenticated"] is True
    assert res["user"] == "alice_operator"

    # Verify write-ahead start event and completed event were logged in WAL
    new_count = len(JOURNAL_STORE._events)
    assert new_count == initial_count + 2

    start_ev = JOURNAL_STORE._events[-2]
    complete_ev = JOURNAL_STORE._events[-1]

    assert start_ev.kind == "action_requested"
    assert start_ev.actor == "alice_operator"
    assert start_ev.status == "Proposed"
    assert start_ev.payload.get("operation") == "USER_LOGIN"
    assert start_ev.payload.get("auth_method") == "password"
    assert start_ev.payload.get("ip_address") == "192.168.1.50"
    # Ensure sensitive password was scrubbed from payload
    assert "valid_pass_123" not in str(start_ev.payload)

    assert complete_ev.kind == "action_completed"
    assert complete_ev.actor == "alice_operator"
    assert complete_ev.status == "Succeeded"
    assert "succeeded" in complete_ev.description.lower()


@pytest.mark.asyncio
async def test_async_audit_login_failure_scrubs_secrets() -> None:
    """Verifies that failed logins record denial events without leaking password."""
    initial_count = len(JOURNAL_STORE._events)

    @audit_login(auth_method="token", actor_arg="user")
    async def check_token(user: str, token: str) -> bool:
        if token != "correct_secret_token":
            raise ValueError("Token signature verification failed")
        return True

    with pytest.raises(ValueError, match="Token signature verification failed"):
        await check_token(user="attacker_bob", token="leaked_super_secret_password")

    # Start event and failure event both logged to WAL
    new_count = len(JOURNAL_STORE._events)
    assert new_count == initial_count + 2

    start_ev = JOURNAL_STORE._events[-2]
    fail_ev = JOURNAL_STORE._events[-1]

    assert start_ev.actor == "attacker_bob"
    assert "leaked_super_secret_password" not in str(start_ev.payload)

    assert fail_ev.kind == "action_denied"
    assert fail_ev.status == "Denied"
    assert fail_ev.actor == "attacker_bob"
    assert "Token signature verification failed" in fail_ev.description


def test_sync_audit_login() -> None:
    """Verifies synchronous function decoration with @audit_login."""
    initial_count = len(JOURNAL_STORE._events)

    @audit_login(auth_method="named_key", actor_arg="key_name")
    def sync_login(key_name: str, secret: str) -> str:
        if secret == "valid_sec":
            return "session_token_xyz"
        raise PermissionError("Invalid key secret")

    token = sync_login(key_name="approver_charlie", secret="valid_sec")
    assert token == "session_token_xyz"

    new_count = len(JOURNAL_STORE._events)
    assert new_count == initial_count + 2

    start_ev = JOURNAL_STORE._events[-2]
    complete_ev = JOURNAL_STORE._events[-1]
    assert start_ev.actor == "approver_charlie"
    assert complete_ev.actor == "approver_charlie"
    assert complete_ev.status == "Succeeded"


# ==============================================================================
# 2. @login_required DECORATOR TESTS
# ==============================================================================

def test_login_required_allows_valid_approver_key() -> None:
    """Verifies @login_required passes for valid key and sets audit_context."""
    @login_required()
    def protected_action(warden_key: str | None = None) -> Dict[str, Any]:
        ctx = get_current_audit_context()
        return {"status": "ok", "actor": ctx.get("actor")}

    # Default configured approver key in .env: admin:aegis-secret-key-123
    result = protected_action(warden_key="aegis-secret-key-123")
    assert result["status"] == "ok"
    assert result["actor"] == "admin"


def test_login_required_rejects_missing_key() -> None:
    """Verifies @login_required rejects unauthenticated callers and logs denial to WAL."""
    initial_count = len(JOURNAL_STORE._events)

    @login_required()
    def restricted_resource(warden_key: str | None = None) -> str:
        return "sensitive_data"

    with pytest.raises(Exception):
        restricted_resource(warden_key=None)

    # Should have logged action_denied to WAL
    new_count = len(JOURNAL_STORE._events)
    assert new_count == initial_count + 1
    denied_ev = JOURNAL_STORE._events[-1]
    assert denied_ev.kind == "action_denied"
    assert denied_ev.status == "Denied"


# ==============================================================================
# 3. HTTP ENDPOINT INTEGRATION TESTS (/api/auth/login, /api/auth/audit, /api/auth/me)
# ==============================================================================

def test_http_login_endpoint_success(client: TestClient) -> None:
    """Tests POST /api/auth/login with valid named approver key."""
    resp = client.post("/api/auth/login", json={
        "username": "admin",
        "warden_key": "aegis-secret-key-123"
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "authenticated"
    assert data["username"] == "admin"
    assert "token" in data


def test_http_login_endpoint_failure(client: TestClient) -> None:
    """Tests POST /api/auth/login with invalid credentials returns 401."""
    resp = client.post("/api/auth/login", json={
        "username": "intruder",
        "password": "wrong_password_999"
    })
    assert resp.status_code == 401
    assert "Invalid username" in resp.json()["detail"]


def test_http_auth_me_protected_route(client: TestClient) -> None:
    """Tests GET /api/auth/me protected by @login_required."""
    # Without header -> 401
    fail_resp = client.get("/api/auth/me")
    assert fail_resp.status_code == 401

    # With valid Warden-Key header -> 200
    ok_resp = client.get("/api/auth/me", headers={"Warden-Key": "aegis-secret-key-123"})
    assert ok_resp.status_code == 200
    data = ok_resp.json()
    assert data["status"] == "active"
    assert data["actor"] == "admin"


def test_http_login_audit_trail(client: TestClient) -> None:
    """Tests GET /api/auth/audit returns recorded authentication history."""
    resp = client.get("/api/auth/audit")
    assert resp.status_code == 200
    data = resp.json()
    assert "login_audit_records" in data
    assert "count" in data
    assert isinstance(data["login_audit_records"], list)
