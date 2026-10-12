"""Unit tests for Aegis Logging & Audit Wrapper Decorators."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict
import pytest
from app.audit import JOURNAL_STORE
from warden.wrappers import (
    audit_context,
    audit_logged,
    get_current_audit_context,
    redact_sensitive_data,
    structured_log,
)


# ==============================================================================
# 1. SECRET & CREDENTIAL REDACTION TESTS
# ==============================================================================

def test_redact_sensitive_keys_in_dictionary() -> None:
    data = {
        "user": "alice",
        "api_key": "sk-proj-1234567890",
        "token": "ghp_abcdef123456",
        "password": "SuperSecretPassword123!",
        "auth_token": "Bearer xyz",
        "nested": {
            "private_key": "-----BEGIN RSA PRIVATE KEY-----",
            "safe_param": "regular_value",
        },
    }
    cleaned = redact_sensitive_data(data)
    assert cleaned["user"] == "alice"
    assert cleaned["api_key"] == "***REDACTED***"
    assert cleaned["token"] == "***REDACTED***"
    assert cleaned["password"] == "***REDACTED***"
    assert cleaned["auth_token"] == "***REDACTED***"
    assert cleaned["nested"]["private_key"] == "***REDACTED***"
    assert cleaned["nested"]["safe_param"] == "regular_value"


def test_redact_sensitive_url_passwords() -> None:
    db_url = "postgresql://user:mypassword123@db.prod.internal:5432/warden"
    cleaned = redact_sensitive_data(db_url)
    assert "mypassword123" not in cleaned
    assert "postgresql://user:***@db.prod.internal:5432/warden" == cleaned


# ==============================================================================
# 2. CONTEXTVARS AUDIT CONTEXT TESTS
# ==============================================================================

@pytest.mark.asyncio
async def test_audit_context_scoping() -> None:
    assert get_current_audit_context()["run_id"] == "run_system"

    with audit_context(run_id="run_test_42", actor="TestAgent", action_id="act_42"):
        ctx = get_current_audit_context()
        assert ctx["run_id"] == "run_test_42"
        assert ctx["actor"] == "TestAgent"
        assert ctx["action_id"] == "act_42"

    # Context resets cleanly upon exit
    assert get_current_audit_context()["run_id"] == "run_system"


# ==============================================================================
# 3. STRUCTURED LOGGING DECORATOR (@structured_log) TESTS
# ==============================================================================

def test_sync_structured_log(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO)

    @structured_log(name="test_sync_op")
    def sync_worker(x: int, token: str) -> int:
        return x * 2

    res = sync_worker(5, token="secret_token_val")
    assert res == 10

    records = [r for r in caplog.records if "test_sync_op" in r.message]
    assert len(records) >= 2  # started and completed
    assert any("test_sync_op.started" in r.message for r in records)
    assert any("test_sync_op.completed" in r.message for r in records)


@pytest.mark.asyncio
async def test_async_structured_log(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO)

    @structured_log(name="test_async_op")
    async def async_worker(msg: str) -> str:
        await asyncio.sleep(0.01)
        return msg.upper()

    res = await async_worker("hello")
    assert res == "HELLO"

    records = [r for r in caplog.records if "test_async_op" in r.message]
    assert any("test_async_op.started" in r.message for r in records)
    assert any("test_async_op.completed" in r.message for r in records)


def test_structured_log_exception_propagation(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO)

    @structured_log(name="failing_op")
    def failing_fn() -> None:
        raise ValueError("Simulated operational failure")

    with pytest.raises(ValueError, match="Simulated operational failure"):
        failing_fn()

    errors = [r for r in caplog.records if r.levelno == logging.ERROR and "failing_op.failed" in r.message]
    assert len(errors) == 1
    assert "Simulated operational failure" in str(errors[0].__dict__.get("error", "")) or "Simulated operational failure" in errors[0].message


# ==============================================================================
# 4. AUDIT JOURNAL DECORATOR (@audit_logged) TESTS
# ==============================================================================

@pytest.mark.asyncio
async def test_audit_logged_writes_ahead_and_completes() -> None:
    initial_count = len(JOURNAL_STORE._events)

    @audit_logged(
        kind_start="execution_started",
        kind_success="action_completed",
        actor="SandboxAgent",
        description="Run test sandbox execution",
    )
    async def execute_task(action_id: str, command: str) -> Dict[str, Any]:
        await asyncio.sleep(0.01)
        return {"output": f"Executed {command}", "exit_code": 0}

    with audit_context(run_id="run_sandbox_1", thread_id="thread_sb_1"):
        result = await execute_task(action_id="act_test_99", command="ls -la")

    assert result["exit_code"] == 0

    # Verify that both the write-ahead event and completion event were appended
    new_count = len(JOURNAL_STORE._events)
    assert new_count == initial_count + 2

    start_event = JOURNAL_STORE._events[-2]
    complete_event = JOURNAL_STORE._events[-1]

    assert start_event.kind == "execution_started"
    assert start_event.action_id == "act_test_99"
    assert start_event.run_id == "run_sandbox_1"
    assert start_event.actor == "SandboxAgent"

    assert complete_event.kind == "action_completed"
    assert complete_event.action_id == "act_test_99"
    assert complete_event.status == "Succeeded"
    assert "completed in" in complete_event.description


@pytest.mark.asyncio
async def test_audit_logged_records_failure_event() -> None:
    initial_count = len(JOURNAL_STORE._events)

    @audit_logged(
        kind_start="action_requested",
        kind_error="action_failed",
        actor="FailingAgent",
        description="Attempt prohibited tool",
    )
    async def faulty_task(action_id: str) -> None:
        raise PermissionError("Access denied by sandbox security monitor")

    with pytest.raises(PermissionError):
        with audit_context(run_id="run_fail_1"):
            await faulty_task(action_id="act_fail_01")

    # Both start and failure event should be recorded in journal
    new_count = len(JOURNAL_STORE._events)
    assert new_count == initial_count + 2

    start_event = JOURNAL_STORE._events[-2]
    fail_event = JOURNAL_STORE._events[-1]

    assert start_event.kind == "action_requested"
    assert fail_event.kind == "action_failed"
    assert fail_event.status == "Failed"
    assert "PermissionError" in fail_event.description
