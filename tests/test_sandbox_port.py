"""Tests for SandboxPort interface and related types.

Validates:
A. SandboxResult is frozen (mutation raises dataclasses.FrozenInstanceError).
B. SandboxResult fields: ok (bool), exit_code (int | None), stdout (str),
   stderr (str), timed_out (bool), duration_ms (int), profile (str).
C. SandboxPort runtime_checkable Protocol with async def run(self, action: Action) -> SandboxResult.
   Dummy class implementing run satisfies isinstance(dummy, SandboxPort).
D. SandboxUnavailable is an Exception subclass, catchable as Exception.
E. OUTPUT_CAP_BYTES is 64 * 1024 in port.py.
F. __init__.py re-exports SandboxPort, SandboxResult, SandboxUnavailable,
   without DockerSandbox.
"""

from __future__ import annotations

import dataclasses

import pytest

import warden.sandbox
from warden.models import Action, ActionKind
from warden.sandbox import (
    SandboxPort,
    SandboxResult,
    SandboxUnavailable,
)
from warden.sandbox.port import OUTPUT_CAP_BYTES


def test_sandbox_result_frozen() -> None:
    """SandboxResult must be frozen: mutating any field raises FrozenInstanceError."""
    result = SandboxResult(
        ok=True,
        exit_code=0,
        stdout="hello",
        stderr="",
        timed_out=False,
        duration_ms=12,
        profile="subprocess",
    )

    with pytest.raises(dataclasses.FrozenInstanceError):
        result.ok = False  # type: ignore[misc]

    with pytest.raises(dataclasses.FrozenInstanceError):
        result.exit_code = 1  # type: ignore[misc]

    with pytest.raises(dataclasses.FrozenInstanceError):
        result.stdout = "modified"  # type: ignore[misc]

    with pytest.raises(dataclasses.FrozenInstanceError):
        result.stderr = "error"  # type: ignore[misc]

    with pytest.raises(dataclasses.FrozenInstanceError):
        result.timed_out = True  # type: ignore[misc]

    with pytest.raises(dataclasses.FrozenInstanceError):
        result.duration_ms = 99  # type: ignore[misc]

    with pytest.raises(dataclasses.FrozenInstanceError):
        result.profile = "other"  # type: ignore[misc]

    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(result, "ok", False)


def test_sandbox_result_fields() -> None:
    """SandboxResult must expose ok, exit_code, stdout, stderr, timed_out, duration_ms, profile."""
    # Standard success result with integer exit code
    success = SandboxResult(
        ok=True,
        exit_code=0,
        stdout="standard out",
        stderr="",
        timed_out=False,
        duration_ms=45,
        profile="subprocess",
    )
    assert success.ok is True
    assert isinstance(success.ok, bool)
    assert success.exit_code == 0
    assert isinstance(success.exit_code, int)
    assert success.stdout == "standard out"
    assert isinstance(success.stdout, str)
    assert success.stderr == ""
    assert isinstance(success.stderr, str)
    assert success.timed_out is False
    assert isinstance(success.timed_out, bool)
    assert success.duration_ms == 45
    assert isinstance(success.duration_ms, int)
    assert success.profile == "subprocess"
    assert isinstance(success.profile, str)

    # Failure / timed-out result where exit_code is None
    timed_out_result = SandboxResult(
        ok=False,
        exit_code=None,
        stdout="",
        stderr="Process killed after timeout",
        timed_out=True,
        duration_ms=5000,
        profile="restricted",
    )
    assert timed_out_result.ok is False
    assert timed_out_result.exit_code is None
    assert timed_out_result.timed_out is True
    assert timed_out_result.duration_ms == 5000
    assert timed_out_result.profile == "restricted"


async def test_sandbox_port_protocol_and_runtime_checkable() -> None:
    """SandboxPort must be a runtime_checkable Protocol with async def run(self, action: Action) -> SandboxResult."""

    class DummySandbox:
        """Dummy sandbox conforming to SandboxPort Protocol."""

        async def run(self, action: Action) -> SandboxResult:
            return SandboxResult(
                ok=True,
                exit_code=0,
                stdout=f"executed {action.name}",
                stderr="",
                timed_out=False,
                duration_ms=10,
                profile="dummy",
            )

    dummy = DummySandbox()
    assert isinstance(dummy, SandboxPort)

    action = Action(
        id="act-test-01",
        kind=ActionKind.TOOL,
        name="test_tool",
        payload={"arg": "val"},
        run_id="run-test-01",
        thread_id="th-test-01",
    )
    result = await dummy.run(action)
    assert isinstance(result, SandboxResult)
    assert result.ok is True
    assert result.stdout == "executed test_tool"

    class IncompleteSandbox:
        """Does not implement run."""

        pass

    assert not isinstance(IncompleteSandbox(), SandboxPort)


def test_sandbox_unavailable_exception() -> None:
    """SandboxUnavailable must be an Exception subclass and catchable as Exception."""
    assert issubclass(SandboxUnavailable, Exception)

    with pytest.raises(Exception) as exc_info:
        raise SandboxUnavailable("Sandbox environment not reachable")

    assert isinstance(exc_info.value, SandboxUnavailable)
    assert "Sandbox environment not reachable" in str(exc_info.value)


def test_output_cap_bytes() -> None:
    """OUTPUT_CAP_BYTES in port.py must equal 64 * 1024."""
    assert OUTPUT_CAP_BYTES == 64 * 1024
    assert isinstance(OUTPUT_CAP_BYTES, int)


def test_init_reexports() -> None:
    """__init__.py must re-export SandboxPort, SandboxResult, SandboxUnavailable, and DockerSandbox."""
    assert hasattr(warden.sandbox, "SandboxPort")
    assert hasattr(warden.sandbox, "SandboxResult")
    assert hasattr(warden.sandbox, "SandboxUnavailable")
    assert hasattr(warden.sandbox, "DockerSandbox")
    assert "SandboxPort" in warden.sandbox.__all__
    assert "SandboxResult" in warden.sandbox.__all__
    assert "SandboxUnavailable" in warden.sandbox.__all__
    assert "DockerSandbox" in warden.sandbox.__all__
