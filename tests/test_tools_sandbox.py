"""Sandbox shell tool: registry mapping + fail-closed (fake sandbox, no Docker)."""

from __future__ import annotations

import pytest

from warden.models import Action
from warden.sandbox.port import SandboxResult
from warden.sandbox.port import SandboxUnavailable
from warden.tools.base import ToolContext
from warden.tools.sandbox_tools import IN_PROCESS_ROUTING, run_shell, to_action

CTX = ToolContext(run_id="run_s", thread_id="thr_s")


class FakeSandbox:
    async def run(self, action: Action) -> SandboxResult:
        assert action.name == "shell"
        return SandboxResult(
            ok=True, exit_code=0, stdout="ok", stderr="",
            timed_out=False, duration_ms=5, profile="fake",
        )


class DownSandbox:
    async def run(self, action: Action) -> SandboxResult:
        raise SandboxUnavailable("daemon down")


def test_registry_mapping_shell() -> None:
    action = to_action({"command": "echo hi"}, CTX)
    assert action.name == "shell"


def test_empty_command_rejected() -> None:
    with pytest.raises(ValueError):
        to_action({"command": "   "}, CTX)


def test_overlong_rejected() -> None:
    with pytest.raises(ValueError):
        to_action({"command": "x" * 4001}, CTX)


async def test_fake_sandbox_ok() -> None:
    out = await run_shell({"command": "echo hi"}, CTX, sandbox=FakeSandbox())
    assert isinstance(out, SandboxResult) and out.ok


async def test_sandbox_down_fail_closed() -> None:
    out = await run_shell({"command": "echo hi"}, CTX, sandbox=DownSandbox())
    assert isinstance(out, dict) and out["reason"] == "governance_unavailable"


def test_routing_table() -> None:
    assert IN_PROCESS_ROUTING["exec_shell"] == "docker-sandbox"
    assert IN_PROCESS_ROUTING["get_system_metrics"] == "in-process"
