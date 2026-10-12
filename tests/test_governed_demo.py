"""Tests for the governed demo runner (offline: fake LLM + fake sandbox)."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from governed_demo import (  # noqa: E402
    GovernedRunner,
    LiveJournal,
    auto_approver,
    db_researcher,
    ops_assistant,
)
from app.audit import VerificationStatus  # noqa: E402
from warden.llm.types import LLMRequest  # noqa: E402
from warden.models import Allowed, Denied, Pending  # noqa: E402
from warden.sandbox.port import SandboxResult  # noqa: E402


async def fake_llm(req: LLMRequest) -> dict[str, str]:
    return {"content": "stub-draft"}


def make_runner(monkeypatch: pytest.MonkeyPatch, **kwargs: Any) -> GovernedRunner:
    journal = LiveJournal()
    runner = GovernedRunner(journal=journal, llm_provider=fake_llm, **kwargs)
    async def fake_shell(payload: dict[str, Any], ctx: Any) -> SandboxResult:
        return SandboxResult(ok=True, exit_code=0, stdout="stubbed", stderr="",
                             timed_out=False, duration_ms=1, profile="fake")
    monkeypatch.setattr("warden.tools.sandbox_tools.run_shell", fake_shell)
    # Route exec_shell through the fake by patching DockerSandbox
    class FakeDocker:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass
        async def run(self, action: Any) -> SandboxResult:
            return SandboxResult(ok=True, exit_code=0, stdout="stubbed", stderr="",
                                 timed_out=False, duration_ms=1, profile="fake")
    monkeypatch.setattr("governed_demo.DockerSandbox", FakeDocker)
    return runner


async def test_safe_tool_allowed_and_journaled(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = make_runner(monkeypatch)
    out = await runner.run_tool(agent="a", run_id="r", thread_id="t",
                                tool="get_system_metrics",
                                payload={"service": "orders", "metric": "cpu"})
    assert isinstance(out, Allowed)
    kinds = [e.kind for e in runner.journal.events]
    assert kinds == ["action_requested", "policy_evaluated", "execution_started", "action_completed"]
    assert runner.journal.verify()[0] == VerificationStatus.VERIFIED


async def test_drop_table_denied_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = make_runner(monkeypatch)
    out = await runner.run_tool(agent="a", run_id="r", thread_id="t",
                                tool="exec_db_mutation", payload={"sql": "DROP TABLE users;"})
    assert isinstance(out, Denied)
    kinds = [e.kind for e in runner.journal.events]
    assert "action_denied" in kinds and "gate_requested" not in kinds


async def test_hitl_approve_executes(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = make_runner(monkeypatch, approve=auto_approver("alice"))
    out = await runner.run_tool(agent="a", run_id="r", thread_id="t", tool="send_email",
                                payload={"recipient": "a@b.co", "subject": "s", "body": "b"})
    assert isinstance(out, Allowed)
    kinds = [e.kind for e in runner.journal.events]
    assert "gate_requested" in kinds and "gate_decided" in kinds


async def test_hitl_without_approver_parks(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = make_runner(monkeypatch, approve=None)
    out = await runner.run_tool(agent="a", run_id="r", thread_id="t", tool="send_email",
                                payload={"recipient": "a@b.co", "subject": "s", "body": "b"})
    assert isinstance(out, Pending)


async def test_llm_goes_through_seam(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = make_runner(monkeypatch)
    out = await runner.run_llm(agent="a", run_id="r", thread_id="t", prompt="hello")
    assert isinstance(out, Allowed) and out.result == "stub-draft"
    assert runner.telemetry["a"].llm_calls == 1


async def test_two_agents_share_journal(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = make_runner(monkeypatch, approve=auto_approver("alice"))
    await ops_assistant(runner, "run_multi")
    await db_researcher(runner, "run_multi")
    agents = {e.actor for e in runner.journal.events} & {"ops-assistant", "db-researcher"}
    assert agents == {"ops-assistant", "db-researcher"}
    assert runner.journal.verify()[0] == VerificationStatus.VERIFIED
    assert runner.telemetry["ops-assistant"].denied == 1
    assert runner.telemetry["db-researcher"].denied == 1
