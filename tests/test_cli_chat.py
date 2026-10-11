"""Tests for the CLI resume-prompt decision loop (cli_chat.py)."""

from __future__ import annotations

import builtins
from typing import Any
from unittest.mock import AsyncMock

import pytest
from _pytest.monkeypatch import MonkeyPatch

from tests import cli_chat


def _patch_input(monkeypatch: MonkeyPatch, side_effect: list[Any]) -> list[str]:
    calls: list[str] = []

    def fake_input(prompt: str) -> str:
        calls.append(prompt)
        item = side_effect.pop(0)
        if isinstance(item, Exception):
            raise item
        return str(item)

    monkeypatch.setattr(builtins, "input", fake_input)
    return calls


async def test_quit_at_resume_prompt_leaves_parked(monkeypatch: MonkeyPatch) -> None:
    """/quit at the resume prompt must abort cleanly, NOT become a decision."""
    _patch_input(monkeypatch, ["/quit"])
    spy = AsyncMock(return_value={})  # would return True if wrongly called
    monkeypatch.setattr(cli_chat, "_resume_and_render", spy)

    result = await cli_chat._prompt_for_resume(None, {}, None)  # type: ignore[arg-type]

    assert result is False
    spy.assert_not_awaited()


async def test_empty_input_reprompts(monkeypatch: MonkeyPatch) -> None:
    """Empty decision re-prompts (stays in the loop) until EOF aborts."""
    calls = _patch_input(monkeypatch, ["", EOFError()])

    result = await cli_chat._prompt_for_resume(None, {}, None)  # type: ignore[arg-type]

    assert result is False
    assert len(calls) == 2  # empty -> re-prompt -> EOF


async def test_failed_resume_reprompts(monkeypatch: MonkeyPatch) -> None:
    """A failed resume (None) re-prompts instead of counting as a decision."""
    calls = _patch_input(monkeypatch, ["approve", EOFError()])
    spy = AsyncMock(return_value=None)  # resume failed
    monkeypatch.setattr(cli_chat, "_resume_and_render", spy)

    result = await cli_chat._prompt_for_resume(None, {}, None)  # type: ignore[arg-type]

    assert result is False
    assert spy.await_count == 1  # approve attempted, then EOF before retry


async def test_repark_loops_until_decision_completes(monkeypatch: MonkeyPatch) -> None:
    """Result still carrying __interrupt__ loops back to the prompt."""
    _patch_input(monkeypatch, ["approve", "approve"])
    spy = AsyncMock(side_effect=[{"__interrupt__": ("x",)}, {"approved": True}])
    monkeypatch.setattr(cli_chat, "_resume_and_render", spy)

    result = await cli_chat._prompt_for_resume(None, {}, None)  # type: ignore[arg-type]

    assert result is True
    assert spy.await_count == 2
