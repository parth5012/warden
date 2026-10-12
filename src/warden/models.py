"""Core domain types for Aegis.

Action, Outcome, and checkpoint-related types.
Everything here is a plain dataclass — no IO, no side effects.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Action — the unit that crosses the executor seam
# ---------------------------------------------------------------------------

class ActionKind(str, Enum):
    TOOL = "tool"
    LLM = "llm"


@dataclass(frozen=True)
class Action:
    """An operation that must cross the GuardedExecutor seam."""

    id: str
    kind: ActionKind
    name: str
    payload: dict[str, Any]
    run_id: str
    thread_id: str


# ---------------------------------------------------------------------------
# Outcome — the four possible verdicts from execute()
# ---------------------------------------------------------------------------

class OutcomeKind(str, Enum):
    ALLOWED = "allowed"
    DENIED = "denied"
    PENDING = "pending"
    ERROR = "error"


@dataclass(frozen=True)
class Allowed:
    result: Any
    kind: OutcomeKind = field(default=OutcomeKind.ALLOWED, init=False)


@dataclass(frozen=True)
class Denied:
    reason: str
    policy: str
    kind: OutcomeKind = field(default=OutcomeKind.DENIED, init=False)


@dataclass(frozen=True)
class Pending:
    gate_request: GateRequest
    kind: OutcomeKind = field(default=OutcomeKind.PENDING, init=False)


@dataclass(frozen=True)
class Error:
    reason: str
    kind: OutcomeKind = field(default=OutcomeKind.ERROR, init=False)


Outcome = Allowed | Denied | Pending | Error


# ---------------------------------------------------------------------------
# Gate types — HITL request/decision
# ---------------------------------------------------------------------------

class GateVerdict(str, Enum):
    APPROVE = "approve"
    DENY = "deny"


@dataclass(frozen=True)
class GateRequest:
    gate_id: str
    action: Action
    context: dict[str, Any] = field(default_factory=dict)
    requested_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


@dataclass(frozen=True)
class GateDecision:
    gate_id: str
    verdict: GateVerdict
    reason: str
    decided_by: str
    decided_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


# ---------------------------------------------------------------------------
# Execution Context
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ExecutionContext:
    """Execution metadata propagated across the executor seam."""

    actor: str = "agent"
    run_id: str | None = None
    thread_id: str | None = None
    checkpoint_step: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Checkpoint state inspection types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CheckpointInfo:
    """Lightweight view of a LangGraph checkpoint for logging/inspection."""

    thread_id: str
    checkpoint_id: str
    parent_checkpoint_id: str | None
    created_at: str | None
    step: int
    has_pending_interrupts: bool
    pending_interrupt_values: list[Any] = field(default_factory=list)
