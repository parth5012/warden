"""ToolSpec + ToolContext shared types for Phase-1 ops-assistant tools.

No IO. Imports only warden.models (existing seam).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from warden.models import Action, ActionKind


@dataclass(frozen=True)
class ToolSpec:
    """Static descriptor for one demo tool."""

    name: str
    description: str
    payload_schema: dict[str, str]
    execution_path: str  # "in-process" | "hitl" | "sandbox" | "aborted"
    triggers_rule: bool


@dataclass(frozen=True)
class ToolContext:
    """Identity carried into every Action."""

    run_id: str
    thread_id: str
    actor: str = "ops-assistant"
    checkpoint_step: int | None = None


def make_action(spec: ToolSpec, payload: dict[str, Any], ctx: ToolContext) -> Action:
    """Build a TOOL Action crossing the executor seam (lock 1)."""
    return Action(
        id=f"act_{uuid.uuid4().hex[:12]}",
        kind=ActionKind.TOOL,
        name=spec.name,
        payload=dict(payload),
        run_id=ctx.run_id,
        thread_id=ctx.thread_id,
    )


__all__ = ["ToolContext", "ToolSpec", "make_action"]
