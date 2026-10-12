"""Append-only policy versions types and models (Lock 9 guardrail).

Lock 9: "Guardrail: append-only policy_versions table (policy_id, version,
content, who, when) — lock 5's 'edits are logged' promise. Repo ships seed
policies loaded on first boot; after that, DB owns the truth."
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class PolicyVersionRecord:
    """Immutable audit record for a policy change."""

    id: str
    policy_id: str
    version: int
    content: dict[str, Any]
    who: str
    changed_at: datetime | str

    def __post_init__(self) -> None:
        if self.version < 1:
            raise ValueError(f"Policy version must be >= 1, got {self.version}")
        if not self.who.strip():
            raise ValueError("Attribution required: 'who' must not be empty (Lock 8/9)")
