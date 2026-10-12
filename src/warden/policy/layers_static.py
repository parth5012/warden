"""L0 static rules: instant deny on known-destructive patterns.

Zero dependencies, zero latency budget. Runs before any model.
"""

from __future__ import annotations

import re

# (pattern, policy_id) — keep small and obvious; semantic stuff belongs in L1/L2.
_BLOCKED: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bdrop\s+table\b", re.IGNORECASE), "no-destructive-sql"),
    (re.compile(r"\bdelete\s+from\b", re.IGNORECASE), "no-destructive-sql"),
    (re.compile(r"\btruncate\s+table\b", re.IGNORECASE), "no-destructive-sql"),
    (re.compile(r"rm\s+-rf\s+/", re.IGNORECASE), "no-destructive-shell"),
    (re.compile(r"mkfs(\.|$|\s)", re.IGNORECASE), "no-destructive-shell"),
    (re.compile(r":\(\)\s*\{\s*:\|\:&\s*\}\s*;", re.IGNORECASE), "no-forkbomb"),
)


def find_static_violation(text: str) -> str | None:
    """Return policy_id if text matches a blocked pattern, else None."""
    for pattern, policy_id in _BLOCKED:
        if pattern.search(text):
            return policy_id
    return None


def action_text(name: str, payload: dict[str, object]) -> str:
    """Flatten action name + payload values into searchable text."""
    parts = [name]
    for value in payload.values():
        parts.append(str(value))
    return "\n".join(parts)
