"""Approval lifecycle contract used by Warden's UI projections.

This module deliberately does not persist decisions or authorize operators. A
production decision handler must perform authentication, authorization, CSRF
validation, expiry/version/hash checks, transactional persistence and audit
recording before applying a transition.
"""
from __future__ import annotations

from collections import Counter
from typing import Any, Iterable


REVIEW_STATUSES = frozenset({"pending", "escalated"})
TERMINAL_STATUSES = frozenset({"denied", "succeeded", "failed", "expired", "cancelled"})

# Lower-case normalized status names are used internally.
ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    "pending": frozenset({"approved", "denied", "escalated", "expired"}),
    "escalated": frozenset({"approved", "denied", "pending", "expired"}),
    "approved": frozenset({"executing", "cancelled", "expired"}),
    "executing": frozenset({"succeeded", "failed", "cancelled"}),
    "denied": frozenset(),
    "succeeded": frozenset(),
    "failed": frozenset(),
    "expired": frozenset(),
    "cancelled": frozenset(),
}


class InvalidTransition(ValueError):
    """Raised when a requested lifecycle transition is not allowed."""


def normalize_status(status: str) -> str:
    return status.strip().lower().replace(" ", "_")


def is_reviewable(action: dict[str, Any]) -> bool:
    """True only for actions that are currently waiting for human review."""
    return normalize_status(str(action.get("status", ""))) in REVIEW_STATUSES


def build_review_metrics(actions: Iterable[dict[str, Any]]) -> dict[str, int]:
    """Calculate every approval-queue count from the same supplied action set."""
    reviewable = [action for action in actions if is_reviewable(action)]
    status_counts = Counter(normalize_status(str(a.get("status", ""))) for a in reviewable)
    return {
        "total": len(reviewable),
        "critical": sum(str(a.get("risk", "")).lower() == "critical" for a in reviewable),
        "escalated": status_counts["escalated"],
        "pending": status_counts["pending"],
    }


def allowed_transitions(status: str) -> list[str]:
    """Return valid next states for UI/documentation; this is not authorization."""
    return sorted(ALLOWED_TRANSITIONS.get(normalize_status(status), frozenset()))


def validate_transition(current_status: str, next_status: str) -> None:
    """Validate the lifecycle state-machine edge, raising for invalid edges."""
    current = normalize_status(current_status)
    target = normalize_status(next_status)
    if target not in ALLOWED_TRANSITIONS.get(current, frozenset()):
        raise InvalidTransition(f"Transition from '{current}' to '{target}' is not allowed")

