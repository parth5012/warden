from app.workflow import (
    InvalidTransition,
    allowed_transitions,
    build_review_metrics,
    is_reviewable,
    validate_transition,
)
import pytest

def test_review_metrics_share_one_queue_scope() -> None:
    actions = [
        {"status": "Escalated", "risk": "Critical"},
        {"status": "Escalated", "risk": "High"},
        {"status": "Pending", "risk": "Medium"},
        {"status": "Pending", "risk": "Medium"},
        {"status": "Approved", "risk": "Low"},
    ]
    assert build_review_metrics(actions) == {
        "total": 4,
        "critical": 1,
        "escalated": 2,
        "pending": 2,
    }


def test_reviewable_status_normalization() -> None:
    assert is_reviewable({"status": "Pending"})
    assert is_reviewable({"status": "ESCALATED"})
    assert not is_reviewable({"status": "Approved"})
    assert not is_reviewable({"status": "Executing"})


def test_valid_lifecycle_transitions() -> None:
    validate_transition("pending", "approved")
    validate_transition("approved", "executing")
    validate_transition("executing", "succeeded")
    assert "denied" in allowed_transitions("pending")
    assert allowed_transitions("succeeded") == []


def test_invalid_transition_is_rejected() -> None:
    with pytest.raises(InvalidTransition):
        validate_transition("denied", "approved")
    with pytest.raises(InvalidTransition):
        validate_transition("pending", "succeeded")
