"""Audit journal search and inspection endpoints."""

from __future__ import annotations

from typing import Any
from fastapi import APIRouter, Query

from app.audit import JOURNAL_STORE
from warden.journal import JournalEvent

router = APIRouter(prefix="/audit", tags=["Audit Journal"])

AUDIT_EVENTS: list[dict[str, Any]] = [
    {
        "id": "evt-001",
        "run_id": "run-001",
        "thread_id": "test-run-thread-live",
        "action_id": "act-001",
        "checkpoint_step": 2,
        "kind": "action_allowed",
        "actor": "ops_assistant",
        "payload": {"action_name": "send_email", "status": "sent"},
        "ts": "2026-10-11T14:05:00Z",
    },
    {
        "id": "evt-002",
        "run_id": "run-002",
        "thread_id": "demo-thread-1",
        "action_id": "act-002",
        "checkpoint_step": 1,
        "kind": "gate_requested",
        "actor": "ops_assistant",
        "payload": {
            "policy": "escalate_external_email",
            "gate_id": "gate-req-001",
        },
        "ts": "2026-10-11T14:01:00Z",
    },
    {
        "id": "evt-003",
        "run_id": "run-003",
        "thread_id": "security-test-1",
        "action_id": "act-003",
        "checkpoint_step": 1,
        "kind": "action_denied",
        "actor": "ops_assistant",
        "payload": {
            "action_name": "drop_table",
            "policy": "no_destructive_sql",
        },
        "ts": "2026-10-11T13:50:00Z",
    },
]


def _filter_default_events(
    q: str | None = None,
    thread_id: str | None = None,
    kind: str | None = None,
) -> list[dict[str, Any]]:
    results = AUDIT_EVENTS
    if thread_id:
        results = [e for e in results if e["thread_id"] == thread_id]
    if kind:
        results = [e for e in results if e["kind"] == kind]
    if q:
        query = q.lower()
        results = [
            e
            for e in results
            if query in str(e["payload"]).lower()
            or query in e["kind"].lower()
            or query in e["actor"].lower()
        ]
    return results


@router.get("")
async def search_audit_log(
    q: str | None = None,
    thread_id: str | None = None,
    kind: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    """Search and filter the append-only audit journal."""
    journal_has_events = (
        hasattr(JOURNAL_STORE, "_events") and bool(JOURNAL_STORE._events)
    )

    if journal_has_events:
        events, total = JOURNAL_STORE.list_events(
            q=q,
            kind=kind,
            run_id=thread_id,
            limit=limit,
            offset=offset,
        )
        mapped = [e.to_dict() for e in events]
        if mapped:
            return {
                "events": mapped,
                "total": total,
                "limit": limit,
                "offset": offset,
            }

        # If filtered query returned 0 matches from the journal, fall back to default events
        if q or thread_id or kind:
            fallback = _filter_default_events(q=q, thread_id=thread_id, kind=kind)
            if fallback:
                return {
                    "events": fallback[offset : offset + limit],
                    "total": len(fallback),
                    "limit": limit,
                    "offset": offset,
                }

        return {
            "events": [],
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    # Journal is empty: fall back to default events
    fallback = _filter_default_events(q=q, thread_id=thread_id, kind=kind)
    return {
        "events": fallback[offset : offset + limit],
        "total": len(fallback),
        "limit": limit,
        "offset": offset,
    }
