"""Audit journal search and inspection endpoints.

The API journal is backed by the existing :class:`warden.journal.InMemoryAuditJournal`
so every endpoint reads and writes the same append-only event store used by the
executor and the Guarded LLM Client.

Event kinds recorded here:

* ``action_requested`` — write-ahead entry produced by :class:`GuardedExecutor`
* ``gate_requested`` — write-ahead entry (same deduplication key as action_requested)
* ``action_denied`` — terminal policy denial
* ``gate_decided`` — operator gate verdict
* ``action_completed`` — successful execution
* ``action_failed`` — handler/preflight failure (budget, protocol, provider)
* ``llm_usage`` — GuardedLLMClient telemetry payload (emitted by the client
  telemetry sink; not by this module)

The journal always redacts secrets before appending, and the search endpoint
only surfaces already-sanitized payloads.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Query

from warden.journal import (
    JournalEvent,
    InMemoryAuditJournal,
    redact_secrets_in_obj,
)

from backend.api import get_audit_journal

logger = logging.getLogger("warden.api.audit")

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
    {
        "id": "evt-004",
        "run_id": "run-004",
        "thread_id": "grant-demo-thread",
        "action_id": None,
        "checkpoint_step": 1,
        "kind": "grant_issued",
        "actor": "approver:alice",
        "description": "Grant gr_seed_01 issued by alice for batch_delete_files (5 max uses)",
        "payload": {
            "grant_id": "gr_seed_01",
            "tool": "batch_delete_files",
            "max_uses": 5,
            "ttl_minutes": 30,
        },
        "ts": "2026-10-11T14:10:00Z",
    },
    {
        "id": "evt-005",
        "run_id": "run-004",
        "thread_id": "grant-demo-thread",
        "action_id": "act-004",
        "checkpoint_step": 2,
        "kind": "grant_consumed",
        "actor": "GuardedExecutor",
        "description": "Grant gr_seed_01 consumed for act-004 (4 uses left)",
        "payload": {
            "grant_id": "gr_seed_01",
            "action_id": "act-004",
            "uses_left": 4,
            "granted_by": "alice",
        },
        "ts": "2026-10-11T14:10:05Z",
    },
    {
        "id": "evt-006",
        "run_id": "run-004",
        "thread_id": "grant-demo-thread",
        "action_id": None,
        "checkpoint_step": 3,
        "kind": "grant_revoked",
        "actor": "approver:alice",
        "description": "Grant gr_seed_01 revoked by alice",
        "payload": {
            "grant_id": "gr_seed_01",
            "revoked_by": "alice",
        },
        "ts": "2026-10-11T14:15:00Z",
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


async def _record(kind: str, actor: str, payload: dict[str, Any], *, step: int | None = None) -> JournalEvent:
    """Append a sanitized journal event and return it."""
    journal = get_audit_journal()
    event = JournalEvent(
        id=str(uuid.uuid4()),
        run_id="",
        thread_id="",
        action_id="",
        checkpoint_step=step,
        kind=kind,
        actor=actor,
        payload=redact_secrets_in_obj(payload),
        ts=datetime.now(timezone.utc),
    )
    await journal.append(event)
    return event


async def record_llm_usage(
    *,
    journal: InMemoryAuditJournal | None = None,
    run_id: str = "",
    thread_id: str = "",
    action_id: str = "",
    **payload: Any,
) -> dict[str, Any]:
    """Record an LLM usage telemetry event into the journal.

    ``journal`` defaults to the shared ``_journal`` instance.  Passing an
    explicit journal allows tests to assert against a specific store.
    """
    safe_fields = {
        "provider",
        "model",
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "input_uncached_tokens",
        "input_cached_tokens",
        "output_standard_tokens",
        "output_reasoning_tokens",
        "usage_source",
        "calculated_cost_usd",
        "estimated_cost_usd",
        "pricing_version",
        "provider_request_id",
        "latency_ms",
        "retry_count",
        "outcome_kind",
        "error_code",
        "error_detail",
        "timestamp",
        "correlation_id",
    }
    safe_payload = redact_secrets_in_obj(
        {key: value for key, value in payload.items() if key in safe_fields}
    )
    event = JournalEvent(
        id=f"evt-llm-{uuid.uuid4().hex[:8]}",
        run_id=run_id,
        thread_id=thread_id,
        action_id=action_id,
        checkpoint_step=None,
        kind="llm_usage",
        actor=None,
        payload=safe_payload,
        ts=datetime.now(timezone.utc),
    )
    target = journal if journal is not None else get_audit_journal()
    await target.append(event)
    return {
        "id": event.id,
        "run_id": event.run_id,
        "thread_id": event.thread_id,
        "action_id": event.action_id,
        "checkpoint_step": event.checkpoint_step,
        "kind": event.kind,
        "actor": event.actor,
        "payload": event.payload,
        "ts": (
            event.ts.isoformat()
            if isinstance(event.ts, datetime)
            else event.ts
        ),
    }


async def record_audit_event(
    run_id: str,
    thread_id: str,
    action_id: str,
    kind: str,
    actor: str,
    payload: dict[str, Any],
    step: int = 1,
) -> dict[str, Any]:
    """Append a new audit event to the journal."""
    event = JournalEvent(
        id=str(uuid.uuid4()),
        run_id=run_id,
        thread_id=thread_id,
        action_id=action_id,
        checkpoint_step=step,
        kind=kind,
        actor=actor,
        payload=redact_secrets_in_obj(payload),
        ts=datetime.now(timezone.utc),
    )
    journal = get_audit_journal()
    await journal.append(event)
    return {
        "id": event.id,
        "run_id": event.run_id,
        "thread_id": event.thread_id,
        "action_id": event.action_id,
        "checkpoint_step": event.checkpoint_step,
        "kind": event.kind,
        "actor": event.actor,
        "payload": event.payload,
        "ts": (
            event.ts.isoformat()
            if isinstance(event.ts, datetime)
            else event.ts
        ),
    }


@router.get("")
async def search_audit_log(
    q: str | None = None,
    thread_id: str | None = None,
    kind: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    """Search and filter the append-only audit journal."""
    journal_events = await get_audit_journal().query()

    if journal_events:
        events = list(journal_events)
        if thread_id:
            events = [e for e in events if getattr(e, "thread_id", None) == thread_id or getattr(e, "run_id", None) == thread_id]
        if kind:
            events = [e for e in events if getattr(e, "kind", None) == kind]
        if q:
            query = q.lower()
            events = [
                e
                for e in events
                if query in str(redact_secrets_in_obj(e.payload)).lower()
                or query in e.kind.lower()
                or query in str(e.actor).lower()
            ]

        limit_int = limit if isinstance(limit, int) else 100
        offset_int = offset if isinstance(offset, int) else 0

        paginated = events[offset_int : offset_int + limit_int]
        return {
            "events": [e.__dict__ for e in paginated],
            "total": len(events),
            "limit": limit_int,
            "offset": offset_int,
        }

    fallback = _filter_default_events(q=q, thread_id=thread_id, kind=kind)
    limit_int = limit if isinstance(limit, int) else 100
    offset_int = offset if isinstance(offset, int) else 0
    return {
        "events": fallback[offset_int : offset_int + limit_int],
        "total": len(fallback),
        "limit": limit_int,
        "offset": offset_int,
    }


@router.get("/llm-usage")
async def get_llm_usage(
    run_id: str | None = None,
    thread_id: str | None = None,
    kind: str = Query(default="llm_usage"),
) -> dict[str, Any]:
    """Return LLM usage events recorded by GuardedLLMClient."""
    events = await get_audit_journal().query()
    if run_id:
        events = [e for e in events if e.run_id == run_id]
    if thread_id:
        events = [e for e in events if e.thread_id == thread_id]
    if kind:
        events = [e for e in events if e.kind == kind]

    return {
        "events": [e.__dict__ for e in events],
        "total": len(events),
    }
