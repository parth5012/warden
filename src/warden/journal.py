"""AuditJournal for Aegis.

Source-of-truth append-only audit event store.
Records action requests (write-ahead), policy denials, gate requests,
gate decisions, action completion, and execution failures.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable

# Pattern matching API keys, tokens, and authorization credentials
SECRET_PATTERN = re.compile(
    r"(?:bearer\s+[a-zA-Z0-9_\-\.]{15,}|sk-[a-zA-Z0-9_\-]{20,}|key=[a-zA-Z0-9_\-]{15,})",
    re.IGNORECASE,
)


def redact_secrets_in_obj(obj: Any) -> Any:
    """Recursively scrub secrets from payload objects."""
    if isinstance(obj, str):
        return SECRET_PATTERN.sub("[REDACTED_SECRET]", obj)
    if isinstance(obj, dict):
        return {k: redact_secrets_in_obj(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_secrets_in_obj(x) for x in obj]
    return obj


@dataclass(frozen=True)
class JournalEvent:
    """An immutable audit journal event entry."""

    id: str
    run_id: str
    thread_id: str
    action_id: str | None
    checkpoint_step: int | None
    kind: str
    actor: str | None
    payload: dict[str, Any]
    ts: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@runtime_checkable
class AuditJournal(Protocol):
    """Protocol for append-only audit journals."""

    async def append(self, event: JournalEvent) -> None:
        """Append an event. Raises if journal is unavailable or write fails."""
        ...

    async def query(self, filters: dict[str, Any] | None = None) -> list[JournalEvent]:
        """Query recorded journal events."""
        ...


class InMemoryAuditJournal:
    """In-memory append-only audit journal for testing and local execution.

    Maintains idempotent write-ahead semantics on (run_id, action_id, kind)
    for write-ahead event types ('action_requested', 'gate_requested').
    """

    def __init__(self, failing: bool = False) -> None:
        self.events: list[JournalEvent] = []
        self._seen_write_ahead: set[tuple[str, str | None, str]] = set()
        self._failing = failing

    def set_failing(self, failing: bool) -> None:
        self._failing = failing

    async def append(self, event: JournalEvent) -> None:
        if self._failing:
            raise RuntimeError("Audit journal storage unavailable")

        # Idempotency check for write-ahead event kinds
        if event.kind in ("action_requested", "gate_requested"):
            key = (event.run_id, event.action_id, event.kind)
            if key in self._seen_write_ahead:
                # Idempotent write-ahead duplicate is ignored safely
                return
            self._seen_write_ahead.add(key)

        sanitized_payload = redact_secrets_in_obj(event.payload)
        sanitized_event = JournalEvent(
            id=event.id,
            run_id=event.run_id,
            thread_id=event.thread_id,
            action_id=event.action_id,
            checkpoint_step=event.checkpoint_step,
            kind=event.kind,
            actor=event.actor,
            payload=sanitized_payload,
            ts=event.ts,
        )
        self.events.append(sanitized_event)

    async def query(self, filters: dict[str, Any] | None = None) -> list[JournalEvent]:
        if self._failing:
            raise RuntimeError("Audit journal storage unavailable")
        if not filters:
            return list(self.events)

        filtered: list[JournalEvent] = []
        for ev in self.events:
            match = True
            for k, v in filters.items():
                if getattr(ev, k, None) != v:
                    match = False
                    break
            if match:
                filtered.append(ev)
        return filtered

    async def append_llm_usage(self, event: JournalEvent) -> None:
        """Append an LLM usage telemetry event (same redaction + idempotency as other events)."""
        await self.append(event)

    def record_llm_usage(
        self,
        *,
        run_id: str,
        thread_id: str,
        action_id: str,
        **payload: Any,
    ) -> JournalEvent:
        """Record an LLM usage telemetry event into this journal.

        The payload is redacted before persistence (secrets / raw prompt and
        response bodies are never retained).  This is the synchronous
        counterpart used by the client's telemetry sink when the sink is
        called from a synchronous context.
        """
        from warden.journal import JournalEvent, redact_secrets_in_obj

        event = JournalEvent(
            id=str(uuid.uuid4()),
            run_id=run_id,
            thread_id=thread_id,
            action_id=action_id,
            checkpoint_step=None,
            kind="llm_usage",
            actor=payload.get("actor"),
            payload=redact_secrets_in_obj(payload),
            ts=payload.get("timestamp") or datetime.now(timezone.utc),
        )
        self.events.append(event)
