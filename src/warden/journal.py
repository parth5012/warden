"""Append-only audit journal & cryptographic write-ahead log for Warden.

Implements:
- Canonical event models matching DATA_MODEL.md § 5
- Cryptographic SHA-256 hash chaining (tamper evident)
- Idempotency deduplication for write-ahead events (run_id, action_id, kind)
- Memory and extensible persistence adapters
"""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class EventKind(str, Enum):
    ACTION_REQUESTED = "action_requested"
    POLICY_EVALUATED = "policy_evaluated"
    ACTION_DENIED = "action_denied"
    GATE_REQUESTED = "gate_requested"
    GATE_DECIDED = "gate_decided"
    EXECUTION_QUEUED = "execution_queued"
    EXECUTION_STARTED = "execution_started"
    ACTION_COMPLETED = "action_completed"
    ACTION_FAILED = "action_failed"
    CHECKPOINT_CREATED = "checkpoint_created"
    LEASE_EVALUATED = "lease_evaluated"
    GRANT_ISSUED = "grant_issued"
    GRANT_CONSUMED = "grant_consumed"
    GRANT_REVOKED = "grant_revoked"
    GRANT_EXPIRED = "grant_expired"


class VerificationStatus(str, Enum):
    VERIFIED = "Verified"
    FAILED = "Verification failed"
    NOT_VERIFIED = "Not verified"
    UNAVAILABLE = "Verification unavailable"


@dataclass(frozen=True)
class JournalEvent:
    id: str
    run_id: str
    thread_id: str
    action_id: Optional[str]
    checkpoint_step: Optional[int]
    kind: str
    actor: str
    status: str
    description: str
    payload: Dict[str, Any]
    ts: str
    prev_hash: Optional[str] = None
    event_hash: Optional[str] = None
    verification_status: VerificationStatus = VerificationStatus.UNAVAILABLE

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["verification_status"] = self.verification_status.value
        return d


def canonical_event_bytes(event_dict: Dict[str, Any]) -> bytes:
    """Serializes event fields (excluding hash and verification status) to canonical sorted JSON."""
    payload_to_hash = {
        "id": event_dict.get("id"),
        "run_id": event_dict.get("run_id"),
        "thread_id": event_dict.get("thread_id"),
        "action_id": event_dict.get("action_id"),
        "checkpoint_step": event_dict.get("checkpoint_step"),
        "kind": event_dict.get("kind"),
        "actor": event_dict.get("actor"),
        "status": event_dict.get("status"),
        "description": event_dict.get("description"),
        "payload": event_dict.get("payload", {}),
        "ts": event_dict.get("ts"),
        "prev_hash": event_dict.get("prev_hash"),
    }
    return json.dumps(
        payload_to_hash,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def calculate_event_hash(event_dict: Dict[str, Any]) -> str:
    """Computes SHA-256 digest of canonical event bytes."""
    return hashlib.sha256(canonical_event_bytes(event_dict)).hexdigest()


def verify_hash_chain(events: List[JournalEvent]) -> Tuple[VerificationStatus, Optional[str]]:
    """Verifies that events form an unbroken SHA-256 cryptographic hash chain."""
    if not events:
        return VerificationStatus.NOT_VERIFIED, "No events to verify"

    sorted_events = list(events)
    expected_prev_hash: Optional[str] = None

    for idx, ev in enumerate(sorted_events):
        if ev.prev_hash != expected_prev_hash:
            return (
                VerificationStatus.FAILED,
                f"Broken chain at event #{idx} ({ev.id}): expected prev_hash '{expected_prev_hash}', got '{ev.prev_hash}'",
            )

        calc_hash = calculate_event_hash(ev.to_dict())
        if ev.event_hash != calc_hash:
            return (
                VerificationStatus.FAILED,
                f"Hash mismatch at event #{idx} ({ev.id}): recorded '{ev.event_hash}', calculated '{calc_hash}'",
            )

        expected_prev_hash = ev.event_hash

    return VerificationStatus.VERIFIED, "Cryptographic hash chain intact and verified"


class AuditJournal(ABC):
    """Abstract interface for Warden audit journals."""

    @abstractmethod
    def append(
        self,
        kind: str | EventKind,
        *,
        run_id: str,
        thread_id: str,
        actor: str,
        action_id: Optional[str] = None,
        checkpoint_step: Optional[int] = None,
        status: str = "",
        description: str = "",
        payload: Optional[Dict[str, Any]] = None,
    ) -> JournalEvent:
        """Appends a new event to the journal, preserving cryptographic hash chain."""
        pass

    @property
    @abstractmethod
    def events(self) -> List[JournalEvent]:
        """Returns all events in append order."""
        pass

    @abstractmethod
    def list_events(
        self,
        q: Optional[str] = None,
        kind: Optional[str] = None,
        action_id: Optional[str] = None,
        run_id: Optional[str] = None,
        actor: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Tuple[List[JournalEvent], int]:
        """Filters events according to search criteria."""
        pass

    @abstractmethod
    def get_event(self, event_id: str) -> Optional[JournalEvent]:
        """Retrieves a single event by ID."""
        pass

    @abstractmethod
    def verify(self) -> Tuple[VerificationStatus, Optional[str]]:
        """Verifies hash chain integrity."""
        pass


class InMemoryJournal(AuditJournal):
    """Thread-safe in-memory journal with write-ahead idempotency and SHA-256 chain."""

    def __init__(self, initial_events: Optional[List[JournalEvent]] = None) -> None:
        self._lock = threading.RLock()
        self._events: List[JournalEvent] = list(initial_events or [])
        self._idempotency_map: Dict[Tuple[str, str, str], JournalEvent] = {}
        for ev in self._events:
            if ev.action_id and ev.kind in (EventKind.ACTION_REQUESTED.value, EventKind.GATE_REQUESTED.value):
                self._idempotency_map[(ev.run_id, ev.action_id, ev.kind)] = ev

    def append(
        self,
        kind: str | EventKind,
        *,
        run_id: str,
        thread_id: str,
        actor: str,
        action_id: Optional[str] = None,
        checkpoint_step: Optional[int] = None,
        status: str = "",
        description: str = "",
        payload: Optional[Dict[str, Any]] = None,
    ) -> JournalEvent:
        kind_str = kind.value if isinstance(kind, EventKind) else str(kind)

        with self._lock:
            # Write-ahead idempotency check (Lock 3)
            if action_id and kind_str in (EventKind.ACTION_REQUESTED.value, EventKind.GATE_REQUESTED.value):
                key = (run_id, action_id, kind_str)
                if key in self._idempotency_map:
                    return self._idempotency_map[key]

            prev_hash = self._events[-1].event_hash if self._events else None
            ev_id = f"ev_{uuid.uuid4().hex[:10]}"
            raw: Dict[str, Any] = {
                "id": ev_id,
                "run_id": run_id,
                "thread_id": thread_id,
                "action_id": action_id,
                "checkpoint_step": checkpoint_step,
                "kind": kind_str,
                "actor": actor,
                "status": status,
                "description": description,
                "payload": payload or {},
                "ts": datetime.now(timezone.utc).isoformat(),
                "prev_hash": prev_hash,
            }
            raw["event_hash"] = calculate_event_hash(raw)
            raw["verification_status"] = VerificationStatus.VERIFIED

            ev = JournalEvent(**raw)
            self._events.append(ev)

            if action_id and kind_str in (EventKind.ACTION_REQUESTED.value, EventKind.GATE_REQUESTED.value):
                self._idempotency_map[(run_id, action_id, kind_str)] = ev

            return ev

    @property
    def events(self) -> List[JournalEvent]:
        with self._lock:
            return list(self._events)

    def list_events(
        self,
        q: Optional[str] = None,
        kind: Optional[str] = None,
        action_id: Optional[str] = None,
        run_id: Optional[str] = None,
        actor: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Tuple[List[JournalEvent], int]:
        with self._lock:
            filtered = list(self._events)

            if kind:
                filtered = [e for e in filtered if e.kind == kind]
            if action_id:
                filtered = [e for e in filtered if e.action_id == action_id]
            if run_id:
                filtered = [e for e in filtered if e.run_id == run_id]
            if actor:
                filtered = [e for e in filtered if actor.lower() in e.actor.lower()]
            if q:
                ql = q.lower()
                filtered = [
                    e
                    for e in filtered
                    if ql in e.id.lower()
                    or (e.action_id and ql in e.action_id.lower())
                    or ql in e.run_id.lower()
                    or ql in e.actor.lower()
                    or ql in e.description.lower()
                    or ql in str(e.payload).lower()
                ]

            total = len(filtered)
            paged = filtered[offset : offset + limit]
            return paged, total

    def get_event(self, event_id: str) -> Optional[JournalEvent]:
        with self._lock:
            for ev in self._events:
                if ev.id == event_id:
                    return ev
            return None

    def verify(self) -> Tuple[VerificationStatus, Optional[str]]:
        with self._lock:
            return verify_hash_chain(self._events)


_GLOBAL_JOURNAL: AuditJournal = InMemoryJournal()


def get_journal() -> AuditJournal:
    """Get the active application audit journal."""
    return _GLOBAL_JOURNAL


def set_journal(journal: AuditJournal) -> None:
    """Set the active application audit journal."""
    global _GLOBAL_JOURNAL
    _GLOBAL_JOURNAL = journal
