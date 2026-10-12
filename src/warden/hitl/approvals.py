"""Secure human-in-the-loop approval for sensitive actions (Phase 1, Step 3).

Implements secure binding between an approval and the exact proposed action:

- ``ApprovalBinding`` — binds approver decision to action id/kind/name,
  run/thread ids, deterministic canonical payload SHA-256 hash, policy
  identity, decision, expiry, and a unique nonce/approval id.
- ``ApprovalStore`` — protocol, plus:
  - ``InMemoryApprovalStore``: atomic (single-threaded) store for unit tests.
  - ``SqliteApprovalStore``: durable store using ``BEGIN IMMEDIATE`` for
    concurrency-safe claim operations; survives process restart.

Nothing here trusts caller-supplied ``approved=True`` flags: authorization is
inside the store via canonical-hash matching, expiry, and one-time claim.

No real emails/services. No Ed25519 (no existing key-management design in the
repo; per instructions we do not invent one).
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from warden.models import Action

APPROVAL_TTL_DEFAULT = timedelta(minutes=15)


def canonical_payload_hash(payload: Any) -> str:
    """Deterministic SHA-256 over a canonical JSON form of the payload.

    Dict keys sorted, no whitespace, unicode preserved, deep-normalized
    (tuples become lists) so semantically-identical payloads hash identically.
    """
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=list
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class ApprovalError(Exception):
    """Base class for approval lifecycle failures."""


class ApprovalNotFound(ApprovalError):
    """Raised when an approval id does not correspond to a live approval."""


class ApprovalExpired(ApprovalError):
    """Raised when a matched approval has passed its expiry."""


class ApprovalMismatch(ApprovalError):
    """Raised when an approval's action binding does not match the proposed action."""


class ApprovalAlreadyClaimed(ApprovalError):
    """Raised on duplicate-claim / replay attempts of the same approval."""


class ApprovalUnauthorized(ApprovalError):
    """Raised when a proposed approver does not match the pending approval owner."""


@runtime_checkable
class ApprovalStore(Protocol):
    """Minimal surface an approval backend must satisfy.

    All operations on approvals are recorded in the AuditJournal elsewhere by
    GuardedExecutor; these methods only manage durable state and match/claim.
    """

    async def record(
        self,
        *,
        action: Action,
        approver_key: str,
        policy_identity: str,
        expires_at: datetime,
    ) -> str:
        """Create a new pending approval bound to the exact action.

        Returns a unique approval id (nonce)."""
        ...

    async def claim(
        self,
        *,
        approval_id: str,
        action: Action,
        approver_key: str,
        decision: str,
        policy_identity: str,
        now: datetime | None = None,
    ) -> bool:
        """Atomically claim the approval if the binding matches.

        Returns True on first successful claim; False if action binding
        (id/kind/name/run/thread/payload hash) or policy identity does not
        match the recorded approval. Raises ApprovalExpired /
        ApprovalAlreadyClaimed on expiry / duplicate."""
        ...

    async def get(self, approval_id: str) -> dict[str, Any] | None:
        """Inspect by id (no claim). None if unknown."""
        ...

    async def count_pending(self) -> int:
        """Number of recorded-but-not-claimed approvals (inbox backing)."""
        ...


def _binding_fingerprint(
    action: Action, policy_identity: str
) -> str:
    """Single composite fingerprint tying an approval to an exact action."""
    composite = {
        "action_id": action.id,
        "kind": action.kind.value if hasattr(action.kind, "value") else str(action.kind),
        "name": action.name,
        "run_id": action.run_id,
        "thread_id": action.thread_id,
        "payload_hash": canonical_payload_hash(action.payload),
        "policy_identity": policy_identity,
    }
    return canonical_payload_hash(composite)


class InMemoryApprovalStore:
    """Atomic in-memory store — safe for single-event-loop test use."""

    def __init__(self) -> None:
        self._approvals: dict[str, dict[str, Any]] = {}

    async def record(
        self,
        *,
        action: Action,
        approver_key: str,
        policy_identity: str,
        expires_at: datetime,
    ) -> str:
        approval_id = f"ap-{uuid.uuid4().hex[:12]}"
        self._approvals[approval_id] = {
            "approval_id": approval_id,
            "fingerprint": _binding_fingerprint(action, policy_identity),
            "action_id": action.id,
            "kind": action.kind.value if hasattr(action.kind, "value") else str(action.kind),
            "name": action.name,
            "run_id": action.run_id,
            "thread_id": action.thread_id,
            "payload_hash": canonical_payload_hash(action.payload),
            "policy_identity": policy_identity,
            "approver_key": approver_key,
            "decision": "pending",
            "expires_at": expires_at,
            "claimed": False,
            "created_at": datetime.now(timezone.utc),
            "claimed_at": None,
        }
        return approval_id

    async def claim(
        self,
        *,
        approval_id: str,
        action: Action,
        approver_key: str,
        decision: str,
        policy_identity: str,
        now: datetime | None = None,
    ) -> bool:
        record = self._approvals.get(approval_id)
        if record is None:
            raise ApprovalNotFound(f"approval {approval_id} not found")

        expected_fingerprint = _binding_fingerprint(action, policy_identity)
        if record["fingerprint"] != expected_fingerprint:
            raise ApprovalMismatch(
                "Approval binding does not match the proposed action"
                " (id/kind/name/run/thread/payload/policy)."
            )

        current = now or datetime.now(timezone.utc)
        if record["expires_at"] <= current:
            raise ApprovalExpired(f"approval {approval_id} expired")

        # Explicit approver identity check: only the recorded approver key may
        # exercise this approval.
        if record["approver_key"] != approver_key:
            raise ApprovalUnauthorized(
                f"approval {approval_id} owned by '{record['approver_key']}', "
                f"not '{approver_key}'"
            )

        if record["claimed"]:
            raise ApprovalAlreadyClaimed(
                f"approval {approval_id} already claimed (replay/duplicate)"
            )

        # One-time atomic claim
        record["claimed"] = True
        record["decision"] = decision
        record["claimed_at"] = current
        return True

    async def get(self, approval_id: str) -> dict[str, Any] | None:
        return self._approvals.get(approval_id)

    async def count_pending(self) -> int:
        return sum(1 for r in self._approvals.values() if not r["claimed"])


class SqliteApprovalStore:
    """Durable approval store backed by SQLite with atomic claim semantics.

    Uses ``BEGIN IMMEDIATE`` transactions for the claim path so concurrent
    claims from two connections serialize safely. File-based by default;
    ``:memory:`` allowed for tests that need an isolated fresh store.
    """

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS approvals (
        approval_id    TEXT PRIMARY KEY,
        fingerprint    TEXT NOT NULL,
        action_id      TEXT NOT NULL,
        kind           TEXT NOT NULL,
        name           TEXT NOT NULL,
        run_id         TEXT NOT NULL,
        thread_id      TEXT NOT NULL,
        payload_hash   TEXT NOT NULL,
        policy_identity TEXT NOT NULL,
        approver_key   TEXT NOT NULL,
        decision       TEXT NOT NULL DEFAULT 'pending',
        expires_at     TEXT NOT NULL,
        created_at     TEXT NOT NULL,
        claimed        INTEGER NOT NULL DEFAULT 0,
        claimed_at     TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_approvals_thread ON approvals(thread_id);
    """

    def __init__(self, path: str | Path = ":memory:") -> None:
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        # WAL for durable restart + atomic visibility
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.executescript(self._SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "approval_id": row["approval_id"],
            "fingerprint": row["fingerprint"],
            "action_id": row["action_id"],
            "kind": row["kind"],
            "name": row["name"],
            "run_id": row["run_id"],
            "thread_id": row["thread_id"],
            "payload_hash": row["payload_hash"],
            "policy_identity": row["policy_identity"],
            "approver_key": row["approver_key"],
            "decision": row["decision"],
            "expires_at": datetime.fromisoformat(row["expires_at"]),
            "created_at": datetime.fromisoformat(row["created_at"]),
            "claimed": bool(row["claimed"]),
            "claimed_at": row["claimed_at"],
        }

    async def record(
        self,
        *,
        action: Action,
        approver_key: str,
        policy_identity: str,
        expires_at: datetime,
    ) -> str:
        approval_id = f"ap-{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc)
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO approvals (
                    approval_id, fingerprint, action_id, kind, name,
                    run_id, thread_id, payload_hash, policy_identity,
                    approver_key, decision, expires_at, created_at,
                    claimed, claimed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, 0, NULL)
                """,
                (
                    approval_id,
                    _binding_fingerprint(action, policy_identity),
                    action.id,
                    action.kind.value if hasattr(action.kind, "value") else str(action.kind),
                    action.name,
                    action.run_id,
                    action.thread_id,
                    canonical_payload_hash(action.payload),
                    policy_identity,
                    approver_key,
                    expires_at.isoformat(),
                    now.isoformat(),
                ),
            )
        return approval_id

    async def claim(
        self,
        *,
        approval_id: str,
        action: Action,
        approver_key: str,
        decision: str,
        policy_identity: str,
        now: datetime | None = None,
    ) -> bool:
        current = now or datetime.now(timezone.utc)
        conn = self._conn

        # BEGIN IMMEDIATE serializes concurrent claims on the same approval.
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                "SELECT * FROM approvals WHERE approval_id = ?",
                (approval_id,),
            ).fetchone()
            if row is None:
                conn.rollback()
                raise ApprovalNotFound(f"approval {approval_id} not found")

            record = self._row_to_record(row)
            expected_fingerprint = _binding_fingerprint(action, policy_identity)
            if record["fingerprint"] != expected_fingerprint:
                conn.rollback()
                raise ApprovalMismatch(
                    "Approval binding does not match the proposed action"
                    " (id/kind/name/run/thread/payload/policy)."
                )
            if record["expires_at"] <= current:
                conn.rollback()
                raise ApprovalExpired(f"approval {approval_id} expired")
            if record["approver_key"] != approver_key:
                conn.rollback()
                raise ApprovalUnauthorized(
                    f"approval {approval_id} owned by '{record['approver_key']}',"
                    f" not '{approver_key}'"
                )
            if bool(row["claimed"]):
                conn.rollback()
                raise ApprovalAlreadyClaimed(
                    f"approval {approval_id} already claimed (replay/duplicate)"
                )

            conn.execute(
                """
                UPDATE approvals
                   SET claimed = 1, decision = ?, claimed_at = ?
                 WHERE approval_id = ?
                """,
                (decision, current.isoformat(), approval_id),
            )
            conn.commit()
            return True
        except Exception:
            conn.rollback()
            raise

    async def get(self, approval_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)
        ).fetchone()
        return self._row_to_record(row) if row is not None else None

    async def count_pending(self) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) FROM approvals WHERE claimed = 0"
        ).fetchone()
        return int(row[0]) if row is not None else 0


def make_expiry(
    ttl: timedelta = APPROVAL_TTL_DEFAULT,
    from_: datetime | None = None,
) -> datetime:
    """Convenience builder for expiry timestamps."""
    base = from_ or datetime.now(timezone.utc)
    return base + ttl


def load_approver_keys_from_env() -> dict[str, str]:
    """Load approver keys from env in `name:key` comma-separated form.

    Example: WARDEN_APPROVER_KEYS="alice:secret1,bob:secret2"
    Map is {name -> key}. Empty when unset.
    """
    raw = os.environ.get("WARDEN_APPROVER_KEYS", "").strip()
    out: dict[str, str] = {}
    if not raw:
        return out
    for pair in raw.split(","):
        pair = pair.strip()
        if not pair or ":" not in pair:
            continue
        name, _, key = pair.partition(":")
        out[name.strip()] = key.strip()
    return out
