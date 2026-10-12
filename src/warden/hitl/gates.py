"""HITL gates — approval inbox registry + approver identity (lock 8).

The glue between the seam's `Pending(gate)` outcomes and the web flow:

- **GateRegistry** projects the journal (the source of truth, lock 3) into
  the approvals inbox: which gates are PENDING (open) vs decided. It keeps
  ONLY in-memory views derived from journaled events — the evidence itself
  is the journal (Parth's DB table); the registry owns the API shape.
- **Approver identity = named keys** (lock 8): a few `name:key` pairs in
  an env/config, sent as a header (`Warden-Key`). `approver: alice` must
  be a true statement in the journal — so an unknown key is an error and
  the person recorded is the key's owner, never client-supplied text.
- **`resume_value()`** produces the exact payload the multi-agent gate
  flow consumes (`Command(resume=...)` — a plain dict to a parked thread
  starts a SECOND run, per the caller contract in multi_agent.py).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from warden.streaming import WardenEvent, WardenJournalBus


# ---------------------------------------------------------------------------
# Approver identity (lock 8): named keys, no login system
# ---------------------------------------------------------------------------


class ApproverError(Exception):
    """Named-key authentication failure."""


@dataclass(frozen=True)
class NamedKeys:
    """`name -> key` table. Lookup is key -> name (identity = the key)."""

    pairs: dict[str, str]  # name -> key

    def principal_for(self, key: str) -> str:
        """The human a valid key stands for. Raises on unknown key."""
        for name, k in self.pairs.items():
            if k == key:
                return name
        raise ApproverError("unknown Warden-Key")

    def principal_for_header(self, header_value: str | None) -> str:
        """Header `Warden-Key: <key>` -> principal. Missing -> error."""
        if not header_value:
            raise ApproverError("missing Warden-Key header")
        return self.principal_for(header_value.strip())

    @classmethod
    def from_env(cls, raw: str) -> NamedKeys:
        """Parse `alice=s3cret,bob=hunter2` (env WARDEN_APPROVER_KEYS)."""
        pairs: dict[str, str] = {}
        for chunk in raw.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            if "=" not in chunk:
                raise ApproverError(f"bad approver entry (want name=key): {chunk!r}")
            name, _, key = chunk.partition("=")
            name, key = name.strip(), key.strip()
            if not name or not key:
                raise ApproverError(f"bad approver entry (want name=key): {chunk!r}")
            pairs[name] = key
        if not pairs:
            raise ApproverError("empty approver keys")
        return cls(pairs=pairs)


# ---------------------------------------------------------------------------
# Gate registry — the inbox projected from journal events
# ---------------------------------------------------------------------------


@dataclass
class GateView:
    """One gate as the inbox shows it."""

    gate_id: str
    action: str
    thread_id: str
    requested_at: str
    payload: dict[str, Any] = field(default_factory=dict)
    verdict: str | None = None  # None = still pending
    decided_by: str | None = None
    decided_reason: str = ""
    decided_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "gate_id": self.gate_id,
            "action": self.action,
            "thread_id": self.thread_id,
            "requested_at": self.requested_at,
            "payload": self.payload,
            "verdict": self.verdict,
            "decided_by": self.decided_by,
            "decided_reason": self.decided_reason,
            "decided_at": self.decided_at,
        }


class GateRegistry:
    """The approvals inbox: a pure projection over journal events.

    Feed it the bus the seam journals into (or `replay()` any event list);
    it maintains the pending/decided views and to-records appends live.
    Journal events consumed (all emitted by `GuardedExecutor`):
      gate_requested {gate_id, actor, thread_id, action_id?, ask}
      gate_decided   {gate_id, verdict, decided_by, reason}
    """

    def __init__(self) -> None:
        self._gates: dict[str, GateView] = {}
        self._order: list[str] = []

    # ------------------------------------------------------------------
    # Build from a journal bus / event list
    # ------------------------------------------------------------------

    def replay(self, events: list[WardenEvent]) -> None:
        """Rebuild views from journaled events (oldest first)."""
        for evt in events:
            self.consume(evt)

    def attach(self, bus: WardenJournalBus) -> None:
        """Consume history now; live appends are NOT auto-consumed — the
        app's gate-decision flow calls `consume` explicitly after append
        (keeps the registry synchronous with the HTTP write path)."""

    @staticmethod
    def from_bus(bus: WardenJournalBus) -> GateRegistry:
        reg = GateRegistry()
        reg.replay(bus.history())
        return reg

    # ------------------------------------------------------------------
    # Event consumption
    # ------------------------------------------------------------------

    def consume(self, evt: WardenEvent) -> None:
        """Apply one journal event to the views. Unknown events ignored."""
        p = evt.payload
        if evt.event == "gate_requested":
            gate_id = str(p.get("gate_id", ""))
            if not gate_id or gate_id in self._gates:
                return  # idempotent: duplicate requests are no-ops
            view = GateView(
                gate_id=gate_id,
                action=str(p.get("actor", "")),
                thread_id=str(p.get("thread_id", "")),
                requested_at=evt.ts,
                payload=dict(p.get("payload", {}) or {}),
            )
            self._gates[gate_id] = view
            self._order.append(gate_id)
        elif evt.event == "gate_decided":
            decided_view: GateView | None = self._gates.get(str(p.get("gate_id", "")))
            if decided_view is None:
                return
            view = decided_view
            view.verdict = str(p.get("verdict", ""))
            view.decided_by = str(p.get("decided_by", ""))
            view.decided_reason = str(p.get("reason", ""))
            view.decided_at = evt.ts

    # ------------------------------------------------------------------
    # Read paths (the inbox)
    # ------------------------------------------------------------------

    def pending(self) -> list[GateView]:
        """Open gates, oldest request first (the inbox list)."""
        return [self._gates[g] for g in self._order if self._gates[g].verdict is None]

    def decided(self) -> list[GateView]:
        """Decided gates, oldest first (the audit strip)."""
        return [self._gates[g] for g in self._order if self._gates[g].verdict is not None]

    def get(self, gate_id: str) -> GateView | None:
        return self._gates.get(gate_id)

    def must_get(self, gate_id: str) -> GateView:
        """Get-or-raise for the decision endpoint (404 path)."""
        view = self.get(gate_id)
        if view is None:
            raise KeyError(gate_id)
        return view

    def assert_pending(self, gate_id: str) -> GateView:
        """A decided gate must NOT be re-decidable (single decision)."""
        view = self.must_get(gate_id)
        if view.verdict is not None:
            raise ValueError(f"gate {gate_id} already decided ({view.verdict})")
        return view

    # ------------------------------------------------------------------
    # The resume bridge
    # ------------------------------------------------------------------

    @staticmethod
    def resume_value(gate_id: str, verdict: str, decided_by: str, reason: str) -> dict[str, Any]:
        """The exact payload the multi-agent gate flow consumes on resume.

        Callers MUST wrap it: `graph.ainvoke(Command(resume=value), config)`.
        """
        return {
            "verdict": verdict,
            "reason": reason,
            "decided_by": decided_by,
        }


# ---------------------------------------------------------------------------
# Decision validation
# ---------------------------------------------------------------------------


def normalize_verdict(raw: Any) -> str:
    """Map client input to 'approve' | 'deny'; anything else -> error."""
    text = str(raw).strip().lower()
    if text in ("approve", "approved", "yes", "allow"):
        return "approve"
    if text in ("deny", "denied", "no", "reject"):
        return "deny"
    raise ApproverError(f"unrecognized verdict: {raw!r}")


def valid_decision(gate_id: str, verdict: str, decided_by: str) -> bool:
    """Cheap shape check shared by tests and the endpoint pre-validation."""
    return bool(gate_id and verdict in ("approve", "deny") and decided_by)
