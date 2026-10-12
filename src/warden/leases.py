"""Ephemeral leases — TTL-scoped ownership of an assigned handoff.

An agent holds a lease on its assignment. Leases exist so semi-trusted
specialists cannot act on a task forever:

- The supervisor grants a lease when it routes work (ttl in seconds).
- Before dispatching across the seam, a specialist calls `evaluate` —
  an EXPIRED lease fail-closes the action (re-escalate to the supervisor,
  re-request after a fresh route — never silently dispatch).
- Same holder re-acquiring its own live lease is idempotent (the ops node
  re-runs at resume and must not lose its lease or deadlock on it).
- A DIFFERENT holder stealing a live lease is refused.

Everything here is pure and IO-free: datetime-in, verdict-out. The clock
is injected (a `Clock` callable) so tests freeze time. The lease itself is
a flat dataclass and serializes to a JSON-safe dict, so the Postgres
checkpointer can persist it inside AgentState across park/resume.

Fail-closed rule (locks 4/5 applied to leases): *missing* or *corrupt*
lease state evaluates to not-held. A specialist without provable custody
does not dispatch.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger("warden.leases")

# A Clock returns the current instant (seconds, monotonic NOT required —
# wall time is correct here because leases bridge park/resume gaps that
# can include a process restart).
Clock = Callable[[], float]


def system_clock() -> float:
    """Default clock: wall time in seconds."""
    import time

    return time.time()


class LeaseVerdict(str, Enum):
    """Result of evaluating a lease for a holder about to act."""

    HELD = "held"          # live lease, correct holder -> dispatch may proceed
    EXPIRED = "expired"    # lease was held once but is now past ttl
    NOT_HELD = "not_held"  # no provable custody: absent/corrupt/wrong holder


@dataclass(frozen=True)
class Lease:
    """Ownership token granted by the supervisor for one assignment."""

    holder: str                 # agent name the lease belongs to (e.g. "ops")
    thread_id: str              # the run/thread the lease covers
    acquired_at: float          # clock() when granted
    ttl_seconds: float          # zero/negative = instantly expired
    purpose: str = ""           # what the lease authorises (e.g. "send_email")

    # ------------------------------------------------------------------
    # Serialization (AgentState must be JSON-safe for the checkpoint store)
    # ------------------------------------------------------------------

    def to_state(self) -> dict[str, Any]:
        """JSON-safe dict for embedding in AgentState."""
        return {
            "holder": self.holder,
            "thread_id": self.thread_id,
            "acquired_at": self.acquired_at,
            "ttl_seconds": self.ttl_seconds,
            "purpose": self.purpose,
        }

    @classmethod
    def from_state(cls, raw: Any) -> Lease | None:
        """Rebuild a Lease from state. None = absent or corrupt (fail-closed).

        Tolerates float/int round-trips through jsonb. Anything not
        matching the shape is treated as no custody rather than raising.
        """
        if not isinstance(raw, dict):
            return None
        holder = raw.get("holder")
        thread_id = raw.get("thread_id")
        acquired = raw.get("acquired_at")
        ttl = raw.get("ttl_seconds")
        if not isinstance(holder, str) or not isinstance(thread_id, str):
            return None
        if isinstance(acquired, bool) or not isinstance(acquired, (int, float)):
            return None
        if isinstance(ttl, bool) or not isinstance(ttl, (int, float)):
            return None
        return cls(
            holder=holder,
            thread_id=thread_id,
            acquired_at=float(acquired),
            ttl_seconds=float(ttl),
            purpose=str(raw.get("purpose", "")),
        )


# ---------------------------------------------------------------------------
# Grant / evaluate
# ---------------------------------------------------------------------------


def grant(
    holder: str,
    thread_id: str,
    ttl_seconds: float,
    *,
    purpose: str = "",
    now: Clock = system_clock,
) -> Lease:
    """Supervisor-path helper: mint a fresh lease for one handoff."""
    return Lease(
        holder=holder,
        thread_id=thread_id,
        acquired_at=now(),
        ttl_seconds=ttl_seconds,
        purpose=purpose,
    )


def evaluate(
    lease: Lease | dict[str, Any] | None,
    holder: str,
    thread_id: str,
    *,
    now: Clock = system_clock,
) -> LeaseVerdict:
    """Can `holder` act on `thread_id` under this lease, right now?

    Rules, in order:
    1. Absent/corrupt lease                -> NOT_HELD (fail-closed)
    2. Thread mismatch                     -> NOT_HELD (wrong run)
    3. Wrong holder                        -> NOT_HELD (not your custody)
    4. Lease age >= ttl                    -> EXPIRED (re-escalate; never silent)
    5. Otherwise                           -> HELD
    """
    parsed = lease if isinstance(lease, Lease) else Lease.from_state(lease)
    if parsed is None:
        logger.debug("lease.eval.not_held.no_lease", extra={"holder": holder})
        return LeaseVerdict.NOT_HELD
    if parsed.thread_id != thread_id:
        logger.info(
            "lease.eval.not_held.thread_mismatch",
            extra={"holder": holder, "lease_thread": parsed.thread_id},
        )
        return LeaseVerdict.NOT_HELD
    if parsed.holder != holder:
        logger.info(
            "lease.eval.not_held.wrong_holder",
            extra={"holder": holder, "lease_holder": parsed.holder},
        )
        return LeaseVerdict.NOT_HELD
    age = now() - parsed.acquired_at
    if age >= parsed.ttl_seconds:
        logger.info(
            "lease.eval.expired",
            extra={
                "holder": holder,
                "age_seconds": round(age, 3),
                "ttl_seconds": parsed.ttl_seconds,
            },
        )
        return LeaseVerdict.EXPIRED
    return LeaseVerdict.HELD


def require(
    lease: Lease | dict[str, Any] | None,
    holder: str,
    thread_id: str,
    *,
    now: Clock = system_clock,
) -> Any:
    """Raise-on-fail variant for callers that want an exception contract.

    Returns the Lease when HELD; raises `LeaseNotHeld` otherwise (the
    message names the verdict so callers can journal the reason).
    """
    verdict = evaluate(lease, holder, thread_id, now=now)
    if verdict is not LeaseVerdict.HELD:
        raise LeaseNotHeld(verdict)
    parsed = lease if isinstance(lease, Lease) else Lease.from_state(lease)
    assert parsed is not None  # evaluate()==HELD implies a parsed lease
    return parsed


class LeaseError(Exception):
    """Base class for lease contract violations."""


class LeaseNotHeld(LeaseError):
    """`require()` raised because the lease is expired/not held."""

    def __init__(self, verdict: LeaseVerdict) -> None:
        self.verdict = verdict
        super().__init__(f"lease not held: {verdict.value}")


def reacquire(
    lease: Lease | dict[str, Any] | None,
    holder: str,
    thread_id: str,
    ttl_seconds: float,
    *,
    purpose: str = "",
    now: Clock = system_clock,
) -> Lease | None:
    """Idempotent re-acquire for a holder re-running on its lease.

    The node re-runs at resume; re-granting blindly would extend every
    resume indefinitely. Policy:
    - no live lease at all (absent or expired) -> grant fresh custody
    - same holder, LIVE lease on same thread   -> return UNCHANGED lease
      (idempotent: no TTL extension on resume)
    - a DIFFERENT holder's live lease          -> refused (None)
    """
    parsed = lease if isinstance(lease, Lease) else Lease.from_state(lease)
    if parsed is not None and parsed.thread_id == thread_id:
        if evaluate(parsed, holder, thread_id, now=now) is LeaseVerdict.HELD:
            # evaluate()==HELD implies holder already matches
            return parsed  # unchanged: resume must not extend the TTL
        if evaluate(parsed, parsed.holder, thread_id, now=now) is LeaseVerdict.HELD:
            # Live lease held by SOMEONE ELSE — no takeover, ever.
            logger.info(
                "lease.reacquire.refused",
                extra={"holder": holder, "lease_holder": parsed.holder},
            )
            return None
    # Expired or absent: ownership returned to the granter (supervisor);
    # a correctly-routed holder may take a fresh one.
    return grant(holder, thread_id, ttl_seconds, purpose=purpose, now=now)


def expires_at(lease: Lease) -> float:
    """Absolute deadline (clock seconds) the lease runs until."""
    return lease.acquired_at + lease.ttl_seconds


def remaining(lease: Lease, *, now: Clock = system_clock) -> float:
    """Seconds left on the lease; 0.0 once expired."""
    left = expires_at(lease) - now()
    return left if left > 0.0 else 0.0


# Sentinel allowing type-safe "None or corrupt or expired" comparisons in
# callers that want to treat all fail cases uniformly.
NOT_HELD_VERDICTS: frozenset[LeaseVerdict] = frozenset(
    {LeaseVerdict.NOT_HELD, LeaseVerdict.EXPIRED}
)


# ---------------------------------------------------------------------------
# Runtime lease policy — the TOGGLE (mutable, shared, read live)
# ---------------------------------------------------------------------------


@dataclass
class LeasePolicy:
    """The mutable runtime knob for lease enforcement. One instance is
    shared with the graph (supervisor + specialists read it live at
    route/check time), so toggling takes effect WITHOUT rebuilding the
    graph:

      - `enabled=False`:  the supervisor still stamps a lease in state
        (keeps the run/audit shape identical) but nobody ENFORCES it;
        `check(state, holder, thread_id)` returns HELD unconditionally.
      - `ttl_seconds`:    read at every grant, so TTL changes apply to
        the next route. Hunting an in-flight handoff requires disabling,
        not shrinking this — by design (a shrunk TTL should not strand
        a mid-flight approved action).

    Default is enforcement ON at 300s: toggles exist to be observable,
    not to silently weaken custody when nobody is looking.
    """

    enabled: bool = True
    ttl_seconds: float = 300.0

    def grant_ttl(self) -> float:
        """TTL the supervisor should grant right now."""
        return self.ttl_seconds

    def check(
        self,
        lease: Lease | dict[str, Any] | None,
        holder: str,
        thread_id: str,
        *,
        now: Clock = system_clock,
    ) -> LeaseVerdict:
        """The enforcement point the specialist nodes call.

        Toggle OFF -> HELD unconditionally (state still carries a lease,
        but nobody enforces it). ON -> the standard fail-closed evaluate.
        """
        if not self.enabled:
            return LeaseVerdict.HELD
        return evaluate(lease, holder, thread_id, now=now)

    def to_state(self) -> dict[str, Any]:
        """JSON-safe view for the toggle card / API responses."""
        return {"enabled": self.enabled, "ttl_seconds": self.ttl_seconds}
