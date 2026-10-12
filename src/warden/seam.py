"""GuardedExecutor — the seam every agent tool call crosses.

One interface: `execute(action) -> Outcome`. This is the first module of the
multi-agent slice and the single choke-point Parth's L1/L2 policy engine
plugs into.

Wiring contract (what this file does NOT do):
- It does NOT route between agents — that is `multi_agent.py`'s supervisor.
- It does NOT parse action contents for "dangerous" patterns — replace
  `SequencingPolicy` with Parth's `PolicyEngine` (same `evaluate` signature).
- It does NOT run subprocesses — the sandbox adapter (Parth's) belongs
  behind the three `TODO` dispatch comments below.

Semantics applied from CONTEXT.md locks:
- lock 1: Action.kind ∈ {tool, llm}; the tool identity lives in `name`.
- lock 2: `execute()` returns Pending explicitly — the *caller* parks.
- lock 4: `execute()` never raises for environmental reasons — only bugs
  raise. Report problems via `Error(reason=...)`.
- lock 5: DENY is terminal: `Denied` carries no resumption path.
"""

from __future__ import annotations

import inspect
import logging
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol

from warden.models import (
    Action,
    ActionKind,
    Allowed,
    Denied,
    Error,
    GateDecision,
    GateRequest,
    GateVerdict,
    Outcome,
    Pending,
)

if TYPE_CHECKING:
    from warden.tools import DockerSandboxPort

logger = logging.getLogger("warden.seam")


# ---------------------------------------------------------------------------
# Policy — a tiny routed table. Parth's engine replaces this wholesale.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SequencingPolicy:
    """Minimal allow/deny/escalate rule table keyed by action `name`.

    Deliberately trivial: Parth's L1/L2 PolicyEngine is the drop-in
    replacement — same call shape, richer internals (L1 fast rules, L2
    pgvector similarity). This stub keeps the multi-agent slice runnable
    before that lands.
    """

    escalate_names: frozenset[str] = frozenset()
    deny_names: frozenset[str] = frozenset()

    def evaluate(self, action: Action) -> str:
        # deny wins over escalate: lock 5 (DENY is terminal)
        if action.name in self.deny_names:
            return "deny"
        if action.name in self.escalate_names:
            return "escalate"
        return "allow"


# ---------------------------------------------------------------------------
# Journal — minimal sink. Parth's AuditJournal is a drop-in superset.
# ---------------------------------------------------------------------------


class JournalSink(Protocol):
    """The only journal surface the seam needs."""

    def append(self, event: str, payload: dict[str, Any], /) -> Awaitable[None]: ...


# ---------------------------------------------------------------------------
# Action factory — the unit that crosses the seam
# ---------------------------------------------------------------------------


def make_action(
    name: str,
    payload: dict[str, Any],
    *,
    kind: str = "tool",
    action_id: str | None = None,
    run_id: str | None = None,
    thread_id: str = "",
) -> Action:
    """Build an `Action` (fresh ids by default). `kind` is 'tool' | 'llm'.

    Pass `action_id` when idempotency matters — e.g. an action that parks
    for human approval MUST produce the same id on the park->resume re-run
    of its node (the gate_id the human saw is the one the approval
    dispatches). Derive it from durable identity (thread_id + action name
    + step), never from a random draw.
    """
    rid = run_id or str(uuid.uuid4())
    return Action(
        id=action_id or str(uuid.uuid4()),
        kind=ActionKind(kind),
        name=name,
        payload=payload,
        run_id=rid,
        thread_id=thread_id,
    )


# ---------------------------------------------------------------------------
# GuardedExecutor
# ---------------------------------------------------------------------------


class GuardedExecutor:
    """The `execute()` seam. All agent side effects funnel through here.

    A multi-agent call site wraps each side effect as an `Action` and calls
    `execute()`. The seam:

      1. journals the attempt (write-ahead intent, best-effort),
      2. asks the policy for allow / deny / escalate,
      3. dispatches on allow, parks on escalate (returns Pending),
      4. journals the completion, one honest verdict back.

    NEVER raises for environmental reasons — one call-site pattern covers
    all four branches.
    """

    def __init__(
        self,
        policy: SequencingPolicy | None = None,
        journal: JournalSink | None = None,
        dispatch: Callable[[Action], Any] | None = None,
    ) -> None:
        self._policy = policy if policy is not None else SequencingPolicy()
        self._journal: JournalSink | None = journal
        self._dispatch: Callable[[Action], Any] = dispatch if dispatch is not None else self._default_dispatch
        # Mutable per-instance dispatch map for the Phase-1 tool catalog path.
        self._TOOL_DISPATCH: dict[str, Callable[[Action], Any]] = {}

    # ------------------------------------------------------------------
    # Convenience: attach a tool-category dispatch map + sandbox port.
    # These are helpers for the caller that wants to wire the Phase-1 tool
    # catalog without constructing a hand-rolled dispatch callable. They do
    # NOT change the seam contract — every tool call still crosses execute().
    # ------------------------------------------------------------------

    def attach_tool_dispatch(self, mapping: dict[str, Callable[[Action], Any]]) -> None:
        """Register per-tool-name dispatch adapters (e.g. the tools.py catalog).

        When the caller passes no explicit `dispatch` to __init__, this map is
        consulted by `_invoke_dispatch` as a fallback. Pass the tool catalog
        mapping from tools.py so each tool routes to its adapter.
        """
        self._TOOL_DISPATCH.update(mapping)

    def attach_sandbox(self, sandbox: "DockerSandboxPort") -> None:
        """Convenience: wire a DockerSandboxPort into the exec_shell dispatch."""
        from warden.tools import attach_sandbox_port

        attach_sandbox_port(sandbox)

    # ------------------------------------------------------------------
    # The seam
    # ------------------------------------------------------------------

    async def execute(
        self, action: Action, *, approval: GateDecision | None = None
    ) -> Outcome:
        """Decide then dispatch. THE one caller for every agent side effect.

        `approval` is set ONLY on re-entry after a human approved the gate
        (decide_after_human calls back into here). An approval IS the allow
        verdict — re-running the policy would escalate again forever.
        """
        if approval is not None and approval.verdict is GateVerdict.APPROVE:
            return await self._dispatch_journaled(action)

        # 1. journal the intent before deciding (write-ahead)
        await self._journal_or_none(
            "action_requested",
            actor=action.name,
            kind=action.kind.value,
            action_id=action.id,
            thread_id=action.thread_id,
            note="write-ahead intent",
        )

        # 2. policy decision (allow | escalate | deny)
        # A policy-engine bug is an internal failure, not a verdict: fail
        # closed (Error) rather than allow-by-accident, and never raise.
        try:
            decision = self._policy.evaluate(action)
        except Exception as exc:
            logger.warning("seam.policy_error", extra={"action_id": action.id, "error": str(exc)})
            return Error(reason=f"policy_engine_failure: {exc}")

        if decision == "deny":
            await self._journal_or_none(
                "action_denied",
                actor=action.name,
                kind=action.kind.value,
                action_id=action.id,
                thread_id=action.thread_id,
                policy="temp_deny_list",
            )
            return Denied(reason="hit the deny list", policy="temp_deny_list")

        if decision == "escalate":
            gate = GateRequest(
                gate_id=action.id,
                action=action,
                context={
                    "actor": action.name,
                    "kind": action.kind.value,
                    "thread_id": action.thread_id,
                },
            )
            await self._journal_or_none(
                "gate_requested",
                actor=action.name,
                kind=action.kind.value,
                action_id=action.id,
                thread_id=action.thread_id,
                gate_id=gate.gate_id,
                ask="human approval needed",
            )
            # lock 2: Pending is data — the caller decides how to park.
            return Pending(gate_request=gate)

        # 3. allowed -> dispatch
        return await self._dispatch_journaled(action)

    async def _dispatch_journaled(self, action: Action) -> Outcome:
        """Run dispatch + journal the completed/failed event. Allowed | Error."""
        try:
            result = await self._invoke_dispatch(action)
        except Exception as exc:  # dispatch failure, not a policy verdict
            await self._journal_or_none(
                "action_failed",
                actor=action.name,
                kind=action.kind.value,
                action_id=action.id,
                thread_id=action.thread_id,
                error=str(exc),
            )
            return Error(reason=f"dispatch_failed: {exc}")

        await self._journal_or_none(
            "action_completed",
            actor=action.name,
            kind=action.kind.value,
            action_id=action.id,
            thread_id=action.thread_id,
            result=_summarize(result),
        )
        return Allowed(result=result)

    # ------------------------------------------------------------------
    # Human decision → dispatch (the second half of the gate)
    # ------------------------------------------------------------------

    async def decide_after_human(
        self, gate: GateRequest, decision: GateDecision
    ) -> Outcome:
        """Re-enter after a human verdict.

        Approve -> dispatch the parked action. Deny -> terminal (lock 5).
        Journaling first keeps the gate's `requested -> decided` trail complete.
        """
        await self._journal_or_none(
            "gate_decided",
            gate_id=gate.gate_id,
            verdict=decision.verdict.value,
            decided_by=decision.decided_by,
            reason=decision.reason,
        )
        if decision.verdict is GateVerdict.DENY:
            return Denied(reason=decision.reason, policy="human_denied")
        # Approve: re-enter with the decision — the approval is the allow
        # verdict, so the policy is NOT re-evaluated (it would escalate again).
        return await self.execute(gate.action, approval=decision)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _invoke_dispatch(self, action: Action) -> dict[str, Any]:
        """Run the caller-provided dispatch; sync functions are supported too.

        If the caller passed an explicit `dispatch` to __init__, use it.
        Otherwise consult the per-tool dispatch map attached via
        `attach_tool_dispatch` (the Phase-1 tool catalog path).
        """
        dispatch = self._dispatch
        if dispatch is self._default_dispatch and self._TOOL_DISPATCH:
            dispatch = self._TOOL_DISPATCH.get(action.name, self._default_dispatch)
        out = dispatch(action)
        if inspect.isawaitable(out):
            out = await out
        return dict(out) if isinstance(out, dict) else {"result": out}

    async def _journal_or_none(
        self,
        event: str,
        **payload: Any,
    ) -> None:
        """Best-effort journal write — telemetry never breaks the action."""
        if self._journal is None:
            return
        try:
            out = self._journal.append(event, payload)
            if inspect.isawaitable(out):
                await out
        except Exception as exc:
            logger.warning("seam.journal_failed", extra={"event": event, "error": str(exc)})

    @staticmethod
    async def _default_dispatch(action: Action) -> dict[str, Any]:
        """Default dispatch: honest no-op so tests can run without a backend."""
        return {"ok": True, "name": action.name, "simulated": True}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _summarize(result: Any) -> Any:
    """Journal-safe summary — no raw payload blobs in the audit log."""
    if isinstance(result, dict):
        keep = ("ok", "to", "from", "command", "simulated", "name")
        return {k: v for k, v in result.items() if k in keep}
    return result
