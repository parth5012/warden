"""Resolve journal-projected tool gates from the Interception Gate itself.

Chat-tool escalations park as `gate_requested` journal events and are approved
in the chat thread via `POST /chat/actions/{id}/decision`. This module lets the
Interception Gate (`/inbox`) approve/deny those same gates directly: it
rebuilds the original `Action` from its journaled `action_requested` event,
re-enters `GuardedExecutor.execute()` with the operator's `GateDecision`, and
syncs the verdict back into the parking chat message when its session is in
memory — so both surfaces agree without two approval stores.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict

# Ensure src/ is importable in all runtimes (mirrors app/chat.py).
SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from app.audit import JOURNAL_STORE
from warden.executor import GuardedExecutor
from warden.models import (
    Action,
    ActionKind,
    Allowed,
    Denied,
    Error,
    ExecutionContext,
    GateDecision,
    GateVerdict,
    Pending,
)


def _request_event(action_id: str) -> Any | None:
    related, _ = JOURNAL_STORE.list_events(action_id=action_id, limit=20)
    for event in related:
        if event.kind == "action_requested":
            return event
    return None


def _sync_chat_session(action_id: str, verdict: str, note: str) -> None:
    """Mirror the decision into the parking chat message, if its session lives."""
    try:
        from app.chat import CHAT_SESSIONS
    except Exception:
        return
    for session in CHAT_SESSIONS.values():
        for msg in session:
            proposal = getattr(msg, "action_proposal", None)
            if proposal and proposal.get("id") == action_id:
                msg.verdict = verdict
                msg.execution_result = note
                return


async def resolve_tool_gate(
    gate_id: str,
    verdict: str,
    decided_by: str,
) -> Dict[str, Any]:
    """Approve or deny a journal-projected tool gate by its gate id.

    Returns a dict with `ok`, `outcome` (`approved`/`denied`/`denied_by_policy`/
    `error`), a human `message`, plus `action_id`/`thread_id`/`action_name`.
    """
    clean_verdict = verdict.strip().lower()
    if clean_verdict not in ("approve", "deny"):
        return {"ok": False, "error": "invalid_decision"}

    from app.projections import live_pending_gates

    pending = {str(g.get("id")): g for g in live_pending_gates(limit=500)}
    gate = pending.get(gate_id)
    if gate is None:
        return {"ok": False, "error": "not_found"}

    action_id = str(gate.get("action_id") or "")
    thread_id = str(gate.get("thread_id") or "")
    action_name = str(gate.get("action_name") or "tool")
    requested = _request_event(action_id)
    if requested is None:
        return {"ok": False, "error": "action_not_found"}

    request_payload = dict(requested.payload or {})
    try:
        kind = ActionKind(str(request_payload.get("kind", ActionKind.TOOL.value)))
    except ValueError:
        kind = ActionKind.TOOL
    inner = request_payload.get("payload")
    tool_payload = dict(inner) if isinstance(inner, dict) else {}

    action = Action(
        id=action_id,
        kind=kind,
        name=str(request_payload.get("name") or action_name),
        payload=tool_payload,
        run_id=requested.run_id,
        thread_id=requested.thread_id or thread_id,
    )

    who = (decided_by or "").strip() or "operator"
    approved = clean_verdict == "approve"
    decision = GateDecision(
        gate_id=gate_id,
        verdict=GateVerdict.APPROVE if approved else GateVerdict.DENY,
        reason=f"{'Authorized' if approved else 'Rejected'} by {who} via Interception Gate",
        decided_by=who,
    )
    ctx = ExecutionContext(
        actor=str(gate.get("actor") or requested.actor or "OpsAssistant"),
        run_id=requested.run_id,
        thread_id=requested.thread_id or thread_id,
    )
    outcome = await GuardedExecutor(journal=JOURNAL_STORE).execute(
        action, ctx, approval=decision
    )

    if isinstance(outcome, Allowed):
        message = f"Approved by {who}. Executed successfully."
        result: Dict[str, Any] = {
            "ok": True,
            "outcome": "approved",
            "message": message,
        }
        _sync_chat_session(action_id, "approved", message)
    elif isinstance(outcome, Denied):
        if not approved:
            message = f"Rejected by {who}. Action was aborted; no side effects occurred."
            result = {"ok": True, "outcome": "denied", "message": message}
        else:
            message = f"Denied on re-evaluation: {outcome.reason}"
            result = {"ok": True, "outcome": "denied_by_policy", "message": message}
        _sync_chat_session(
            action_id, "denied", message if not approved else (
                f"Rejected on re-evaluation ({outcome.policy}). {outcome.reason}"
            ),
        )
    elif isinstance(outcome, Pending):
        message = "Still pending after decision; gate was recreated."
        result = {"ok": False, "error": "still_pending", "message": message}
    elif isinstance(outcome, Error):
        message = f"Execution failed: {outcome.reason}"
        result = {"ok": False, "error": "execution_failed", "message": message}
    else:  # pragma: no cover - defensive
        message = "Unexpected outcome from governed execution."
        result = {"ok": False, "error": "unknown_outcome", "message": message}

    result.update(
        {
            "action_id": action_id,
            "thread_id": thread_id,
            "action_name": action.name,
            "gate_id": gate_id,
            "decided_by": who,
        }
    )
    return result
