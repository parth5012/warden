"""Journal projections: pure `events -> view` derivations (per CONTEXT.md).

The AuditJournal is the source of truth. Sandbox runs and policy-evaluation
feeds below are derived from journaled seam events, so anything an agent does
through the chat console (or any GuardedExecutor caller) shows up in the UI
panels with no per-caller bookkeeping.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from typing import Any, Dict, List

from app.audit import JOURNAL_STORE

_LATENCY_RE = re.compile(r"(\d+)\s*ms")


def _payload(event: Any) -> Dict[str, Any]:
    payload = getattr(event, "payload", None)
    return dict(payload) if isinstance(payload, dict) else {}


def _requested_by_action(action_id: str) -> Any | None:
    """Find the ACTION_REQUESTED event carrying an action's identity + payload."""
    if not action_id:
        return None
    related, _ = JOURNAL_STORE.list_events(action_id=action_id, limit=20)
    for event in related:
        if event.kind == "action_requested":
            return event
    return None


def recent_policy_evaluations(limit: int = 10) -> List[Dict[str, Any]]:
    """Newest-first seam checks: evaluations, terminal denies, and HITL gates."""
    gathered: List[Any] = []
    for kind in ("policy_evaluated", "action_denied", "gate_requested"):
        events, _ = JOURNAL_STORE.list_events(kind=kind, limit=limit)
        gathered.extend(events)
    gathered.sort(key=lambda e: e.ts, reverse=True)

    evaluations: List[Dict[str, Any]] = []
    for event in gathered[:limit]:
        payload = _payload(event)
        if event.kind == "gate_requested":
            rule = str(payload.get("rule_id", "?"))
            verdict = "escalate"
        else:
            rule = str(payload.get("policy", "?"))
            verdict = (event.status or "").lower()
        action_name = ""
        actor = event.actor
        requested = _requested_by_action(event.action_id or "")
        if requested is not None:
            action_name = str(requested.payload.get("name", ""))
            actor = requested.actor or actor
        evaluations.append(
            {
                "ts": event.ts,
                "policy": rule,
                "layer": str(payload.get("layer", "?")),
                "verdict": verdict,
                "reason": event.description,
                "actor": actor,
                "action_id": event.action_id or "",
                "action_name": action_name,
            }
        )
    return evaluations


def policy_trigger_counts(limit: int = 500) -> Dict[str, int]:
    """Live per-rule hit counts from evaluation, denial, and gate events."""
    counter: Counter[str] = Counter()
    for kind in ("policy_evaluated", "action_denied", "gate_requested"):
        events, _ = JOURNAL_STORE.list_events(kind=kind, limit=limit)
        for event in events:
            payload = _payload(event)
            rule = str(payload.get("policy") or payload.get("rule_id") or "").strip()
            if rule and rule != "?":
                counter[rule] += 1
    return dict(counter)


def _summarize_payload(action_payload: Dict[str, Any]) -> str:
    """Compact human-readable command/payload preview for the runs table."""
    for key in ("command", "statement", "sql"):
        value = action_payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()[:300]
    try:
        return json.dumps(action_payload, default=str)[:300]
    except (TypeError, ValueError):
        return str(action_payload)[:300]


def live_sandbox_runs(limit: int = 50) -> List[Dict[str, Any]]:
    """Full-shape sandbox run rows projected from execution seam events.

    One row per EXECUTION_STARTED action; completion/failure details are
    joined by action_id. Rows carry every key the sandbox table, filters,
    metrics, and log drawer read.
    """
    started, _ = JOURNAL_STORE.list_events(kind="execution_started", limit=limit)
    runs: List[Dict[str, Any]] = []
    for event in started:
        action_id = event.action_id or ""
        payload = _payload(event)
        requested = _requested_by_action(action_id)

        agent = event.actor
        tool_name = ""
        command = ""
        if requested is not None:
            agent = requested.actor or agent
            request_payload = _payload(requested)
            tool_name = str(request_payload.get("name", ""))
            command = _summarize_payload(
                {k: v for k, v in request_payload.items() if k not in ("name", "kind")}
            )

        status = "SUCCESS"
        exit_code = 0
        stdout = ""
        stderr = ""
        duration_ms = 0
        executed_at = event.ts
        related, _ = JOURNAL_STORE.list_events(action_id=action_id, limit=10)
        for rel in related:
            if rel.kind == "action_completed":
                executed_at = rel.ts or executed_at
                completion = _payload(rel)
                stdout = str(completion.get("result", ""))[:2000]
                match = _LATENCY_RE.search(rel.description or "")
                if match:
                    duration_ms = int(match.group(1))
            elif rel.kind == "action_failed":
                status = "FAILED"
                exit_code = 1
                executed_at = rel.ts or executed_at
                failure = _payload(rel)
                stderr = str(failure.get("error", rel.description))[:2000]

        route = str(payload.get("route", "in-process"))
        if route == "sandbox":
            adapter = "Docker Sandbox (chat dispatch)"
            adapter_short = "docker_chat"
        else:
            adapter = "In-Process Safe Adapter"
            adapter_short = "in_process"

        runs.append(
            {
                "id": f"live_{action_id}" if action_id else f"live_{event.id}",
                "action_id": action_id,
                "agent": agent,
                "tool_name": tool_name,
                "adapter": adapter,
                "adapter_short": adapter_short,
                "command": command,
                "exit_code": exit_code,
                "status": status,
                "duration_ms": duration_ms,
                "cpu_ms": 0,
                "peak_memory_mb": 0.0,
                "scrubbed_secrets_count": 0,
                "scrubbed_secrets": [],
                "executed_at": executed_at,
                "stdout": stdout,
                "stderr": stderr,
            }
        )
    return runs
