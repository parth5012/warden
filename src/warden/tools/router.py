"""ToolRouter: preview-only dispatcher over EXISTING seams.

No executor/journal/runner created here. preview() is pure (no side
effects): it runs the existing PolicyEngine and maps the verdict onto
warden.models Outcome types so the future GuardedExecutor can adopt it
unchanged. Groq is the core LLM: get_router_llm() returns the configured
ChatOpenAI client (may be None without GROQ_API_KEY); LLM actions
(kind=llm) skip sandbox — timeout + token accounting only (lock 7).
"""

from __future__ import annotations

import uuid
from typing import Any

from warden.config import get_groq_llm
from warden.models import Action, ActionKind, Allowed, Denied, Error, GateRequest, Outcome, Pending
from warden.policy.engine import PolicyDecision, PolicyEngine, PolicyError

_SAFE_ALLOW = ("get_system_metrics", "read_service_logs", "query_db_readonly")
_ESCALATING_TOOLS = ("send_email", "restart_service")
_RULE_FOR_TOOL = {
    "send_email": "POL_EGRESS_EXTERNAL_MSG",
    "restart_service": "POL_INFRA_MUTATION",
}


class ToolRouter:
    """Pure preview router: Action -> Outcome (no IO, no sandbox dispatch)."""

    def __init__(self, policy: PolicyEngine | None = None) -> None:
        self._policy = policy or PolicyEngine()

    def preview(self, action: Action) -> Outcome:
        try:
            verdict = self._policy.evaluate(action.name, action.payload)
        except PolicyError:
            return Error(reason="governance_unavailable")
        except Exception:
            return Error(reason="governance_unavailable")
        if verdict.decision == PolicyDecision.DENY:
            return Denied(reason=verdict.reason, policy=verdict.policy)
        from warden.tools import deny_tools
        static = None
        if action.name == "exec_db_mutation":
            static = deny_tools.check_db_mutation(action.payload, self._policy)
        elif action.name == "read_file_sensitive":
            static = deny_tools.check_path(str(action.payload.get("path", "")))
        if static is not None:
            return static
        if action.name in _ESCALATING_TOOLS or verdict.decision == PolicyDecision.ESCALATE:
            rule = _RULE_FOR_TOOL.get(action.name, verdict.policy)
            gate = GateRequest(
                gate_id=f"gate-{action.id}",
                action=action,
                context={"rule_id": rule, "reason": verdict.reason},
            )
            return Pending(gate_request=gate)
        if action.name == "exec_shell":
            return Allowed(result={"route": "sandbox", "fast_path": False})
        return Allowed(result={"fast_path": True, "reason": verdict.reason})

    def describe_demo_flow(self) -> list[dict[str, str]]:
        return [
            {"beat": "1-safe-reads", "tools": "get_system_metrics + query_db_readonly", "outcome": "ALLOW fast-path"},
            {"beat": "2-hitl-gate", "tools": "send_email", "outcome": "Pending POL_EGRESS_EXTERNAL_MSG"},
            {"beat": "3-hard-deny", "tools": "exec_db_mutation DROP TABLE", "outcome": "DENIED terminal"},
            {"beat": "4-sandbox", "tools": "exec_shell rm -rf", "outcome": "sandbox containment"},
        ]


def get_router_llm() -> Any | None:
    """Return the configured Groq client, or None when unconfigured."""
    return get_groq_llm()


async def draft_with_groq(prompt: str) -> str:
    """Draft via Groq; deterministic stub when unconfigured/offline."""
    llm = get_router_llm()
    if llm is None:
        return "Groq unavailable — stub draft: weekly ops report ready"
    try:
        response = llm.invoke(f"Draft a concise one-sentence ops summary for: {prompt}")
        content = getattr(response, "content", response)
        text = str(content).strip().replace("\n", " ")
        return text or "Groq unavailable — stub draft: weekly ops report ready"
    except Exception:
        return "Groq unavailable — stub draft: weekly ops report ready"


def make_tool_action(name: str, payload: dict[str, Any], run_id: str, thread_id: str) -> Action:
    return Action(
        id=f"act_{uuid.uuid4().hex[:12]}",
        kind=ActionKind.TOOL,
        name=name,
        payload=dict(payload),
        run_id=run_id,
        thread_id=thread_id,
    )


__all__ = [
    "ToolRouter",
    "draft_with_groq",
    "get_router_llm",
    "make_tool_action",
]
