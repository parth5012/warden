"""GuardedExecutor: The single governance seam for all tool and LLM actions.

Core Invariants:
- Lock 1: Both tool and LLM actions cross this single seam (Action.kind in {tool, llm}).
- Lock 2: Pending is returned as explicit data — never an invisible interrupt inside execute().
- Lock 3: Write-ahead logging (action_requested) before policy evaluation with idempotency key (run_id, action_id).
- Lock 4: Fail-closed on governance / policy infrastructure failure -> Error(reason="governance_unavailable").
- Lock 5: Denied is terminal. No human override of a policy deny.
- Lock 7: Sandboxed tools contained via Docker SandboxPort; API tools run in-process.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple

from warden.config import get_groq_llm, settings
from warden.journal import AuditJournal, EventKind, InMemoryJournal, get_journal
from warden.llm.client import GuardedLLMClient
from warden.llm.types import LLMRequest
from warden.models import (
    Action,
    ActionKind,
    Allowed,
    Denied,
    Error,
    ExecutionContext,
    GateDecision,
    GateRequest,
    GateVerdict,
    Outcome,
    Pending,
)
from warden.policy.engine import PolicyDecision, PolicyEngine, PolicyVerdict
from warden.sandbox.docker import DockerSandbox
from warden.sandbox.port import SandboxPort, SandboxUnavailable
from warden.tools import base as tools_base
from warden.tools import deny_tools, hitl_tools, safe_tools, sandbox_tools

HITL_TOOLS: Dict[str, str] = {
    "send_email": "POL_EGRESS_EXTERNAL_MSG",
    "restart_service": "POL_INFRA_MUTATION",
    "batch_delete_files": "SEC-FS-04",
    "sql_schema_migration": "SEC-DB-02",
    "mass_delete": "SEC-FS-04",
}

SANDBOX_TOOLS = {"exec_shell", "shell"}

LLMProviderFn = Callable[[LLMRequest], Awaitable[Any]]


@dataclass
class AgentTelemetry:
    """Telemetry metrics accumulated for an agent across the executor seam."""

    llm_calls: int = 0
    tool_calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    denied: int = 0
    gated: int = 0
    latency_ms: int = 0


class GuardedExecutor:
    """The deep module seam. One interface: execute(action, ctx, approval) -> Outcome."""

    def __init__(
        self,
        journal: Optional[AuditJournal] = None,
        policy: Optional[PolicyEngine] = None,
        sandbox: Optional[SandboxPort] = None,
        llm_provider: Optional[LLMProviderFn] = None,
    ) -> None:
        self.journal: AuditJournal = journal if journal is not None else get_journal()
        self.policy: PolicyEngine = policy if policy is not None else PolicyEngine()
        self._sandbox: Optional[SandboxPort] = sandbox
        self.llm_provider: Optional[LLMProviderFn] = llm_provider
        self.telemetry: Dict[str, AgentTelemetry] = {}

    @property
    def sandbox(self) -> SandboxPort:
        if self._sandbox is None:
            self._sandbox = DockerSandbox(workspace_path=settings.sandbox_workspace)
        return self._sandbox

    def get_telemetry(self, actor: str) -> AgentTelemetry:
        return self.telemetry.setdefault(actor, AgentTelemetry())

    async def execute(
        self,
        action: Action,
        ctx: Optional[ExecutionContext] = None,
        approval: Optional[GateDecision] = None,
    ) -> Outcome:
        """Execute an action across the governance seam.

        Args:
            action: The action to execute (kind=tool or kind=llm).
            ctx: Execution context metadata (actor, thread_id, checkpoint_step).
            approval: Optional human gate decision from a previous Pending outcome.

        Returns:
            Allowed, Denied, Pending, or Error.
        """
        actor = (ctx.actor if ctx else None) or str(action.payload.get("actor", "agent"))
        checkpoint_step = ctx.checkpoint_step if ctx else None
        tele = self.get_telemetry(actor)

        # 1. Write-Ahead Logging (Lock 3)
        self.journal.append(
            EventKind.ACTION_REQUESTED,
            run_id=action.run_id,
            thread_id=action.thread_id,
            actor=actor,
            action_id=action.id,
            checkpoint_step=checkpoint_step,
            status="Proposed",
            description=f"{action.kind.value.upper()} action: {action.name}",
            payload={"name": action.name, "kind": action.kind.value, **action.payload},
        )

        # 2. Policy Evaluation (L0 -> L1 -> L2)
        try:
            verdict = self.policy.evaluate(action.name, action.payload)

            # Static deny guards for tools
            if action.kind == ActionKind.TOOL:
                static_denied: Optional[Denied] = None
                policy_hint = action.payload.get("policy_id")
                if policy_hint in ("SEC-HOST-00", "SEC-DB-01"):
                    static_denied = Denied(
                        reason=str(action.payload.get("policy_reason") or "Terminal Lock 5: Invariant prohibited action"),
                        policy=str(policy_hint),
                    )
                elif action.name in ("exec_db_mutation", "sql_query", "sql_drop") and (
                    action.name == "sql_drop"
                    or any(kw in str(action.payload).lower() for kw in ("drop table", "truncate", "delete from"))
                ):
                    static_denied = deny_tools.check_db_mutation(action.payload)
                    if static_denied and policy_hint:
                        static_denied = Denied(reason=static_denied.reason, policy=str(policy_hint))
                    elif static_denied is None and action.name == "sql_drop":
                        static_denied = Denied(reason="Destructive DDL forbidden by policy", policy=str(policy_hint or "SEC-DB-01"))
                elif any(kw in str(action.payload).lower() for kw in ("/etc/shadow", "/etc/passwd", "/boot")):
                    path_val = str(action.payload.get("path") or action.payload.get("target_resource") or "")
                    static_denied = deny_tools.check_path(path_val) or Denied(
                        reason="Terminal Lock 5: Mutation or deletion of host security configuration (/etc/shadow) is strictly prohibited.",
                        policy=str(policy_hint or "SEC-HOST-00"),
                    )
                    if policy_hint:
                        static_denied = Denied(reason=static_denied.reason, policy=str(policy_hint))
                elif action.name in ("exec_shell", "run_shell"):
                    try:
                        sandbox_tools.validate_shell(action.payload)
                    except ValueError as exc:
                        static_denied = Denied(reason=str(exc), policy=str(policy_hint or "no-destructive-shell"))

                if static_denied is not None:
                    verdict = PolicyVerdict(
                        decision=PolicyDecision.DENY,
                        reason=static_denied.reason,
                        policy=static_denied.policy,
                        layer="L0-static",
                        scores={},
                    )
        except Exception:
            # Policy infrastructure failure -> Fail Closed (Lock 4)
            self.journal.append(
                EventKind.ACTION_FAILED,
                run_id=action.run_id,
                thread_id=action.thread_id,
                actor="PolicyEngine",
                action_id=action.id,
                checkpoint_step=checkpoint_step,
                status="Failed",
                description="Policy evaluation failure — fail closed",
                payload={},
            )
            return Error(reason="governance_unavailable")

        self.journal.append(
            EventKind.POLICY_EVALUATED,
            run_id=action.run_id,
            thread_id=action.thread_id,
            actor="PolicyEngine",
            action_id=action.id,
            checkpoint_step=checkpoint_step,
            status=verdict.decision.value,
            description=f"Policy {verdict.decision.value}: {verdict.reason}",
            payload={"policy": verdict.policy, "layer": verdict.layer},
        )

        # 3. Terminal Deny (Lock 5) — humans cannot override
        if verdict.decision == PolicyDecision.DENY:
            tele.denied += 1
            if action.kind == ActionKind.TOOL:
                tele.tool_calls += 1
            else:
                tele.llm_calls += 1

            self.journal.append(
                EventKind.ACTION_DENIED,
                run_id=action.run_id,
                thread_id=action.thread_id,
                actor="PolicyEngine",
                action_id=action.id,
                checkpoint_step=checkpoint_step,
                status="Denied",
                description=f"DENIED (terminal, Lock 5): {verdict.reason}",
                payload={"policy": verdict.policy, "terminal": True},
            )
            return Denied(reason=verdict.reason, policy=verdict.policy)

        # 4. HITL Escalation (Lock 2)
        policy_hint = action.payload.get("policy_id")
        is_hitl = (
            action.name in HITL_TOOLS
            or policy_hint in ("SEC-FS-04", "SEC-DB-02", "SEC-NET-01")
            or verdict.decision == PolicyDecision.ESCALATE
        )
        if is_hitl:
            rule_id = str(policy_hint or HITL_TOOLS.get(action.name, verdict.policy))
            gate = GateRequest(
                gate_id=f"gate-{action.id}",
                action=action,
                context={"rule_id": rule_id, "reason": verdict.reason, "payload": action.payload},
            )

            if approval is None:
                tele.gated += 1
                self.journal.append(
                    EventKind.GATE_REQUESTED,
                    run_id=action.run_id,
                    thread_id=action.thread_id,
                    actor="GuardedExecutor",
                    action_id=action.id,
                    checkpoint_step=checkpoint_step,
                    status="Pending",
                    description=f"HITL gate parked: {rule_id}",
                    payload={"gate_id": gate.gate_id, "rule_id": rule_id},
                )
                return Pending(gate_request=gate)

            # Record human approver decision
            self.journal.append(
                EventKind.GATE_DECIDED,
                run_id=action.run_id,
                thread_id=action.thread_id,
                actor=f"approver:{approval.decided_by}",
                action_id=action.id,
                checkpoint_step=checkpoint_step,
                status=approval.verdict.value,
                description=f"Human {approval.verdict.value}d: {approval.reason}",
                payload={"gate_id": gate.gate_id, "reason": approval.reason, "verdict": approval.verdict.value},
            )

            if approval.verdict != GateVerdict.APPROVE:
                if action.kind == ActionKind.TOOL:
                    tele.tool_calls += 1
                return Denied(reason=f"Human denied: {approval.reason}", policy=rule_id)

        # 5. Execution (Sandboxed or In-Process)
        start = time.monotonic()
        is_sandbox = action.name in SANDBOX_TOOLS

        self.journal.append(
            EventKind.EXECUTION_STARTED,
            run_id=action.run_id,
            thread_id=action.thread_id,
            actor="GuardedExecutor",
            action_id=action.id,
            checkpoint_step=checkpoint_step,
            status="Started",
            description=f"Executing {action.name}",
            payload={"route": "sandbox" if is_sandbox else "in-process", "kind": action.kind.value},
        )

        try:
            if action.kind == ActionKind.TOOL:
                tele.tool_calls += 1
                result = await self._execute_tool(action, actor, is_sandbox)
            else:
                tele.llm_calls += 1
                result, usage = await self._execute_llm(action)
                tele.prompt_tokens += usage.get("prompt", 0)
                tele.completion_tokens += usage.get("completion", 0)
        except SandboxUnavailable as exc:
            self.journal.append(
                EventKind.ACTION_FAILED,
                run_id=action.run_id,
                thread_id=action.thread_id,
                actor="GuardedExecutor",
                action_id=action.id,
                checkpoint_step=checkpoint_step,
                status="Failed",
                description=f"{action.name} sandbox unavailable — fail closed",
                payload={"error": str(exc)[:200]},
            )
            return Error(reason="governance_unavailable")
        except Exception as exc:
            latency = int((time.monotonic() - start) * 1000)
            tele.latency_ms += latency
            self.journal.append(
                EventKind.ACTION_FAILED,
                run_id=action.run_id,
                thread_id=action.thread_id,
                actor="GuardedExecutor",
                action_id=action.id,
                checkpoint_step=checkpoint_step,
                status="Failed",
                description=f"{action.name} failed: {type(exc).__name__}",
                payload={"error": str(exc)[:200]},
            )
            return Error(reason="governance_unavailable")

        latency = int((time.monotonic() - start) * 1000)
        tele.latency_ms += latency

        self.journal.append(
            EventKind.ACTION_COMPLETED,
            run_id=action.run_id,
            thread_id=action.thread_id,
            actor="GuardedExecutor",
            action_id=action.id,
            checkpoint_step=checkpoint_step,
            status="Succeeded",
            description=f"{action.name} completed in {latency}ms",
            payload={"result": str(result)[:300]},
        )
        return Allowed(result=result)

    async def _execute_tool(self, action: Action, actor: str, is_sandbox: bool) -> Any:
        tool_ctx = tools_base.ToolContext(
            run_id=action.run_id,
            thread_id=action.thread_id,
            actor=actor,
        )

        if action.name == "get_system_metrics":
            return await safe_tools.run_system_metrics(action.payload, tool_ctx)
        elif action.name == "read_service_logs":
            return await safe_tools.run_service_logs(action.payload, tool_ctx)
        elif action.name in ("query_db_readonly", "sql_query"):
            return await safe_tools.run_db_readonly(action.payload, tool_ctx)
        elif action.name in ("send_email", "restart_service", "batch_delete_files", "sql_schema_migration", "mass_delete"):
            return {"status": "sent-after-approval", "tool": action.name}
        elif action.name in ("exec_db_mutation", "read_file_sensitive", "read_file"):
            if action.name == "exec_db_mutation":
                return await deny_tools.run_db_mutation(action.payload)
            return await deny_tools.run_file_read(action.payload)
        elif is_sandbox:
            sandbox_action = Action(
                id=action.id,
                kind=action.kind,
                name="shell",
                payload=action.payload,
                run_id=action.run_id,
                thread_id=action.thread_id,
            )
            sb_result = await self.sandbox.run(sandbox_action)
            return {
                "ok": sb_result.ok,
                "exit_code": sb_result.exit_code,
                "stdout": sb_result.stdout[:500],
                "profile": sb_result.profile,
                "duration_ms": sb_result.duration_ms,
            }
        else:
            return {"status": "executed", "tool": action.name, "payload": action.payload}

    async def _execute_llm(self, action: Action) -> Tuple[str, Dict[str, int]]:
        prompt = str(action.payload.get("prompt") or action.payload.get("messages") or "")
        usage: Dict[str, int] = {"prompt": 0, "completion": 0}

        if self.llm_provider is not None:
            raw = await self.llm_provider(
                LLMRequest(
                    model=action.name,
                    messages=[{"role": "user", "content": prompt}],
                    provider="groq",
                )
            )
            text = str(raw.get("content", raw)) if isinstance(raw, dict) else str(raw)
            return text, usage

        llm = get_groq_llm()
        if llm is None:
            return f"[Offline/Stub response for {prompt[:50]}]", usage

        async def provider(req: LLMRequest) -> Any:
            text = " ".join(str(m.get("content", m)) for m in req.messages)
            return await llm.ainvoke(text)

        captured: list[dict[str, Any]] = []

        async def sink(event: dict[str, Any]) -> None:
            captured.append(event)

        client = GuardedLLMClient(provider_caller=provider, telemetry_sink=sink)
        res = await client.invoke(action)
        if captured:
            usage = {
                "prompt": int(captured[0].get("prompt_tokens", 0)),
                "completion": int(captured[0].get("output_standard_tokens", 0)),
            }
        return str(res.result), usage
