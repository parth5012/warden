"""Governed multi-agent demo: ONE enforced path for every action.

DEMO-GRADE seam (not the production GuardedExecutor): every agent action —
both LLM and tool calls — flows through GovernedRunner.run(), which enforces
write-ahead journaling -> PolicyEngine verdict -> HITL approval on escalate
-> sandboxed/in-process execution -> completion journaling -> telemetry.

Locks honored: Pending is data (lock 2), DENY terminal (lock 5), fail-closed
Error on infra failure (lock 4), LLM crosses the seam with usage journaled
(lock 1), DockerSandbox containment (lock 7).

Run:  uv run python scripts/governed_demo.py [--auto-approve NAME] [--out DIR]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from app.audit import (  # noqa: E402
    EventKind,
    JournalEvent,
    VerificationStatus,
    calculate_event_hash,
    verify_hash_chain,
)
from warden.config import get_groq_llm, settings  # noqa: E402
from warden.llm.client import GuardedLLMClient  # noqa: E402
from warden.llm.types import LLMRequest  # noqa: E402
from warden.models import (  # noqa: E402
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
from warden.policy.engine import PolicyDecision, PolicyEngine  # noqa: E402
from warden.sandbox.docker import DockerSandbox  # noqa: E402
from warden.sandbox.port import SandboxUnavailable  # noqa: E402
from warden.tools import base as tools_base  # noqa: E402
from warden.tools import deny_tools, hitl_tools, safe_tools, sandbox_tools  # noqa: E402

HITL_TOOLS = {"send_email": "POL_EGRESS_EXTERNAL_MSG", "restart_service": "POL_INFRA_MUTATION"}
SANDBOX_TOOLS = {"exec_shell"}


# ---------------------------------------------------------------------------
# Live journal (hash-chained, in-memory; reuses app.audit event model)
# ---------------------------------------------------------------------------

class LiveJournal:
    """Append-only live journal. Fresh per run — no seeded demo events."""

    def __init__(self) -> None:
        self._events: list[JournalEvent] = []

    def append(
        self, kind: str, *, run_id: str, thread_id: str, actor: str,
        action_id: str | None = None, status: str = "",
        description: str = "", payload: dict[str, Any] | None = None,
    ) -> JournalEvent:
        prev = self._events[-1].event_hash if self._events else None
        raw: dict[str, Any] = {
            "id": f"ev_{uuid.uuid4().hex[:10]}",
            "run_id": run_id, "thread_id": thread_id, "action_id": action_id,
            "checkpoint_step": None, "kind": kind, "actor": actor,
            "status": status, "description": description,
            "payload": payload or {}, "ts": datetime.now(timezone.utc).isoformat(),
            "prev_hash": prev,
        }
        raw["event_hash"] = calculate_event_hash(raw)
        raw["verification_status"] = VerificationStatus.VERIFIED
        ev = JournalEvent(**raw)
        self._events.append(ev)
        return ev

    @property
    def events(self) -> list[JournalEvent]:
        return list(self._events)

    def verify(self) -> tuple[VerificationStatus, str | None]:
        return verify_hash_chain(self._events)


# ---------------------------------------------------------------------------
# Governed runner: the single enforced path (demo-grade)
# ---------------------------------------------------------------------------

ApproverFn = Callable[[GateRequest], Awaitable[GateDecision]]
LLMProviderFn = Callable[[LLMRequest], Awaitable[Any]]


@dataclass
class AgentTelemetry:
    llm_calls: int = 0
    tool_calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    denied: int = 0
    gated: int = 0
    latency_ms: int = 0


@dataclass
class GovernedRunner:
    """Enforces journal -> policy -> HITL -> execute -> journal for every action."""

    journal: LiveJournal
    policy: PolicyEngine = field(default_factory=PolicyEngine)
    approve: ApproverFn | None = None
    llm_provider: LLMProviderFn | None = None
    actor: str = "governed-runner"
    telemetry: dict[str, AgentTelemetry] = field(default_factory=dict)

    def _tele(self, agent: str) -> AgentTelemetry:
        return self.telemetry.setdefault(agent, AgentTelemetry())

    async def run_llm(self, *, agent: str, run_id: str, thread_id: str, prompt: str) -> Outcome:
        """LLM action across the seam: policy screen -> GuardedLLMClient -> journal."""
        tele = self._tele(agent)
        action = Action(
            id=f"act_{uuid.uuid4().hex[:10]}", kind=ActionKind.LLM,
            name=settings.groq_model, payload={"model": settings.groq_model, "prompt": prompt},
            run_id=run_id, thread_id=thread_id,
        )
        self.journal.append(EventKind.ACTION_REQUESTED.value, run_id=run_id,
                            thread_id=thread_id, actor=agent, action_id=action.id,
                            status="Proposed", description=f"LLM call: {prompt[:80]}",
                            payload={"model": settings.groq_model})
        try:
            verdict = self.policy.evaluate(action.name, {"prompt": prompt})
        except Exception:
            self.journal.append(EventKind.ACTION_FAILED.value, run_id=run_id,
                                thread_id=thread_id, actor="PolicyEngine",
                                action_id=action.id, status="Failed",
                                description="Policy infra failure — fail closed",
                                payload={})
            return Error(reason="governance_unavailable")
        if verdict.decision == PolicyDecision.DENY:
            tele.denied += 1
            self.journal.append(EventKind.ACTION_DENIED.value, run_id=run_id,
                                thread_id=thread_id, actor="PolicyEngine",
                                action_id=action.id, status="Denied",
                                description=f"DENIED (terminal): {verdict.reason}",
                                payload={"policy": verdict.policy})
            return Denied(reason=verdict.reason, policy=verdict.policy)
        start = time.monotonic()
        try:
            result_text, usage = await self._invoke_llm(prompt)
        except Exception as exc:
            latency = int((time.monotonic() - start) * 1000)
            tele.latency_ms += latency
            self.journal.append(EventKind.ACTION_FAILED.value, run_id=run_id,
                                thread_id=thread_id, actor="LLMClient",
                                action_id=action.id, status="Failed",
                                description=f"LLM failed: {type(exc).__name__}",
                                payload={"error": str(exc)[:200]})
            return Error(reason="governance_unavailable")
        latency = int((time.monotonic() - start) * 1000)
        tele.llm_calls += 1
        tele.latency_ms += latency
        tele.prompt_tokens += usage.get("prompt", 0)
        tele.completion_tokens += usage.get("completion", 0)
        self.journal.append(EventKind.ACTION_COMPLETED.value, run_id=run_id,
                            thread_id=thread_id, actor="LLMClient",
                            action_id=action.id, status="Succeeded",
                            description=f"LLM completed in {latency}ms",
                            payload={"model": settings.groq_model, **usage})
        return Allowed(result=result_text)

    async def _invoke_llm(self, prompt: str) -> tuple[str, dict[str, int]]:
        usage: dict[str, int] = {"prompt": 0, "completion": 0}
        if self.llm_provider is not None:
            raw = await self.llm_provider(LLMRequest(model=settings.groq_model, messages=[
                {"role": "user", "content": prompt}], provider="groq"))
            text = str(raw.get("content", raw)) if isinstance(raw, dict) else str(raw)
            return text, usage
        llm = get_groq_llm()
        if llm is None:
            return "Groq unavailable — stub draft", usage

        async def provider(req: LLMRequest) -> Any:
            text = " ".join(str(m.get("content", m)) for m in req.messages)
            return await llm.ainvoke(text)

        captured: list[dict[str, Any]] = []

        async def sink(event: dict[str, Any]) -> None:
            captured.append(event)

        client = GuardedLLMClient(provider_caller=provider, telemetry_sink=sink)
        action = Action(id=f"act_{uuid.uuid4().hex[:10]}", kind=ActionKind.LLM,
                        name=settings.groq_model,
                        payload={"model": settings.groq_model, "provider": "groq",
                                 "messages": [{"role": "user", "content": prompt}],
                                 "max_tokens": 200},
                        run_id="run_llm", thread_id="thr_llm")
        res = await client.invoke(action)
        if captured:
            usage = {"prompt": int(captured[0].get("prompt_tokens", 0)),
                     "completion": int(captured[0].get("output_standard_tokens", 0))}
        return str(res.result), usage

    async def run_tool(self, *, agent: str, run_id: str, thread_id: str,
                       tool: str, payload: dict[str, Any]) -> Outcome:
        """Tool action across the seam: journal -> policy -> [HITL] -> execute -> journal."""
        tele = self._tele(agent)
        ctx = tools_base.ToolContext(run_id=run_id, thread_id=thread_id, actor=agent)
        spec = {"get_system_metrics": safe_tools.GET_SYSTEM_METRICS_SPEC,
                "read_service_logs": safe_tools.READ_SERVICE_LOGS_SPEC,
                "query_db_readonly": safe_tools.QUERY_DB_READONLY_SPEC,
                "send_email": hitl_tools.SEND_EMAIL_SPEC,
                "restart_service": hitl_tools.RESTART_SERVICE_SPEC,
                "exec_db_mutation": deny_tools.EXEC_DB_MUTATION_SPEC,
                "read_file_sensitive": deny_tools.READ_FILE_SENSITIVE_SPEC,
                "exec_shell": sandbox_tools.EXEC_SHELL_SPEC}[tool]
        action = tools_base.make_action(spec, payload, ctx)
        if tool == "exec_shell":
            # registry profile name mapping (docker looks up action.name)
            action = Action(id=action.id, kind=action.kind, name="shell",
                            payload=action.payload, run_id=run_id, thread_id=thread_id)
        self.journal.append(EventKind.ACTION_REQUESTED.value, run_id=run_id,
                            thread_id=thread_id, actor=agent, action_id=action.id,
                            status="Proposed", description=f"Tool call: {tool}",
                            payload={k: str(v)[:200] for k, v in payload.items()})
        try:
            verdict = self.policy.evaluate(tool, payload)
            # Tool-aware static guards (what the executor classifier enforces):
            static_denied: Denied | None = None
            if tool == "exec_db_mutation":
                static_denied = deny_tools.check_db_mutation(payload)
            elif tool == "read_file_sensitive":
                static_denied = deny_tools.check_path(str(payload.get("path", "")))
            elif tool == "exec_shell":
                try:
                    sandbox_tools.validate_shell(payload)
                except ValueError as exc:
                    static_denied = Denied(reason=str(exc), policy="no-destructive-shell")
            if static_denied is not None:
                from warden.policy.engine import PolicyVerdict  # noqa: E402
                verdict = PolicyVerdict(decision=PolicyDecision.DENY,
                                        reason=static_denied.reason,
                                        policy=static_denied.policy, layer="L0-static",
                                        scores={})
        except Exception:
            self.journal.append(EventKind.ACTION_FAILED.value, run_id=run_id,
                                thread_id=thread_id, actor="PolicyEngine",
                                action_id=action.id, status="Failed",
                                description="Policy infra failure — fail closed",
                                payload={})
            return Error(reason="governance_unavailable")
        self.journal.append(EventKind.POLICY_EVALUATED.value, run_id=run_id,
                            thread_id=thread_id, actor="PolicyEngine",
                            action_id=action.id, status=verdict.decision.value,
                            description=f"Policy {verdict.decision.value}: {verdict.reason}",
                            payload={"policy": verdict.policy, "layer": verdict.layer})
        if verdict.decision == PolicyDecision.DENY:
            tele.denied += 1
            tele.tool_calls += 1
            self.journal.append(EventKind.ACTION_DENIED.value, run_id=run_id,
                                thread_id=thread_id, actor="PolicyEngine",
                                action_id=action.id, status="Denied",
                                description=f"DENIED (terminal, lock 5): {verdict.reason}",
                                payload={"policy": verdict.policy, "terminal": True})
            return Denied(reason=verdict.reason, policy=verdict.policy)
        if tool in HITL_TOOLS or verdict.decision == PolicyDecision.ESCALATE:
            tele.gated += 1
            return await self._gated(agent, run_id, thread_id, tool, payload, action,
                                     HITL_TOOLS.get(tool, verdict.policy), tele)
        return await self._execute(agent, run_id, thread_id, tool, payload, action, tele)

    async def _gated(self, agent: str, run_id: str, thread_id: str, tool: str,
                     payload: dict[str, Any], action: Action, rule: str,
                     tele: AgentTelemetry) -> Outcome:
        gate = GateRequest(gate_id=f"gate-{action.id}", action=action,
                           context={"rule_id": rule, "payload": {k: str(v)[:200] for k, v in payload.items()}})
        self.journal.append(EventKind.GATE_REQUESTED.value, run_id=run_id,
                            thread_id=thread_id, actor="GovernedRunner",
                            action_id=action.id, status="Pending",
                            description=f"HITL gate parked: {rule}",
                            payload={"gate_id": gate.gate_id, "rule_id": rule})
        if self.approve is None:
            return Pending(gate_request=gate)
        decision = await self.approve(gate)
        self.journal.append("gate_decided", run_id=run_id, thread_id=thread_id,
                            actor=f"approver:{decision.decided_by}", action_id=action.id,
                            status=decision.verdict.value,
                            description=f"Human {decision.verdict.value}d: {decision.reason}",
                            payload={"gate_id": gate.gate_id, "reason": decision.reason})
        if decision.verdict != GateVerdict.APPROVE:
            tele.tool_calls += 1
            return Denied(reason=f"Human denied: {decision.reason}", policy=rule)
        return await self._execute(agent, run_id, thread_id, tool, payload, action, tele)

    async def _execute(self, agent: str, run_id: str, thread_id: str, tool: str,
                       payload: dict[str, Any], action: Action,
                       tele: AgentTelemetry) -> Outcome:
        tele.tool_calls += 1
        start = time.monotonic()
        self.journal.append(EventKind.EXECUTION_STARTED.value, run_id=run_id,
                            thread_id=thread_id, actor="GovernedRunner",
                            action_id=action.id, status="Started",
                            description=f"Executing {tool}",
                            payload={"route": "sandbox" if tool in SANDBOX_TOOLS else "in-process"})
        try:
            if tool == "get_system_metrics":
                result: Any = await safe_tools.run_system_metrics(payload, tools_base.ToolContext(run_id, thread_id, agent))
            elif tool == "read_service_logs":
                result = await safe_tools.run_service_logs(payload, tools_base.ToolContext(run_id, thread_id, agent))
            elif tool == "query_db_readonly":
                result = await safe_tools.run_db_readonly(payload, tools_base.ToolContext(run_id, thread_id, agent))
            elif tool in ("send_email", "restart_service"):
                result = {"status": "sent-after-approval", "tool": tool}
            elif tool == "exec_db_mutation":
                try:
                    result = await deny_tools.run_db_mutation(payload)
                except PermissionError as exc:
                    return Denied(reason=str(exc), policy="no-destructive-sql")
            elif tool == "read_file_sensitive":
                try:
                    result = await deny_tools.run_file_read(payload)
                except PermissionError as exc:
                    return Denied(reason=str(exc), policy="path-acl")
            elif tool == "exec_shell":
                sandbox = DockerSandbox(workspace_path=settings.sandbox_workspace)
                result = await sandbox.run(action)
                result = {"ok": result.ok, "exit_code": result.exit_code,
                          "stdout": result.stdout[:500], "profile": result.profile,
                          "duration_ms": result.duration_ms}
            else:
                raise RuntimeError(f"no execution route for {tool}")
        except SandboxUnavailable as exc:
            self.journal.append(EventKind.ACTION_FAILED.value, run_id=run_id,
                                thread_id=thread_id, actor="GovernedRunner",
                                action_id=action.id, status="Failed",
                                description=f"{tool} sandbox unavailable — fail closed",
                                payload={"error": str(exc)[:200]})
            return Error(reason="governance_unavailable")
        except Exception as exc:
            latency = int((time.monotonic() - start) * 1000)
            self.journal.append(EventKind.ACTION_FAILED.value, run_id=run_id,
                                thread_id=thread_id, actor="GovernedRunner",
                                action_id=action.id, status="Failed",
                                description=f"{tool} failed: {type(exc).__name__}",
                                payload={"error": str(exc)[:200]})
            return Error(reason="governance_unavailable")
        latency = int((time.monotonic() - start) * 1000)
        tele.latency_ms += latency
        self.journal.append(EventKind.ACTION_COMPLETED.value, run_id=run_id,
                            thread_id=thread_id, actor="GovernedRunner",
                            action_id=action.id, status="Succeeded",
                            description=f"{tool} completed in {latency}ms",
                            payload={"result_preview": str(result)[:300]})
        return Allowed(result=result)


# ---------------------------------------------------------------------------
# Demo agents (share one runner + journal = multi-agent governance)
# ---------------------------------------------------------------------------

async def ops_assistant(runner: GovernedRunner, run_id: str) -> list[str]:
    """Ops agent: reads -> gated email -> denied DDL -> sandboxed cleanup."""
    tid, notes = "thr_ops", []
    draft = await runner.run_llm(agent="ops-assistant", run_id=run_id,
                                 thread_id=tid, prompt="One-sentence weekly ops summary")
    notes.append(f"draft: {getattr(draft, 'result', draft)}")
    out = await runner.run_tool(agent="ops-assistant", run_id=run_id, thread_id=tid,
                                tool="get_system_metrics",
                                payload={"service": "orders", "metric": "cpu", "window_minutes": 15})
    notes.append(f"metrics: {type(out).__name__}")
    out = await runner.run_tool(agent="ops-assistant", run_id=run_id, thread_id=tid,
                                tool="send_email",
                                payload={"recipient": "ops-team@example.com",
                                         "subject": "Weekly ops report", "body": "All green."})
    notes.append(f"email: {type(out).__name__}")
    out = await runner.run_tool(agent="ops-assistant", run_id=run_id, thread_id=tid,
                                tool="exec_db_mutation", payload={"sql": "DROP TABLE old_logs;"})
    notes.append(f"drop: {type(out).__name__}")
    out = await runner.run_tool(agent="ops-assistant", run_id=run_id, thread_id=tid,
                                tool="exec_shell", payload={"command": "ls /workspace && echo cleaned"})
    notes.append(f"shell: {type(out).__name__}")
    return notes


async def db_researcher(runner: GovernedRunner, run_id: str) -> list[str]:
    """Research agent: readonly query -> denied secret read -> gated restart."""
    tid, notes = "thr_db", []
    brief = await runner.run_llm(agent="db-researcher", run_id=run_id,
                                 thread_id=tid, prompt="One-sentence DB health brief")
    notes.append(f"brief: {getattr(brief, 'result', brief)}")
    out = await runner.run_tool(agent="db-researcher", run_id=run_id, thread_id=tid,
                                tool="query_db_readonly",
                                payload={"sql": "SELECT id, status FROM health_checks LIMIT 10;"})
    notes.append(f"select: {type(out).__name__}")
    out = await runner.run_tool(agent="db-researcher", run_id=run_id, thread_id=tid,
                                tool="read_file_sensitive", payload={"path": "/etc/shadow"})
    notes.append(f"shadow: {type(out).__name__}")
    out = await runner.run_tool(agent="db-researcher", run_id=run_id, thread_id=tid,
                                tool="restart_service",
                                payload={"service_name": "worker", "grace_period_sec": 10})
    notes.append(f"restart: {type(out).__name__}")
    return notes


def terminal_approver(name: str) -> Callable[[GateRequest], Awaitable[GateDecision]]:
    async def decide(gate: GateRequest) -> GateDecision:
        rule = gate.context.get("rule_id", "?")
        print(f"\n  [HITL] {rule} parked gate {gate.gate_id}")
        print(f"  [HITL] action={gate.action.name} payload={json.dumps(gate.action.payload)[:200]}")
        ans = input("  [HITL] approve or deny? [approve/deny] ").strip().lower()
        verdict = GateVerdict.APPROVE if ans in ("approve", "a", "yes", "y") else GateVerdict.DENY
        return GateDecision(gate_id=gate.gate_id, verdict=verdict,
                            reason=f"terminal decision by {name}", decided_by=name)
    return decide


def auto_approver(name: str, verdict: GateVerdict = GateVerdict.APPROVE) -> Callable[[GateRequest], Awaitable[GateDecision]]:
    async def decide(gate: GateRequest) -> GateDecision:
        print(f"  [HITL-auto:{name}] {gate.context.get('rule_id')} -> {verdict.value}")
        return GateDecision(gate_id=gate.gate_id, verdict=verdict,
                            reason=f"auto-{verdict.value} by {name}", decided_by=name)
    return decide


async def main() -> None:
    parser = argparse.ArgumentParser(description="Governed multi-agent demo")
    parser.add_argument("--auto-approve", default=None, help="approver name for non-interactive demo")
    parser.add_argument("--out", default=".tmp/governed_demo", help="output dir for run.json")
    args = parser.parse_args()

    journal = LiveJournal()
    approver = auto_approver(args.auto_approve) if args.auto_approve else terminal_approver("operator")
    runner = GovernedRunner(journal=journal, approve=approver)
    run_id = f"run_demo_{uuid.uuid4().hex[:6]}"

    print("== Warden governed demo: 2 agents, 1 enforced path ==")
    print("-- ops-assistant --")
    for line in await ops_assistant(runner, run_id):
        print(" ", str(line).encode("ascii", "replace").decode())
    print("-- db-researcher --")
    for line in await db_researcher(runner, run_id):
        print(" ", str(line).encode("ascii", "replace").decode())

    status, detail = journal.verify()
    print(f"\njournal: {len(journal.events)} events, chain={status.value} ({detail})")
    for agent, tele in runner.telemetry.items():
        print(f"telemetry[{agent}]: llm={tele.llm_calls} tools={tele.tool_calls} "
              f"gated={tele.gated} denied={tele.denied} "
              f"prompt_tok={tele.prompt_tokens} completion_tok={tele.completion_tokens} "
              f"latency_ms={tele.latency_ms}")

    outdir = ROOT / args.out
    outdir.mkdir(parents=True, exist_ok=True)
    run_doc = {
        "run_id": run_id,
        "chain": {"status": status.value, "detail": detail},
        "telemetry": {a: vars(t) for a, t in runner.telemetry.items()},
        "events": [{"id": e.id, "kind": e.kind, "actor": e.actor, "run_id": e.run_id,
                    "thread_id": e.thread_id, "action_id": e.action_id,
                    "status": e.status, "description": e.description,
                    "payload": e.payload, "ts": e.ts} for e in journal.events],
    }
    (outdir / "run.json").write_text(json.dumps(run_doc, indent=2), encoding="utf-8")
    print(f"run.json -> {outdir / 'run.json'}")


if __name__ == "__main__":
    asyncio.run(main())
