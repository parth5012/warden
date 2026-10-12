"""Sandbox tool: exec_shell -> DockerSandbox registry profile "shell" (lock 7).

Spec name exec_shell maps to registry key "shell" (docker adapter looks up
action.name in the registry). Containment: --network=none, read-only rootfs,
tmpfs /tmp + /work, 30s/256MB/1CPU, single workspace bind mount.
LLM actions skip sandbox (timeout + token accounting only).
"""

from __future__ import annotations

from typing import Any, Protocol

from warden.config import settings
from warden.models import Action
from warden.policy.layers_static import find_static_violation
from warden.sandbox.docker import DockerSandbox
from warden.sandbox.port import SandboxResult, SandboxUnavailable
from warden.tools.base import ToolContext, ToolSpec, make_action

EXEC_SHELL_SPEC = ToolSpec(
    name="exec_shell",
    description="Arbitrary shell — contained in Docker sandbox.",
    payload_schema={"command": "str<=4000"},
    execution_path="sandbox",
    triggers_rule=True,
)

# Registry key expected by DockerSandbox for shell mode.
REGISTRY_PROFILE = "shell"

IN_PROCESS_ROUTING: dict[str, str] = {
    "get_system_metrics": "in-process",
    "read_service_logs": "in-process",
    "query_db_readonly": "in-process",
    "send_email": "in-process-after-approval",
    "restart_service": "in-process-after-approval",
    "exec_shell": "docker-sandbox",
    "exec_db_mutation": "aborted-on-deny",
    "read_file_sensitive": "aborted-on-deny",
}


class SandboxRunner(Protocol):
    async def run(self, action: Action) -> SandboxResult: ...


def validate_shell(payload: dict[str, Any]) -> None:
    command = payload.get("command")
    if not isinstance(command, str) or not command.strip():
        raise ValueError("command must be a non-empty string")
    if len(command) > 4000:
        raise ValueError("command exceeds 4000 chars")
    if find_static_violation(f"exec_shell\n{command}") is not None:
        # Prohibited patterns never reach the sandbox (fail before dispatch).
        raise ValueError("command blocked by static policy")


def to_action(payload: dict[str, Any], ctx: ToolContext) -> Action:
    validate_shell(payload)
    proxy = ToolSpec(
        name=REGISTRY_PROFILE,
        description=EXEC_SHELL_SPEC.description,
        payload_schema=EXEC_SHELL_SPEC.payload_schema,
        execution_path="sandbox",
        triggers_rule=True,
    )
    return make_action(proxy, {"command": payload["command"]}, ctx)


async def run_shell(
    payload: dict[str, Any],
    ctx: ToolContext,
    sandbox: SandboxRunner | None = None,
) -> SandboxResult | dict[str, Any]:
    """Execute in Docker; fail-closed to Error-shaped dict (lock 4), never raise."""
    try:
        action = to_action(payload, ctx)
    except ValueError as exc:
        return {"status": "denied", "reason": str(exc)}
    runner: SandboxRunner
    if sandbox is not None:
        runner = sandbox
    else:
        runner = DockerSandbox(workspace_path=settings.sandbox_workspace)
    try:
        return await runner.run(action)
    except SandboxUnavailable as exc:
        return {"status": "error", "reason": "governance_unavailable", "detail": str(exc)}
    except Exception as exc:  # environmental — fail closed, never raise
        return {"status": "error", "reason": "governance_unavailable", "detail": str(exc)}


__all__ = [
    "EXEC_SHELL_SPEC",
    "IN_PROCESS_ROUTING",
    "REGISTRY_PROFILE",
    "SandboxRunner",
    "run_shell",
    "to_action",
    "validate_shell",
]
