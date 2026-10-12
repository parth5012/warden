"""Tool catalog for the Phase 1 ops-assistant agent.

Eight tools, all crossing the GuardedExecutor seam as Action(kind=tool).
Each tool is a plain dataclass payload + a dispatch adapter; the seam +
PolicyEngine decide, the ops node dispatches behind the adapter that matches
the tool's governance outcome.

Design contract (mirrors ARCHITECTURE.md §3 + docs/API_CONTRACT.md):
- Safe reads fast-path ALLOW in-process (no sandbox, no gate).
- HITL tools escalate -> Pending -> ops node parks via interrupt().
- Terminal-deny tools never reach dispatch (policy denies before dispatch).
- The shell tool runs inside Docker isolation (--network=none, resource caps).

Dependency rule honored: this module imports from warden.models + warden.seam
only; it imports nothing from app/ or agents/. The dispatch adapters are
injected into GuardedExecutor so the seam stays the only call site.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from typing import Any

from warden.models import ActionKind

# ---------------------------------------------------------------------------
# Tool name constant table (single source of truth for policy routing).
# These are the names that the L1/L2 PolicyEngine and the seam match against.
# ---------------------------------------------------------------------------

SAFE_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "get_system_metrics",
        "read_service_logs",
        "query_db_readonly",
    }
)

HITL_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "send_email",
        "restart_service",
    }
)

DENY_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "exec_db_mutation",
        "read_file_sensitive",
    }
)

SANDBOX_TOOL_NAMES: frozenset[str] = frozenset({"exec_shell"})

# ---------------------------------------------------------------------------
# Tool payload dataclasses — document the expected shape of each tool's
# Action.payload. The ops node builds these; the dispatch adapters read them.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GetSystemMetricsPayload:
    service: str  # e.g. "orders"
    metric: str  # "cpu" | "memory" | "latency"
    window_minutes: int = 15


@dataclass(frozen=True)
class ReadServiceLogsPayload:
    service: str  # e.g. "api-gateway"
    lines: int = 50
    filter: str = ""


@dataclass(frozen=True)
class QueryDbReadonlyPayload:
    sql: str  # read-only SELECT


@dataclass(frozen=True)
class SendEmailPayload:
    recipient: str
    subject: str
    body: str


@dataclass(frozen=True)
class RestartServicePayload:
    service_name: str
    grace_period_sec: int = 10


@dataclass(frozen=True)
class ExecDbMutationPayload:
    sql: str  # destructive DDL/DML — blocked by policy


@dataclass(frozen=True)
class ReadFileSensitivePayload:
    path: str  # path-traversal / secret path — blocked by policy


@dataclass(frozen=True)
class ExecShellPayload:
    command: str  # arbitrary shell — runs in Docker sandbox


# ---------------------------------------------------------------------------
# Tool descriptor — stable metadata the seam / ops node can route on
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ToolDescriptor:
    name: str
    category: str  # "safe" | "hitl" | "deny" | "sandbox"
    summary: str


TOOL_CATALOG: list[ToolDescriptor] = [
    ToolDescriptor(
        name="get_system_metrics",
        category="safe",
        summary="Read-only telemetry inspection (cpu|memory|latency) for a service.",
    ),
    ToolDescriptor(
        name="read_service_logs",
        category="safe",
        summary="Bounded log query against an allowlisted log directory.",
    ),
    ToolDescriptor(
        name="query_db_readonly",
        category="safe",
        summary="Read-only SQL SELECT projection (L0 AST-verified).",
    ),
    ToolDescriptor(
        name="send_email",
        category="hitl",
        summary="Outbound email — external egress policy escalates to a human gate.",
    ),
    ToolDescriptor(
        name="restart_service",
        category="hitl",
        summary="Critical infra restart — gated until a Warden-Key approver signs off.",
    ),
    ToolDescriptor(
        name="exec_db_mutation",
        category="deny",
        summary="Destructive SQL (DROP/TRUNCATE/ALTER) — terminal deny, no override.",
    ),
    ToolDescriptor(
        name="read_file_sensitive",
        category="deny",
        summary="Path-traversal / secret-file read — terminal deny, no override.",
    ),
    ToolDescriptor(
        name="exec_shell",
        category="sandbox",
        summary="Arbitrary shell command — contained in a zero-network Docker container.",
    ),
]


def descriptor_for(name: str) -> ToolDescriptor | None:
    """Return the catalog entry for *name*, or None if the name is unknown."""
    for entry in TOOL_CATALOG:
        if entry.name == name:
            return entry
    return None


# ---------------------------------------------------------------------------
# Dispatch adapters — one per tool. Injected into GuardedExecutor by the
# caller (app/main.py or tests). Each adapter receives the Action and returns
# a JSON-safe result dict.
# ---------------------------------------------------------------------------


async def dispatch_get_system_metrics(action: Any) -> dict[str, Any]:
    """Simulate a metrics read. In a real backend this hits a metrics store."""
    payload = action.payload
    service = str(payload.get("service", "unknown"))
    metric = str(payload.get("metric", "cpu"))
    window = int(payload.get("window_minutes", 15))
    return {
        "ok": True,
        "name": action.name,
        "service": service,
        "metric": metric,
        "window_minutes": window,
        "simulated": True,
        "sample": {
            "value": 0.42,
            "unit": "percent",
            "window_start": "2026-10-12T00:00:00Z",
        },
    }


async def dispatch_read_service_logs(action: Any) -> dict[str, Any]:
    """Simulate a bounded log read from an allowlisted directory."""
    payload = action.payload
    service = str(payload.get("service", "unknown"))
    lines = int(payload.get("lines", 50))
    log_filter = str(payload.get("filter", ""))
    return {
        "ok": True,
        "name": action.name,
        "service": service,
        "lines": lines,
        "filter": log_filter,
        "simulated": True,
        "entries": [
            {"line": i, "level": "INFO", "msg": f"sample log entry {i}"}
            for i in range(min(lines, 5))
        ],
    }


async def dispatch_query_db_readonly(action: Any) -> dict[str, Any]:
    """Simulate a read-only SQL SELECT. Real backend hits the DB pool."""
    payload = action.payload
    sql = str(payload.get("sql", ""))
    return {
        "ok": True,
        "name": action.name,
        "sql": sql,
        "simulated": True,
        "rows": [
            {"id": 1, "status": "healthy", "latency_ms": 12},
            {"id": 2, "status": "healthy", "latency_ms": 15},
        ],
    }


async def dispatch_send_email(action: Any) -> dict[str, Any]:
    """Actually send the email — called only after the human approves the gate."""
    payload = action.payload
    return {
        "ok": True,
        "name": action.name,
        "to": str(payload.get("recipient", "")),
        "subject": str(payload.get("subject", "")),
        "simulated": True,
        "message_id": f"msg-{action.id[:8]}",
    }


async def dispatch_restart_service(action: Any) -> dict[str, Any]:
    """Restart the service — called only after the human approves the gate."""
    payload = action.payload
    return {
        "ok": True,
        "name": action.name,
        "service": str(payload.get("service_name", "")),
        "grace_period_sec": int(payload.get("grace_period_sec", 10)),
        "simulated": True,
        "restarted_at": "2026-10-12T00:00:00Z",
    }


async def dispatch_exec_db_mutation(action: Any) -> dict[str, Any]:
    """Should never be called by the seam for a deny-listed action (lock 5)."""
    return {
        "ok": False,
        "error_code": "dispatch_should_not_reach_deny_tool",
        "error_detail": f"{action.name} must be denied by policy before dispatch",
    }


async def dispatch_read_file_sensitive(action: Any) -> dict[str, Any]:
    """Should never be called by the seam for a deny-listed action (lock 5)."""
    return {
        "ok": False,
        "error_code": "dispatch_should_not_reach_deny_tool",
        "error_detail": f"{action.name} must be denied by policy before dispatch",
    }


# ---------------------------------------------------------------------------
# Sandbox tool (Docker isolation, Lock 7)
# ---------------------------------------------------------------------------


async def dispatch_exec_shell(action: Any) -> dict[str, Any]:
    """Run *action* inside the Docker sandbox port (Lock 7)."""
    sandbox = getattr(dispatch_exec_shell, "_sandbox", None)
    if sandbox is None:
        return {
            "ok": False,
            "error_code": "sandbox_unconfigured",
            "error_detail": "exec_shell dispatch has no DockerSandboxPort attached",
        }
    res: dict[str, Any] = await sandbox.run(action)
    return res


def attach_sandbox_port(sandbox: "DockerSandboxPort") -> None:
    """Wire a DockerSandboxPort into the exec_shell dispatch adapter.

    Call this once at app startup (or in a test fixture) before any
    exec_shell action reaches the seam. The sandbox port is shared across
    all exec_shell dispatches — one adapter, many containers.
    """
    dispatch_exec_shell._sandbox = sandbox  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Docker sandbox port — Lock 7 containment adapter
# ---------------------------------------------------------------------------


@dataclass
class SandboxConfig:
    """Tuning knobs for the Docker sandbox port. Injected by the caller."""

    image: str = "alpine:3.19"
    timeout_seconds: int = 30
    memory_mb: int = 256
    cpu_quota: int = 1024  # 1 CPU
    network_mode: str = "none"
    scratch_dir: str = ""  # host tmpfs bind; empty => no bind
    read_only_root: bool = True


class DockerSandboxPort:
    """SandboxPort adapter for exec_shell (Lock 7).

    Runs a command inside a Docker container with:
    - --network=none (network calls fail immediately)
    - read-only root filesystem + optional tmpfs scratch bind
    - CPU/RAM/timeout caps
    - stdout+stderr captured and returned

    Missing Docker daemon / absence of the docker SDK -> the adapter returns
    a structured error result (fail-closed for the tool, not a crash). The
    seam's Error path is NOT used here: sandbox containment is a dispatch
    concern; a sandbox failure is an action_failed journal event, not a
    governance-unavailable condition.
    """

    def __init__(self, config: SandboxConfig | None = None) -> None:
        self._config = config or SandboxConfig()

    async def run(self, action: Any) -> dict[str, Any]:
        """Execute *action* (must be exec_shell) inside the container."""
        if action.name != "exec_shell":
            return {
                "ok": False,
                "error_code": "bad_tool_for_sandbox",
                "error_detail": f"sandbox port received {action.name}",
            }
        payload = action.payload
        command = str(payload.get("command", ""))
        if not command.strip():
            return {
                "ok": False,
                "error_code": "empty_command",
                "error_detail": "exec_shell command must not be empty",
            }
        return await self._run_in_container(action, command)

    async def _run_in_container(self, action: Any, command: str) -> dict[str, Any]:
        cfg = self._config
        try:
            import docker as _docker_mod
        except ImportError:
            return {
                "ok": False,
                "error_code": "sandbox_unavailable",
                "error_detail": "docker SDK not available",
            }

        try:
            client = _docker_mod.from_env()
        except _docker_mod.errors.DockerException as exc:
            return {
                "ok": False,
                "error_code": "sandbox_unavailable",
                "error_detail": f"docker daemon unreachable: {exc}",
            }

        host_cfg = _docker_mod.types.ContainerHostConfig(
            network_mode=cfg.network_mode,
            read_only=cfg.read_only_root,
        )
        if cfg.scratch_dir:
            host_cfg = _docker_mod.types.ContainerHostConfig(
                network_mode=cfg.network_mode,
                read_only=True,
                binds={cfg.scratch_dir: {"bind": "/scratch", "mode": "rw"}},
            )

        try:
            container = client.containers.run(
                cfg.image,
                command=["/bin/sh", "-c", command],
                detach=True,
                hostname="warden-sandbox",
                mem_limit=f"{cfg.memory_mb}m",
                cpu_quota=cfg.cpu_quota,
                network_mode=cfg.network_mode,
                read_only=cfg.read_only_root,
                tmpfs={"/tmp": "size=64m"} if not cfg.scratch_dir else None,
                host_config=host_cfg,
                labels={"warden": "sandbox", "warden-action": action.id},
            )
        except _docker_mod.errors.DockerException as exc:
            return {
                "ok": False,
                "error_code": "sandbox_run_error",
                "error_detail": f"container launch failed: {exc}",
            }

        try:
            inspection = container.wait(timeout=cfg.timeout_seconds)
        except _docker_mod.errors.NotFound:
            return {
                "ok": False,
                "error_code": "sandbox_timeout",
                "error_detail": f"container vanished (timeout={cfg.timeout_seconds}s)",
            }
        except _docker_mod.errors.DockerException as exc:
            return {
                "ok": False,
                "error_code": "sandbox_timeout",
                "error_detail": f"wait failed: {exc}",
            }

        exit_code = inspection.get("StatusCode", -1)
        stdout = ""
        stderr = ""
        try:
            stdout = container.logs(stdout=True, stderr=False, timestamps=False).decode(
                "utf-8", errors="replace"
            )
            stderr = container.logs(stdout=False, stderr=True, timestamps=False).decode(
                "utf-8", errors="replace"
            )
        except Exception:
            pass
        finally:
            try:
                container.remove(force=True)
            except Exception:
                pass

        timed_out = exit_code == -1
        ok = timed_out is False and exit_code == 0
        return {
            "ok": ok,
            "name": action.name,
            "command": command,
            "exit_code": exit_code,
            "timed_out": timed_out,
            "timeout_seconds": cfg.timeout_seconds,
            "network_mode": cfg.network_mode,
            "memory_mb": cfg.memory_mb,
            "simulated": shutil.which("docker") is None,
            "stdout": stdout.strip(),
            "stderr": stderr.strip(),
            "sandbox": {
                "image": cfg.image,
                "network_mode": cfg.network_mode,
                "read_only_root": cfg.read_only_root,
                "scratch_dir": cfg.scratch_dir or None,
            },
        }


# ---------------------------------------------------------------------------
# Helpers — payload validation used by the ops node before dispatch (defense
# in depth: the seam/PolicyEngine decide, but the dispatch adapter also
# sanity-checks its inputs).
# ---------------------------------------------------------------------------

_PATH_TRAVERSAL_TOKENS = ("../", "/etc/", "/proc/", "shadow", ".env", ".aws", ".secret")


def _looks_sensitive_path(path: str) -> bool:
    """Heuristic: path-traversal or known secret-token paths."""
    lower = path.lower()
    if ".." in path and "/" in path:
        return True
    for token in _PATH_TRAVERSAL_TOKENS:
        if token in lower:
            return True
    return False


def _extract_metric(task: str) -> str:
    """Pick a metric name from the task."""
    t = task.lower()
    if "memory" in t or "mem" in t:
        return "memory"
    if "latency" in t or "lag" in t or "slow" in t:
        return "latency"
    return "cpu"


def _extract_service_name(task: str) -> str | None:
    """Pull a service name out of the task text."""
    t = task.lower()
    for name in ("orders", "postgres", "api-gateway", "api_gateway", "auth", "payments", "primary"):
        if name in t:
            return name
    return None


def _extract_path(task: str) -> str | None:
    """Pull a file path out of the task text."""
    t = task
    for token in ("../../../.env", "/etc/shadow", "/etc/passwd", ".env", "shadow"):
        idx = t.lower().find(token.lower())
        if idx != -1:
            end = idx + len(token)
            while end < len(t) and t[end] not in " \t\n\r":
                end += 1
            return t[idx:end].strip()
    return None


def _extract_shell_command(task: str) -> str | None:
    """Pull a shell command from the task text after 'run ', 'shell ', etc."""
    t = task.strip()
    lowered = t.lower()
    for prefix in ("run ", "shell ", "bash ", "exec ", "cmd ", "command "):
        if lowered.startswith(prefix):
            return t[len(prefix):].strip()
        idx = lowered.find(prefix)
        if idx != -1:
            return t[idx + len(prefix):].strip().split("\n")[0].strip()
    for candidate in t.split("\n"):
        candidate = candidate.strip()
        if candidate and not candidate.endswith("?") and not candidate.endswith("."):
            if any(candidate.startswith(k) for k in ("rm ", "curl ", "wget ", "ls ", "cat ", "echo ", "ps ", "top ")):
                return candidate
    return None


def _subject_from_task(task: str) -> str:
    """First ~80 chars of the task as an email subject."""
    s = task.strip().split(".")[0].split("?")[0].strip()
    return s[:80] if s else "ops report"


def _extract_filter(task: str) -> str:
    """Pull a log filter keyword from the task."""
    t = task.lower()
    for token in ("error", "warn", "warning", "info", "debug"):
        if token in t:
            return token.upper()
    return ""
