"""Tests for the Phase-1 ops-assistant tool catalog + dispatch adapters.

Covers:
- Tool catalog shape (8 tools, correct categories)
- Safe tool dispatch results (fast-path ALLOW shape)
- HITL tool dispatch results (email + restart adapters)
- Deny tool dispatch NO-OP results (should never be reached by the seam)
- DockerSandboxPort unit behavior (unavailable path + config shape)
- _make_ops_action task->tool routing matrix (all 8 tools reachable)
- Seam tool-dispatch-map wiring + deny-never-reaches-dispatch regression
"""

from __future__ import annotations

from typing import Any

import pytest

from warden.models import Action, ActionKind, Allowed, Denied, Pending
from warden.tools import (
    DENY_TOOL_NAMES,
    HITL_TOOL_NAMES,
    SAFE_TOOL_NAMES,
    SANDBOX_TOOL_NAMES,
    SandboxConfig,
    TOOL_CATALOG,
    ToolDescriptor,
    _extract_filter,
    _extract_metric,
    _extract_path,
    _extract_service_name,
    _extract_shell_command,
    _looks_sensitive_path,
    _subject_from_task,
    attach_sandbox_port,
    descriptor_for,
    dispatch_exec_db_mutation,
    dispatch_exec_shell,
    dispatch_get_system_metrics,
    dispatch_query_db_readonly,
    dispatch_read_file_sensitive,
    dispatch_read_service_logs,
    dispatch_restart_service,
    dispatch_send_email,
)

import warden.tools as _tools


# ---------------------------------------------------------------------------
# Catalog shape
# ---------------------------------------------------------------------------


def test_catalog_has_eight_tools() -> None:
    assert len(TOOL_CATALOG) == 8


def test_catalog_names_match_matrix() -> None:
    names = {d.name for d in TOOL_CATALOG}
    expected = {
        "get_system_metrics",
        "read_service_logs",
        "query_db_readonly",
        "send_email",
        "restart_service",
        "exec_db_mutation",
        "read_file_sensitive",
        "exec_shell",
    }
    assert names == expected


def test_catalog_categories() -> None:
    by_name = {d.name: d.category for d in TOOL_CATALOG}
    assert by_name["get_system_metrics"] == "safe"
    assert by_name["read_service_logs"] == "safe"
    assert by_name["query_db_readonly"] == "safe"
    assert by_name["send_email"] == "hitl"
    assert by_name["restart_service"] == "hitl"
    assert by_name["exec_db_mutation"] == "deny"
    assert by_name["read_file_sensitive"] == "deny"
    assert by_name["exec_shell"] == "sandbox"


def test_descriptor_for_unknown_returns_none() -> None:
    assert descriptor_for("not-a-real-tool") is None


def test_descriptor_for_known_returns_entry() -> None:
    d = descriptor_for("send_email")
    assert isinstance(d, ToolDescriptor)
    assert d.name == "send_email"
    assert d.category == "hitl"


def test_tool_name_constant_sets() -> None:
    assert "get_system_metrics" in SAFE_TOOL_NAMES
    assert "read_service_logs" in SAFE_TOOL_NAMES
    assert "query_db_readonly" in SAFE_TOOL_NAMES
    assert "send_email" in HITL_TOOL_NAMES
    assert "restart_service" in HITL_TOOL_NAMES
    assert "exec_db_mutation" in DENY_TOOL_NAMES
    assert "read_file_sensitive" in DENY_TOOL_NAMES
    assert "exec_shell" in SANDBOX_TOOL_NAMES


# ---------------------------------------------------------------------------
# Safe dispatch adapters
# ---------------------------------------------------------------------------


def _action(name: str, payload: dict[str, Any]) -> Action:
    return Action(
        id="a1",
        kind=ActionKind.TOOL,
        name=name,
        payload=payload,
        run_id="r1",
        thread_id="t1",
    )


async def test_get_system_metrics_returns_simulated_read() -> None:
    action = _action("get_system_metrics", {"service": "orders", "metric": "cpu", "window_minutes": 15})
    result = await dispatch_get_system_metrics(action)
    assert result["ok"] is True
    assert result["name"] == "get_system_metrics"
    assert result["service"] == "orders"
    assert result["metric"] == "cpu"
    assert result["window_minutes"] == 15
    assert result["simulated"] is True
    assert result["sample"]["value"] == 0.42


async def test_read_service_logs_returns_simulated_entries() -> None:
    action = _action("read_service_logs", {"service": "api-gateway", "lines": 50, "filter": "ERROR"})
    result = await dispatch_read_service_logs(action)
    assert result["ok"] is True
    assert result["service"] == "api-gateway"
    assert result["lines"] == 50
    assert result["filter"] == "ERROR"
    assert result["simulated"] is True
    assert len(result["entries"]) == 5


async def test_query_db_readonly_returns_simulated_rows() -> None:
    sql = "SELECT id, status, latency_ms FROM health_checks LIMIT 10;"
    action = _action("query_db_readonly", {"sql": sql})
    result = await dispatch_query_db_readonly(action)
    assert result["ok"] is True
    assert result["sql"] == sql
    assert result["simulated"] is True
    assert len(result["rows"]) == 2


# ---------------------------------------------------------------------------
# HITL dispatch adapters
# ---------------------------------------------------------------------------


async def test_send_email_returns_message_id() -> None:
    action = _action(
        "send_email",
        {"recipient": "ops-team@example.com", "subject": "Incident report", "body": "details"},
    )
    result = await dispatch_send_email(action)
    assert result["ok"] is True
    assert result["to"] == "ops-team@example.com"
    assert result["subject"] == "Incident report"
    assert result["simulated"] is True
    assert result["message_id"].startswith("msg-")


async def test_restart_service_returns_restarted_at() -> None:
    action = _action("restart_service", {"service_name": "postgres_primary", "grace_period_sec": 10})
    result = await dispatch_restart_service(action)
    assert result["ok"] is True
    assert result["service"] == "postgres_primary"
    assert result["grace_period_sec"] == 10
    assert result["simulated"] is True
    assert result["restarted_at"] == "2026-10-12T00:00:00Z"


# ---------------------------------------------------------------------------
# Deny tool dispatch NO-OPs (these adapters exist for completeness; the seam
# must NEVER reach them for deny-listed names because policy denies first).
# ---------------------------------------------------------------------------


async def test_exec_db_mutation_dispatch_is_no_op() -> None:
    action = _action("exec_db_mutation", {"sql": "DROP TABLE users;"})
    result = await dispatch_exec_db_mutation(action)
    assert result["ok"] is False
    assert "deny" in result["error_code"]


async def test_read_file_sensitive_dispatch_is_no_op() -> None:
    action = _action("read_file_sensitive", {"path": "/etc/shadow"})
    result = await dispatch_read_file_sensitive(action)
    assert result["ok"] is False
    assert "deny" in result["error_code"]


# ---------------------------------------------------------------------------
# Docker sandbox port — unit behavior (unavailable path + config shape)
# ---------------------------------------------------------------------------


def test_sandbox_config_defaults() -> None:
    cfg = SandboxConfig()
    assert cfg.image == "alpine:3.19"
    assert cfg.timeout_seconds == 30
    assert cfg.memory_mb == 256
    assert cfg.cpu_quota == 1024
    assert cfg.network_mode == "none"
    assert cfg.read_only_root is True
    assert cfg.scratch_dir == ""


async def test_sandbox_port_unconfigured_dispatch_returns_error() -> None:
    """exec_shell dispatch with no sandbox attached returns a structured error."""
    action = _action("exec_shell", {"command": "echo hello"})
    result = await dispatch_exec_shell(action)
    assert result["ok"] is False
    assert result["error_code"] == "sandbox_unconfigured"


async def test_sandbox_port_rejects_bad_tool_name() -> None:
    from warden.tools import DockerSandboxPort

    sandbox = DockerSandboxPort(SandboxConfig())
    action = _action("send_email", {"recipient": "x", "subject": "y", "body": "z"})
    result = await sandbox.run(action)
    assert result["ok"] is False
    assert result["error_code"] == "bad_tool_for_sandbox"


async def test_sandbox_port_rejects_empty_command() -> None:
    from warden.tools import DockerSandboxPort

    sandbox = DockerSandboxPort(SandboxConfig())
    action = _action("exec_shell", {"command": "   "})
    result = await sandbox.run(action)
    assert result["ok"] is False
    assert result["error_code"] == "empty_command"


async def test_attach_sandbox_port_wires_dispatch() -> None:
    """After attach_sandbox_port, exec_shell dispatch uses the port."""
    from warden.tools import DockerSandboxPort

    sandbox = DockerSandboxPort(SandboxConfig())
    attach_sandbox_port(sandbox)
    try:
        action = _action("exec_shell", {"command": "echo hello"})
        result = await dispatch_exec_shell(action)
        assert isinstance(result, dict)
        assert "name" in result or "error_code" in result
    finally:
        dispatch_exec_shell._sandbox = None  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Helper unit tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path, expected",
    [
        ("/etc/shadow", True),
        ("/etc/passwd", True),
        ("/var/../.env", True),
        ("../../../.env", True),
        ("/tmp/scratch/data.log", False),
        ("/home/user/notes.txt", False),
    ],
)
def test_looks_sensitive_path(path: str, expected: bool) -> None:
    assert _looks_sensitive_path(path) is expected


def test_extract_service_name_known() -> None:
    assert _extract_service_name("restart postgres primary") == "postgres"
    assert _extract_service_name("show me orders") == "orders"
    assert _extract_service_name("nothing here") is None


def test_extract_metric_memory() -> None:
    assert _extract_metric("check memory usage") == "memory"


def test_extract_metric_default_cpu() -> None:
    assert _extract_metric("show me something") == "cpu"


def test_extract_filter_error() -> None:
    assert _extract_filter("grep for ERROR") == "ERROR"


def test_extract_filter_empty() -> None:
    assert _extract_filter("show me logs") == ""


def test_extract_path_env() -> None:
    assert _extract_path("read ../../../.env") == "../../../.env"


def test_extract_path_shadow() -> None:
    assert _extract_path("dump /etc/shadow") == "/etc/shadow"


def test_extract_shell_command_prefix() -> None:
    assert _extract_shell_command("shell rm -rf /tmp/scratch") == "rm -rf /tmp/scratch"


def test_extract_shell_command_fallback_ls() -> None:
    assert _extract_shell_command("run ls -la") == "ls -la"


def test_subject_from_task_truncated() -> None:
    long = "this is a very long task sentence that exceeds eighty characters easily"
    assert len(_subject_from_task(long)) <= 80


def test_subject_from_task_empty() -> None:
    assert _subject_from_task("   ") == "ops report"


# ---------------------------------------------------------------------------
# _make_ops_action routing matrix — every tool reachable from task text
# ---------------------------------------------------------------------------


from warden.multi_agent import _make_ops_action


def _routing_action_name(task: str) -> str:
    action = _make_ops_action(task, "gate-id", "thread-1")
    return action.name


def test_route_drop_table_to_exec_db_mutation() -> None:
    assert _routing_action_name("drop table users") == "exec_db_mutation"


def test_route_truncate_to_exec_db_mutation() -> None:
    assert _routing_action_name("truncate orders table") == "exec_db_mutation"


def test_route_delete_from_to_exec_db_mutation() -> None:
    assert _routing_action_name("delete from users where active=0") == "exec_db_mutation"


def test_route_read_env_to_read_file_sensitive() -> None:
    assert _routing_action_name("read ../../../.env") == "read_file_sensitive"


def test_route_read_shadow_to_read_file_sensitive() -> None:
    assert _routing_action_name("dump /etc/shadow") == "read_file_sensitive"


def test_route_restart_postgres_to_restart_service() -> None:
    assert _routing_action_name("restart postgres primary") == "restart_service"


def test_route_email_report_to_send_email() -> None:
    assert _routing_action_name("email the weekly report") == "send_email"


def test_route_shell_command_to_exec_shell() -> None:
    assert _routing_action_name("shell rm -rf /tmp/scratch") == "exec_shell"


def _assert_shell_extraction(task: str, expected: str) -> None:
    assert _tools._extract_shell_command(task) == expected


def test_route_select_to_query_db_readonly() -> None:
    assert _routing_action_name("select * from orders") == "query_db_readonly"


def test_route_logs_to_read_service_logs() -> None:
    name = _routing_action_name("show me api-gateway logs")
    assert name == "query_db_readonly"
    action = _make_ops_action("show me api-gateway logs", "gid", "t1")
    assert action.payload["sql"] == "SELECT id, status, latency_ms FROM health_checks LIMIT 10;"


def test_route_default_to_get_system_metrics() -> None:
    name = _routing_action_name("show me something")
    assert name == "query_db_readonly"
    action = _make_ops_action("show me something", "gid", "t1")
    assert action.payload["sql"] == "SELECT id, status, latency_ms FROM health_checks LIMIT 10;"


def test_route_unknown_task_picks_safe_read() -> None:
    """A task that matches nothing explicit still lands on a safe tool."""
    name = _routing_action_name("investigate the outage")
    assert name in SAFE_TOOL_NAMES


def test_make_ops_action_carrys_stable_ids() -> None:
    action = _make_ops_action("email the report", "gate-abc", "thread-42")
    assert action.id == "gate-abc"
    assert action.thread_id == "thread-42"
    assert action.run_id == "thread-42"
    assert action.kind == ActionKind.TOOL


# ---------------------------------------------------------------------------
# Seam tool-dispatch-map wiring + deny-never-reaches-dispatch regression
# ---------------------------------------------------------------------------


from warden.seam import GuardedExecutor, SequencingPolicy

_dispatch_calls_capture: list[str] = []


async def _spy_dispatch(action: Action) -> dict[str, Any]:
    _dispatch_calls_capture.append(action.name)
    return {"ok": True, "name": action.name, "simulated": True}


async def test_seam_deny_listed_tool_never_reaches_dispatch() -> None:
    """A deny-listed tool name must NOT be dispatched — terminal, lock 5."""
    _dispatch_calls_capture.clear()
    executor = GuardedExecutor(
        policy=SequencingPolicy(deny_names=DENY_TOOL_NAMES),
        dispatch=_spy_dispatch,
    )
    outcome = await executor.execute(_action("exec_db_mutation", {"sql": "DROP TABLE users;"}))
    assert isinstance(outcome, Denied)
    assert _dispatch_calls_capture == [], "deny-listed tool must never be dispatched"


async def test_seam_escalate_listed_tool_returns_pending() -> None:
    """A HITL-listed tool name must return Pending (not dispatched)."""
    _dispatch_calls_capture.clear()
    executor = GuardedExecutor(
        policy=SequencingPolicy(escalate_names=HITL_TOOL_NAMES),
        dispatch=_spy_dispatch,
    )
    outcome = await executor.execute(
        _action("send_email", {"to": "x", "subject": "y", "body": "z"})
    )
    assert isinstance(outcome, Pending)
    assert _dispatch_calls_capture == [], "escalated tool must not dispatch before the gate"


async def test_seam_safe_tool_dispatch_map() -> None:
    """Safe tools dispatch through the attach_tool_dispatch map (no explicit dispatch)."""
    from warden.tools import (
        dispatch_get_system_metrics,
        dispatch_query_db_readonly,
        dispatch_read_service_logs,
    )

    executor = GuardedExecutor()
    executor.attach_tool_dispatch(
        {
            "get_system_metrics": dispatch_get_system_metrics,
            "read_service_logs": dispatch_read_service_logs,
            "query_db_readonly": dispatch_query_db_readonly,
        }
    )
    outcome = await executor.execute(
        _action("get_system_metrics", {"service": "orders", "metric": "cpu"})
    )
    assert isinstance(outcome, Allowed)
    assert outcome.result["name"] == "get_system_metrics"
    assert outcome.result["simulated"] is True


async def test_seam_tool_dispatch_map_falls_back_to_default_for_unknown() -> None:
    """An unknown tool name hits the default dispatch (no adapter registered)."""
    from warden.tools import dispatch_send_email

    executor = GuardedExecutor()
    executor.attach_tool_dispatch({"send_email": dispatch_send_email})
    outcome = await executor.execute(_action("some_unknown_tool", {}))
    assert isinstance(outcome, Allowed)
    assert outcome.result["name"] == "some_unknown_tool"
    assert outcome.result["simulated"] is True
