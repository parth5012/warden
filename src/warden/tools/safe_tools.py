"""Safe fast-path tools: never trigger safety rules (ALLOW, in-process).

Tools: get_system_metrics, read_service_logs, query_db_readonly.
All execution is synthetic stubs — no real DB/SMTP/FS side effects.
"""

from __future__ import annotations

import re
from typing import Any

from warden.policy.layers_static import find_static_violation
from warden.tools.base import ToolContext, ToolSpec, make_action
from warden.models import Action

_ALLOWED_SERVICES = ("api-gateway", "orders", "postgres_primary", "worker")
_ALLOWED_METRICS = ("cpu", "memory", "latency")
_LOG_ROOTS = ("D:/tmp/logs", "D:\\tmp\\logs", "/tmp/logs", "/var/log")
_INJECTION_RE = re.compile(r"ignore\s+(previous|all)\s+instructions", re.IGNORECASE)
_STACKED_RE = re.compile(r";\s*\S")
_WRITE_KW_RE = re.compile(
    r"\b(drop|truncate|delete|insert|update|alter|create|grant|revoke|into|copy|merge|call|do|execute|lock|pg_terminate_backend|pg_sleep)\b",
    re.IGNORECASE,
)

GET_SYSTEM_METRICS_SPEC = ToolSpec(
    name="get_system_metrics",
    description="Pure telemetry inspection (read-only).",
    payload_schema={"service": "str", "metric": "cpu|memory|latency", "window_minutes": "int"},
    execution_path="in-process",
    triggers_rule=False,
)

READ_SERVICE_LOGS_SPEC = ToolSpec(
    name="read_service_logs",
    description="Bounded log query over an allowlisted directory.",
    payload_schema={"service": "str", "lines": "int<=200", "filter": "str"},
    execution_path="in-process",
    triggers_rule=False,
)

QUERY_DB_READONLY_SPEC = ToolSpec(
    name="query_db_readonly",
    description="Pure SELECT projection (read-only AST intent).",
    payload_schema={"sql": "SELECT... only"},
    execution_path="in-process",
    triggers_rule=False,
)


def validate_system_metrics(payload: dict[str, Any]) -> None:
    if payload.get("service") not in _ALLOWED_SERVICES:
        raise ValueError(f"unknown service: {payload.get('service')!r}")
    if payload.get("metric") not in _ALLOWED_METRICS:
        raise ValueError(f"unknown metric: {payload.get('metric')!r}")
    window = payload.get("window_minutes", 15)
    if not isinstance(window, int) or not 1 <= window <= 1440:
        raise ValueError("window_minutes must be int in 1..1440")


def validate_service_logs(payload: dict[str, Any]) -> None:
    if payload.get("service") not in _ALLOWED_SERVICES:
        raise ValueError(f"unknown service: {payload.get('service')!r}")
    lines = payload.get("lines", 50)
    if not isinstance(lines, int) or not 1 <= lines <= 200:
        raise ValueError("lines must be int in 1..200")
    filt = str(payload.get("filter", ""))
    if find_static_violation(filt) is not None or _INJECTION_RE.search(filt):
        raise ValueError("log filter blocked by policy")


def validate_readonly_sql(payload: dict[str, Any]) -> None:
    sql = payload.get("sql")
    if not isinstance(sql, str) or not sql.strip():
        raise ValueError("sql must be a non-empty string")
    stripped = sql.strip()
    upper = stripped.upper()
    if not (upper.startswith("SELECT") or upper.startswith("WITH")):
        raise ValueError("only SELECT/WITH queries are allowed")
    if find_static_violation(stripped) is not None:
        raise ValueError("Destructive DDL forbidden by policy")
    if _WRITE_KW_RE.search(stripped):
        raise ValueError("Destructive DDL forbidden by policy")
    if _STACKED_RE.search(stripped):
        raise ValueError("stacked statements are not allowed")


async def run_system_metrics(payload: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    validate_system_metrics(payload)
    service = str(payload["service"])
    metric = str(payload["metric"])
    window = int(payload.get("window_minutes", 15))
    seed = abs(hash((service, metric))) % 100
    return {
        "service": service,
        "metric": metric,
        "window_minutes": window,
        "value": round(10.0 + seed / 10.0, 2),
        "fast_path": True,
        "run_id": ctx.run_id,
    }


async def run_service_logs(payload: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    validate_service_logs(payload)
    lines = int(payload.get("lines", 50))
    filt = str(payload.get("filter", ""))
    service = str(payload["service"])
    out = [
        f"[{service}] line {i + 1} [{filt or 'ALL'}]: synthetic log entry"
        for i in range(lines)
    ]
    return {"service": service, "lines": out, "root": _LOG_ROOTS[0], "fast_path": True}


async def run_db_readonly(payload: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    validate_readonly_sql(payload)
    return {
        "rows": [{"id": 1, "status": "ok", "latency_ms": 12}],
        "rowcount": 1,
        "note": "readonly-stub (no real DB connection)",
        "fast_path": True,
    }


def to_action(spec_name: str, payload: dict[str, Any], ctx: ToolContext) -> Action:
    spec = {
        "get_system_metrics": GET_SYSTEM_METRICS_SPEC,
        "read_service_logs": READ_SERVICE_LOGS_SPEC,
        "query_db_readonly": QUERY_DB_READONLY_SPEC,
    }[spec_name]
    return make_action(spec, payload, ctx)


__all__ = [
    "GET_SYSTEM_METRICS_SPEC",
    "QUERY_DB_READONLY_SPEC",
    "READ_SERVICE_LOGS_SPEC",
    "run_db_readonly",
    "run_service_logs",
    "run_system_metrics",
    "to_action",
    "validate_readonly_sql",
    "validate_service_logs",
    "validate_system_metrics",
]
