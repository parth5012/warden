"""System metrics tool for Aegis governance.

Accepts only allowlisted services and supported metrics.
Bounds window_minutes to a configurable safe range.
Uses a mock/fixture adapter; never exposes secrets.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from warden.models import Action

logger = logging.getLogger("warden.tools.metrics")

ALLOWED_SERVICES: frozenset[str] = frozenset({
    "api-gateway",
    "auth-service",
    "payment-service",
    "order-service",
    "database",
    "worker",
})

SUPPORTED_METRICS: frozenset[str] = frozenset({
    "cpu_usage_pct",
    "memory_usage_pct",
    "request_count",
    "error_rate_pct",
    "latency_p95_ms",
    "latency_p99_ms",
    "active_connections",
})

MIN_WINDOW_MINUTES = 1
MAX_WINDOW_MINUTES = 1440  # 24 hours
DEFAULT_WINDOW_MINUTES = 60


@dataclass(frozen=True)
class SystemMetricsResult:
    """Structured metrics observation."""

    service: str
    window_minutes: int
    timestamp_utc: str
    metrics: dict[str, float | int]


# Baseline synthetic metrics for fixture adapter
_SERVICE_BASELINES: dict[str, dict[str, float | int]] = {
    "api-gateway": {
        "cpu_usage_pct": 34.5,
        "memory_usage_pct": 58.2,
        "request_count": 12450,
        "error_rate_pct": 0.08,
        "latency_p95_ms": 42.1,
        "latency_p99_ms": 115.0,
        "active_connections": 320,
    },
    "auth-service": {
        "cpu_usage_pct": 21.0,
        "memory_usage_pct": 44.8,
        "request_count": 8920,
        "error_rate_pct": 0.02,
        "latency_p95_ms": 28.5,
        "latency_p99_ms": 78.4,
        "active_connections": 140,
    },
    "payment-service": {
        "cpu_usage_pct": 18.2,
        "memory_usage_pct": 49.1,
        "request_count": 1150,
        "error_rate_pct": 0.01,
        "latency_p95_ms": 85.0,
        "latency_p99_ms": 210.0,
        "active_connections": 45,
    },
    "order-service": {
        "cpu_usage_pct": 29.8,
        "memory_usage_pct": 61.3,
        "request_count": 5420,
        "error_rate_pct": 0.05,
        "latency_p95_ms": 52.0,
        "latency_p99_ms": 130.5,
        "active_connections": 180,
    },
    "database": {
        "cpu_usage_pct": 48.0,
        "memory_usage_pct": 72.4,
        "request_count": 28900,
        "error_rate_pct": 0.00,
        "latency_p95_ms": 12.3,
        "latency_p99_ms": 35.8,
        "active_connections": 85,
    },
    "worker": {
        "cpu_usage_pct": 65.2,
        "memory_usage_pct": 55.0,
        "request_count": 3400,
        "error_rate_pct": 0.12,
        "latency_p95_ms": 140.0,
        "latency_p99_ms": 310.0,
        "active_connections": 25,
    },
}


def get_system_metrics(action: Action) -> SystemMetricsResult:
    """Handler for get_system_metrics action.

    Validates:
    - service in ALLOWED_SERVICES
    - all requested metrics in SUPPORTED_METRICS
    - window_minutes within [MIN_WINDOW_MINUTES, MAX_WINDOW_MINUTES]
    """
    payload = action.payload

    # 1. Service validation
    service = payload.get("service")
    if not isinstance(service, str) or service not in ALLOWED_SERVICES:
        raise ValueError(
            f"Service '{service}' is not allowlisted. Allowed services: {sorted(ALLOWED_SERVICES)}"
        )

    # 2. Window validation
    raw_window = payload.get("window_minutes", DEFAULT_WINDOW_MINUTES)
    if not isinstance(raw_window, int) or isinstance(raw_window, bool):
        raise ValueError(
            f"window_minutes must be an integer, got {type(raw_window).__name__}"
        )
    if not (MIN_WINDOW_MINUTES <= raw_window <= MAX_WINDOW_MINUTES):
        raise ValueError(
            f"window_minutes must be between {MIN_WINDOW_MINUTES} and {MAX_WINDOW_MINUTES}, got {raw_window}"
        )
    window_minutes = raw_window

    # 3. Metrics validation
    raw_metrics = payload.get("metrics")
    if raw_metrics is None:
        selected_metrics = list(SUPPORTED_METRICS)
    elif isinstance(raw_metrics, (list, tuple)):
        for m in raw_metrics:
            if not isinstance(m, str) or m not in SUPPORTED_METRICS:
                raise ValueError(
                    f"Metric '{m}' is not supported. Supported metrics: {sorted(SUPPORTED_METRICS)}"
                )
        selected_metrics = list(raw_metrics)
    else:
        raise ValueError(
            f"metrics must be a list of metric names, got {type(raw_metrics).__name__}"
        )

    # 4. Generate metrics data from fixture baseline
    baseline = _SERVICE_BASELINES.get(service, {})
    collected: dict[str, float | int] = {}
    for m in selected_metrics:
        if m in baseline:
            collected[m] = baseline[m]

    return SystemMetricsResult(
        service=service,
        window_minutes=window_minutes,
        timestamp_utc=datetime.now(timezone.utc).isoformat(),
        metrics=collected,
    )
