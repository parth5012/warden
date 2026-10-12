"""Service logs reading tool for Aegis governance.

Enforces:
- Service allowlisting
- Canonical path resolution against approved log root
- Traversal and escape rejection
- Unauthorized symlink rejection
- Line count and byte size limits
- Recursive credential and secret redaction
- Synthetic fixture fallback
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from warden.journal import redact_secrets_in_obj
from warden.models import Action

logger = logging.getLogger("warden.tools.logs")

ALLOWED_LOG_SERVICES: frozenset[str] = frozenset({
    "api-gateway",
    "auth-service",
    "payment-service",
    "order-service",
    "database",
})

DEFAULT_MAX_LINES = 100
MAX_ALLOWED_LINES = 1000
MAX_OUTPUT_BYTES = 65536  # 64 KB


@dataclass(frozen=True)
class ServiceLogsResult:
    """Structured log reading result."""

    service: str
    file_name: str
    line_count: int
    byte_count: int
    lines: list[str]
    is_truncated: bool


# Synthetic fixture logs for when physical files do not exist
_FIXTURE_LOGS: dict[str, list[str]] = {
    "api-gateway": [
        "2026-10-12T06:00:01Z [INFO] Gateway worker 1 initialized on port 8080",
        "2026-10-12T06:00:05Z [INFO] Route /api/v1/orders registered -> order-service:5000",
        "2026-10-12T06:01:12Z [INFO] Inbound request GET /health from 10.0.0.1 - 200 OK (2ms)",
        "2026-10-12T06:02:44Z [INFO] Inbound request POST /api/v1/auth - 200 OK (35ms)",
        "2026-10-12T06:03:19Z [WARN] Upstream latency spike detected on payment-service: 420ms",
        "2026-10-12T06:05:00Z [INFO] Health check passed for 5 downstream microservices",
    ],
    "auth-service": [
        "2026-10-12T06:00:00Z [INFO] JWT authentication provider loaded",
        "2026-10-12T06:01:00Z [INFO] Token issued for user_id=usr_48102 scope=read:orders",
        "2026-10-12T06:02:15Z [INFO] Key rotation scheduled for 2026-10-13T00:00:00Z",
        "2026-10-12T06:03:22Z [WARN] Invalid password attempt for principal admin from 192.168.1.10",
        "2026-10-12T06:04:10Z [INFO] Session invalidated for user_id=usr_10294",
    ],
    "payment-service": [
        "2026-10-12T06:00:02Z [INFO] Payment gateway connected: provider=stripe_sandbox",
        "2026-10-12T06:01:45Z [INFO] Payment intent created: id=pi_99214 amount=4999 currency=usd",
        "2026-10-12T06:02:10Z [INFO] Charge captured: id=ch_88192 status=succeeded",
        "2026-10-12T06:04:00Z [INFO] Webhook dispatched to order-service for intent pi_99214",
    ],
    "order-service": [
        "2026-10-12T06:00:01Z [INFO] Order consumer listening on orders.events topic",
        "2026-10-12T06:01:50Z [INFO] Order placed: order_id=ord_10492 customer_id=cust_8810",
        "2026-10-12T06:02:15Z [INFO] Order status updated: ord_10492 -> PAID",
        "2026-10-12T06:03:00Z [INFO] Fulfillment notification triggered for warehouse_1",
    ],
    "database": [
        "2026-10-12T06:00:00Z [INFO] PostgreSQL 16 server started on socket /tmp/.s.PGSQL.5432",
        "2026-10-12T06:00:05Z [INFO] Connection pool allocated: 50 connections",
        "2026-10-12T06:02:00Z [INFO] Checkpoint starting: time",
        "2026-10-12T06:02:12Z [INFO] Checkpoint complete: wrote 42 buffers (0.3%); 0 WAL file(s) added",
    ],
}


def read_service_logs(
    action: Action,
    log_root_dir: Path | None = None,
) -> ServiceLogsResult:
    """Handler for read_service_logs action.

    Validates:
    - Service is allowlisted
    - File path does not escape canonical log root (no path traversal / symlink escapes)
    - Enforces max_lines and max_bytes limits
    - Redacts credentials / tokens from returned log lines
    """
    payload = action.payload

    # 1. Service validation
    service = payload.get("service")
    if not isinstance(service, str) or service not in ALLOWED_LOG_SERVICES:
        raise ValueError(
            f"Service '{service}' is not allowlisted. Allowed services: {sorted(ALLOWED_LOG_SERVICES)}"
        )

    # 2. File name validation
    file_name = payload.get("file_name", f"{service}.log")
    if not isinstance(file_name, str) or not file_name.strip():
        raise ValueError("file_name must be a non-empty string")

    # Reject path separators in file_name
    if "/" in file_name or "\\" in file_name or ".." in file_name:
        raise PermissionError(f"Path traversal detected in file_name: '{file_name}'")

    # 3. Line bounds validation
    max_lines = payload.get("max_lines", DEFAULT_MAX_LINES)
    if not isinstance(max_lines, int) or isinstance(max_lines, bool) or max_lines <= 0:
        raise ValueError("max_lines must be a positive integer")
    effective_max_lines = min(max_lines, MAX_ALLOWED_LINES)

    raw_lines: list[str] = []

    # 4. Canonical path resolution if root_dir is specified or exists
    if log_root_dir is not None:
        canonical_root = log_root_dir.resolve()
        target_path = (canonical_root / service / file_name).resolve()

        # Reject path traversal outside log root
        try:
            target_path.relative_to(canonical_root)
        except ValueError:
            raise PermissionError(
                f"Access denied: Resolved path '{target_path}' escapes approved log root '{canonical_root}'"
            )

        # Reject unauthorized symlinks pointing outside root
        if os.path.islink(canonical_root / service / file_name):
            real_target = Path(os.path.realpath(canonical_root / service / file_name)).resolve()
            try:
                real_target.relative_to(canonical_root)
            except ValueError:
                raise PermissionError(
                    f"Access denied: Symlink points outside approved log root: '{real_target}'"
                )

        if target_path.is_file():
            with open(target_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    raw_lines.append(line.rstrip("\r\n"))
                    if len(raw_lines) >= effective_max_lines:
                        break

    # If no physical log file read, fallback to synthetic fixture logs
    if not raw_lines:
        synthetic = _FIXTURE_LOGS.get(service, [
            f"2026-10-12T06:00:00Z [INFO] {service} running normally"
        ])
        raw_lines = synthetic[:effective_max_lines]

    # 5. Redact secrets and enforce byte limits
    redacted_lines: list[str] = []
    accumulated_bytes = 0
    is_truncated = False

    for line in raw_lines:
        safe_line = str(redact_secrets_in_obj(line))
        line_bytes = len(safe_line.encode("utf-8"))
        if accumulated_bytes + line_bytes > MAX_OUTPUT_BYTES:
            is_truncated = True
            break
        redacted_lines.append(safe_line)
        accumulated_bytes += line_bytes

    return ServiceLogsResult(
        service=service,
        file_name=file_name,
        line_count=len(redacted_lines),
        byte_count=accumulated_bytes,
        lines=redacted_lines,
        is_truncated=is_truncated,
    )
