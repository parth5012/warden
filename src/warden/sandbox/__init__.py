"""Sandbox execution interfaces and adapters for Warden.

Provides the SandboxPort boundary and execution result types.
"""

from __future__ import annotations

from warden.sandbox.port import (
    SandboxPort,
    SandboxResult,
    SandboxUnavailable,
)

__all__ = [
    "SandboxPort",
    "SandboxResult",
    "SandboxUnavailable",
]
