"""Sandbox execution interfaces and adapters for Aegis.

Provides the SandboxPort boundary and execution result types.
"""

from __future__ import annotations

from warden.sandbox.docker import DockerSandbox
from warden.sandbox.port import (
    SandboxPort,
    SandboxResult,
    SandboxUnavailable,
)
from warden.sandbox.registry import (
    ToolProfile,
    get_profile,
)

__all__ = [
    "DockerSandbox",
    "SandboxPort",
    "SandboxResult",
    "SandboxUnavailable",
    "ToolProfile",
    "get_profile",
]
