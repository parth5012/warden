"""Sandbox port interface and result types for Aegis.

Defines the SandboxPort protocol, execution result container,
exception types, and output capture constraints for sandboxed execution.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from warden.models import Action

# Maximum output capture size: 64 KiB
OUTPUT_CAP_BYTES: int = 64 * 1024


@dataclass(frozen=True)
class SandboxResult:
    """Immutable result of executing an action within a sandbox environment.

    Attributes:
        ok: Whether execution succeeded without errors.
        exit_code: Process exit code, or None if terminated or timed out.
        stdout: Standard output captured from execution.
        stderr: Standard error captured from execution.
        timed_out: Whether execution was terminated due to timeout.
        duration_ms: Wall-clock execution duration in milliseconds.
        profile: Sandbox isolation profile used for execution.
    """

    ok: bool
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool
    duration_ms: int
    profile: str


class SandboxUnavailable(Exception):
    """Raised when the sandbox environment is unreachable or cannot be initialized."""


@runtime_checkable
class SandboxPort(Protocol):
    """Abstract interface for sandboxed execution of tool actions.

    Defines the boundary between the governance executor and isolation
    environments (such as subprocess or container backends).
    """

    async def run(self, action: Action) -> SandboxResult:
        """Execute an action inside the sandbox.

        Args:
            action: The tool action to execute within the sandbox.

        Returns:
            SandboxResult detailing stdout, stderr, exit code, and timing.

        Raises:
            SandboxUnavailable: If the sandbox environment cannot be reached.
        """
        ...


__all__ = [
    "OUTPUT_CAP_BYTES",
    "SandboxPort",
    "SandboxResult",
    "SandboxUnavailable",
]
