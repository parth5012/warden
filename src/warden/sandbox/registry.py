"""Sandbox tool profile registry and seed configurations for Aegis.

Defines the ToolProfile data structure and provides profile lookups
for Phase-1 ops-assistant sandbox tools.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


DEFAULT_IMAGE: str = (
    "alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
)


@dataclass(frozen=True)
class ToolProfile:
    """Immutable execution profile configuration for sandboxed tools.

    Attributes:
        name: Unique identifier for the tool.
        mode: Execution mode ('exec' for direct binary invocation, 'shell' for shell wrapping).
        mount: Filesystem isolation mount mode ('none', 'ro' for read-only, 'rw' for read-write).
        timeout_s: Maximum execution duration in seconds before termination.
        memory: Memory ceiling constraint (e.g. '256m').
        cpus: CPU allocation limit constraint (e.g. '1').
        image: Base container image for containerized execution backends.
    """

    name: str
    mode: Literal["exec", "shell"]
    mount: Literal["none", "ro", "rw"]
    timeout_s: int = 30
    memory: str = "256m"
    cpus: str = "1"
    image: str = DEFAULT_IMAGE


SEED_PROFILES: dict[str, ToolProfile] = {
    "shell": ToolProfile(
        name="shell",
        mode="shell",
        mount="rw",
        timeout_s=30,
        memory="256m",
        cpus="1",
        image=DEFAULT_IMAGE,
    ),
    "file_inspect": ToolProfile(
        name="file_inspect",
        mode="exec",
        mount="ro",
        timeout_s=30,
        memory="256m",
        cpus="1",
        image=DEFAULT_IMAGE,
    ),
    "file_cleanup": ToolProfile(
        name="file_cleanup",
        mode="exec",
        mount="rw",
        timeout_s=30,
        memory="256m",
        cpus="1",
        image=DEFAULT_IMAGE,
    ),
    "code": ToolProfile(
        name="code",
        mode="exec",
        mount="rw",
        timeout_s=30,
        memory="256m",
        cpus="1",
        image=DEFAULT_IMAGE,
    ),
}


def get_profile(tool_name: str) -> ToolProfile | None:
    """Retrieve the ToolProfile configuration for a given tool name.

    Args:
        tool_name: The name of the tool to look up.

    Returns:
        The registered ToolProfile if found, or None if the tool is unknown.
    """
    return SEED_PROFILES.get(tool_name)


__all__ = [
    "DEFAULT_IMAGE",
    "SEED_PROFILES",
    "ToolProfile",
    "get_profile",
]
