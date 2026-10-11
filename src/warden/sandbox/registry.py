"""Sandbox tool profile registry and seed configurations for Warden.

Defines the ToolProfile data structure and provides profile lookups
for Phase-1 ops-assistant sandbox tools.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class ToolProfile:
    """Immutable execution profile configuration for sandboxed tools.

    Attributes:
        name: Unique identifier of the tool.
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
    image: str = "alpine:3.20"


SEED_PROFILES: dict[str, ToolProfile] = {
    "shell": ToolProfile(
        name="shell",
        mode="shell",
        mount="rw",
        timeout_s=30,
        memory="256m",
        cpus="1",
        image="alpine:3.20",
    ),
    "file_inspect": ToolProfile(
        name="file_inspect",
        mode="exec",
        mount="ro",
        timeout_s=30,
        memory="256m",
        cpus="1",
        image="alpine:3.20",
    ),
    "file_cleanup": ToolProfile(
        name="file_cleanup",
        mode="exec",
        mount="rw",
        timeout_s=30,
        memory="256m",
        cpus="1",
        image="alpine:3.20",
    ),
    "code": ToolProfile(
        name="code",
        mode="exec",
        mount="rw",
        timeout_s=30,
        memory="256m",
        cpus="1",
        image="alpine:3.20",
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
    "SEED_PROFILES",
    "ToolProfile",
    "get_profile",
]
