"""Docker sandbox adapter for tool execution in Warden.

Executes tool actions in ephemeral, read-only Docker containers with resource limits,
network isolation (--network=none), tmpfs mounts, and fail-closed error handling.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
import re
import time
from typing import Any, Callable

from warden.models import Action, ActionKind
from warden.sandbox.port import (
    OUTPUT_CAP_BYTES,
    SandboxPort,
    SandboxResult,
    SandboxUnavailable,
)
from warden.sandbox.registry import ToolProfile, get_profile

TRUNCATION_MARKER = "...[truncated]"

# Heuristic patterns in stderr indicating Docker daemon or image pull infrastructure failure
DOCKER_UNAVAILABLE_PATTERNS = (
    "cannot connect to the docker daemon",
    "is the docker daemon running",
    "docker daemon",
    "unable to find image",
    "pull access denied",
    "repository does not exist",
    "failed to register layer",
    "failed to create task",
    "error response from daemon",
)


def _sanitize_container_name(action_id: str) -> str:
    """Sanitize action ID for use in Docker container name."""
    sanitized = re.sub(r"[^a-zA-Z0-9_.-]", "-", action_id)
    return f"warden-{sanitized or 'default'}"


def _truncate_output(raw_bytes: bytes) -> str:
    """Truncate output bytes exceeding OUTPUT_CAP_BYTES with trailing marker."""
    if len(raw_bytes) > OUTPUT_CAP_BYTES:
        truncated_bytes = raw_bytes[:OUTPUT_CAP_BYTES]
        return truncated_bytes.decode("utf-8", errors="replace") + TRUNCATION_MARKER
    return raw_bytes.decode("utf-8", errors="replace")


def _is_infrastructure_failure(stderr_text: str) -> bool:
    """Check if stderr contains heuristics indicating Docker daemon / pull failure."""
    stderr_lower = stderr_text.lower()
    return any(pattern in stderr_lower for pattern in DOCKER_UNAVAILABLE_PATTERNS)


def _validate_payload(profile: ToolProfile, payload: Any) -> None:
    """Validate action payload structure against profile requirements."""
    if not isinstance(payload, dict):
        raise SandboxUnavailable("Action payload must be a dictionary")

    if profile.mode == "exec":
        argv = payload.get("argv")
        if not isinstance(argv, list) or len(argv) == 0:
            raise SandboxUnavailable(
                "Malformed payload for exec mode: 'argv' must be a non-empty list of strings"
            )
        for item in argv:
            if not isinstance(item, str) or not item.strip():
                raise SandboxUnavailable(
                    "Malformed payload for exec mode: each item in 'argv' must be a non-empty string"
                )
    elif profile.mode == "shell":
        command = payload.get("command")
        if not isinstance(command, str) or not command.strip():
            raise SandboxUnavailable(
                "Malformed payload for shell mode: 'command' must be a non-empty string"
            )
    else:
        raise SandboxUnavailable(f"Unsupported tool profile mode: {profile.mode}")


class DockerSandbox:
    """Docker-based container sandbox implementing SandboxPort.

    Enforces container isolation with memory limits, cpu quotas, read-only root filesystems,
    temporary writable tmpfs mounts for /tmp and /work, network isolation, and workspace bind mounts.
    """

    def __init__(
        self,
        workspace_path: Path,
        registry_getter: Callable[[str], ToolProfile | None] = get_profile,
    ) -> None:
        self._workspace_path = workspace_path
        self._registry_getter = registry_getter

    def _build_argv(
        self,
        profile: ToolProfile,
        action: Action,
        container_name: str,
    ) -> list[str]:
        """Construct the docker run CLI argument vector."""
        cmd = [
            "docker",
            "run",
            "--rm",
            "--network=none",
            "--read-only",
            f"--memory={profile.memory}",
            f"--cpus={profile.cpus}",
            "--tmpfs",
            "/tmp:rw,size=64m",
            "--tmpfs",
            "/work:rw,size=64m",
            "--name",
            container_name,
        ]

        if profile.mount in ("ro", "rw"):
            cmd.extend(["-v", f"{self._workspace_path}:/workspace:{profile.mount}"])

        cmd.append(profile.image)

        if profile.mode == "exec":
            cmd.extend(action.payload["argv"])
        elif profile.mode == "shell":
            cmd.extend(["sh", "-c", action.payload["command"]])

        return cmd

    async def run(self, action: Action) -> SandboxResult:
        """Execute tool action inside an isolated Docker container."""
        if action.kind != ActionKind.TOOL:
            raise SandboxUnavailable(f"Unsupported action kind for sandbox: {action.kind}")

        profile = self._registry_getter(action.name)
        if profile is None:
            raise SandboxUnavailable(f"Unknown tool profile: '{action.name}'")

        _validate_payload(profile, action.payload)

        container_name = _sanitize_container_name(action.id)
        argv = self._build_argv(profile, action, container_name)
        profile_tag = f"docker:{action.name}:{profile.mode}-netnone"

        start_time = time.monotonic()

        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError as err:
            raise SandboxUnavailable(
                f"Docker CLI binary not found on PATH: {err}"
            ) from err
        except Exception as err:
            raise SandboxUnavailable(
                f"Failed to spawn Docker process: {err}"
            ) from err

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(),
                timeout=float(profile.timeout_s),
            )
        except (TimeoutError, asyncio.TimeoutError):
            # Best-effort kill and remove container
            try:
                kill_proc = await asyncio.create_subprocess_exec(
                    "docker", "kill", container_name
                )
                try:
                    await asyncio.wait_for(kill_proc.wait(), timeout=5.0)
                except (TimeoutError, asyncio.TimeoutError):
                    kill_proc.kill()
            except Exception:
                pass

            try:
                rm_proc = await asyncio.create_subprocess_exec(
                    "docker", "rm", "-f", container_name
                )
                try:
                    await asyncio.wait_for(rm_proc.wait(), timeout=5.0)
                except (TimeoutError, asyncio.TimeoutError):
                    rm_proc.kill()
            except Exception:
                pass

            try:
                proc.kill()
            except (ProcessLookupError, Exception):
                pass

            try:
                await asyncio.wait_for(proc.wait(), timeout=2.0)
            except Exception:
                pass

            duration_ms = int((time.monotonic() - start_time) * 1000)
            return SandboxResult(
                ok=False,
                exit_code=None,
                stdout="",
                stderr="",
                timed_out=True,
                duration_ms=duration_ms,
                profile=profile_tag,
            )

        duration_ms = int((time.monotonic() - start_time) * 1000)
        stdout_text = _truncate_output(stdout_bytes)
        stderr_text = _truncate_output(stderr_bytes)

        if proc.returncode != 0 and _is_infrastructure_failure(stderr_text):
            raise SandboxUnavailable(
                f"Docker sandbox unavailable (exit {proc.returncode}): {stderr_text.strip()}"
            )

        return SandboxResult(
            ok=(proc.returncode == 0),
            exit_code=proc.returncode,
            stdout=stdout_text,
            stderr=stderr_text,
            timed_out=False,
            duration_ms=duration_ms,
            profile=profile_tag,
        )


__all__ = ["DockerSandbox"]
