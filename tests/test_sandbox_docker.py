"""Tests for DockerSandbox adapter (docker run builder, timeout kill, fail-closed).

Execution goes through ``warden.sandbox.docker._blocking_run`` (sync
``subprocess.run`` offloaded via ``asyncio.to_thread``), so it never depends
on the running event loop's subprocess support. Tests patch that seam.

Validates:
1. argv construction:
   - standard flags: --rm, --network=none, --read-only, --memory, --cpus, --tmpfs, --name
   - mount handling: -v workspace:/workspace:{ro|rw} for ro/rw, omitted for none
   - container name format: warden-<sanitized action.id>
   - image placement after options (registry pin or image_override)
   - exec mode appends argv list
   - shell mode appends ["sh", "-c", command]
2. Protocol compliance: DockerSandbox satisfies SandboxPort.
3. Unknown profile raises SandboxUnavailable.
4. Malformed payload raises SandboxUnavailable:
   - exec mode: missing argv, empty argv, invalid argv types
   - shell mode: missing command, empty command, whitespace command, invalid command types
5. Timeout handling:
   - when _blocking_run raises subprocess.TimeoutExpired
   - executes best-effort cleanup (_blocking_cleanup with container name)
   - returns SandboxResult(ok=False, exit_code=None, timed_out=True, ...)
6. Truncation:
   - stdout/stderr > OUTPUT_CAP_BYTES (64 KiB) truncated to 64 KiB with "...[truncated]" marker
7. Profile field matches f"docker:{action.name}:{profile.mode}-netnone".
8. Docker daemon down / image pull failure heuristics in stderr raise SandboxUnavailable:
   - "Cannot connect to the Docker daemon"
   - "Unable to find image"
   - "pull access denied"
   - "repository does not exist"
9. FileNotFoundError when spawning docker CLI raises SandboxUnavailable.
10. Normal non-zero exit returns SandboxResult(ok=False, exit_code=1, timed_out=False, ...).
11. Normal exit code 0 returns SandboxResult(ok=True, exit_code=0, timed_out=False, ...).
12. image_override replaces the registry-pinned image in argv.
"""

from __future__ import annotations

import asyncio
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest

from warden.models import Action, ActionKind
from warden.sandbox.docker import DockerSandbox
from warden.sandbox.port import OUTPUT_CAP_BYTES, SandboxPort, SandboxResult, SandboxUnavailable
from warden.sandbox.registry import ToolProfile


def _completed(
    stdout: bytes = b"",
    stderr: bytes = b"",
    returncode: int = 0,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(
        args=["docker", "run"], returncode=returncode, stdout=stdout, stderr=stderr
    )


@pytest.fixture
def workspace_path(tmp_path: Path) -> Path:
    return tmp_path / "test_workspace"


@pytest.fixture
def sample_exec_profile() -> ToolProfile:
    return ToolProfile(
        name="file_inspect",
        mode="exec",
        mount="ro",
        timeout_s=10,
        memory="128m",
        cpus="0.5",
        image="alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc",
    )


@pytest.fixture
def sample_shell_profile() -> ToolProfile:
    return ToolProfile(
        name="shell",
        mode="shell",
        mount="rw",
        timeout_s=15,
        memory="256m",
        cpus="1",
        image="alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc",
    )


@pytest.fixture
def sample_none_mount_profile() -> ToolProfile:
    return ToolProfile(
        name="pure_compute",
        mode="exec",
        mount="none",
        timeout_s=5,
        memory="64m",
        cpus="0.25",
        image="alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc",
    )


def test_docker_sandbox_satisfies_sandbox_port_protocol(workspace_path: Path) -> None:
    """DockerSandbox must implement SandboxPort Protocol."""
    sandbox = DockerSandbox(workspace_path=workspace_path)
    assert isinstance(sandbox, SandboxPort)


@pytest.mark.asyncio
async def test_argv_construction_exec_mode(
    monkeypatch: pytest.MonkeyPatch,
    workspace_path: Path,
    sample_exec_profile: ToolProfile,
) -> None:
    """Validate argv flags, mounts, container name, and image order for exec mode."""
    recorded: list[tuple[list[str], float]] = []

    def fake_run(argv: list[str], timeout_s: float) -> subprocess.CompletedProcess[bytes]:
        recorded.append((argv, timeout_s))
        return _completed(stdout=b"file1.txt\n")

    monkeypatch.setattr("warden.sandbox.docker._blocking_run", fake_run)

    sandbox = DockerSandbox(
        workspace_path=workspace_path,
        registry_getter=lambda name: sample_exec_profile if name == "file_inspect" else None,
    )

    action = Action(
        id="act-1234",
        kind=ActionKind.TOOL,
        name="file_inspect",
        payload={"argv": ["ls", "-l", "/workspace"]},
        run_id="run-1",
        thread_id="th-1",
    )

    result = await sandbox.run(action)

    assert result.ok is True
    assert result.exit_code == 0
    assert result.stdout == "file1.txt\n"
    assert result.stderr == ""
    assert result.timed_out is False
    assert result.profile == "docker:file_inspect:exec-netnone"

    assert len(recorded) == 1
    argv, timeout_s = recorded[0]
    assert timeout_s == float(sample_exec_profile.timeout_s)
    expected_argv = [
        "docker",
        "run",
        "--rm",
        "--network=none",
        "--read-only",
        "--memory=128m",
        "--cpus=0.5",
        "--tmpfs",
        "/tmp:rw,size=64m",
        "--tmpfs",
        "/work:rw,size=64m",
        "--name",
        "warden-act-1234",
        "-v",
        f"{workspace_path}:/workspace:ro",
        sample_exec_profile.image,
        "ls",
        "-l",
        "/workspace",
    ]
    assert argv == expected_argv


@pytest.mark.asyncio
async def test_argv_construction_shell_mode(
    monkeypatch: pytest.MonkeyPatch,
    workspace_path: Path,
    sample_shell_profile: ToolProfile,
) -> None:
    """Validate argv flags, mounts, container name, and shell invocation for shell mode."""
    recorded: list[tuple[list[str], float]] = []

    def fake_run(argv: list[str], timeout_s: float) -> subprocess.CompletedProcess[bytes]:
        recorded.append((argv, timeout_s))
        return _completed(stdout=b"hello shell\n")

    monkeypatch.setattr("warden.sandbox.docker._blocking_run", fake_run)

    sandbox = DockerSandbox(
        workspace_path=workspace_path,
        registry_getter=lambda name: sample_shell_profile if name == "shell" else None,
    )

    action = Action(
        id="act-5678",
        kind=ActionKind.TOOL,
        name="shell",
        payload={"command": "echo 'hello shell'"},
        run_id="run-2",
        thread_id="th-2",
    )

    result = await sandbox.run(action)

    assert result.ok is True
    assert result.exit_code == 0
    assert result.stdout == "hello shell\n"
    assert result.profile == "docker:shell:shell-netnone"

    assert len(recorded) == 1
    argv, _ = recorded[0]
    expected_argv = [
        "docker",
        "run",
        "--rm",
        "--network=none",
        "--read-only",
        "--memory=256m",
        "--cpus=1",
        "--tmpfs",
        "/tmp:rw,size=64m",
        "--tmpfs",
        "/work:rw,size=64m",
        "--name",
        "warden-act-5678",
        "-v",
        f"{workspace_path}:/workspace:rw",
        sample_shell_profile.image,
        "sh",
        "-c",
        "echo 'hello shell'",
    ]
    assert argv == expected_argv


@pytest.mark.asyncio
async def test_argv_construction_mount_none(
    monkeypatch: pytest.MonkeyPatch,
    workspace_path: Path,
    sample_none_mount_profile: ToolProfile,
) -> None:
    """When profile mount is 'none', no -v flag must be added."""
    recorded: list[tuple[list[str], float]] = []

    def fake_run(argv: list[str], timeout_s: float) -> subprocess.CompletedProcess[bytes]:
        recorded.append((argv, timeout_s))
        return _completed(stdout=b"computed\n")

    monkeypatch.setattr("warden.sandbox.docker._blocking_run", fake_run)

    sandbox = DockerSandbox(
        workspace_path=workspace_path,
        registry_getter=lambda name: sample_none_mount_profile,
    )

    action = Action(
        id="act-9999",
        kind=ActionKind.TOOL,
        name="pure_compute",
        payload={"argv": ["echo", "42"]},
        run_id="run-3",
        thread_id="th-3",
    )

    await sandbox.run(action)

    argv, _ = recorded[0]
    assert "-v" not in argv
    # Ensure image comes right after --name argument
    name_idx = list(argv).index("--name")
    assert argv[name_idx + 1] == "warden-act-9999"
    assert argv[name_idx + 2] == sample_none_mount_profile.image


@pytest.mark.asyncio
async def test_container_name_sanitization(
    monkeypatch: pytest.MonkeyPatch,
    workspace_path: Path,
    sample_exec_profile: ToolProfile,
) -> None:
    """Action id containing unsafe chars is sanitized to alphanumeric, dots, underscores, dashes."""
    recorded: list[tuple[list[str], float]] = []

    def fake_run(argv: list[str], timeout_s: float) -> subprocess.CompletedProcess[bytes]:
        recorded.append((argv, timeout_s))
        return _completed()

    monkeypatch.setattr("warden.sandbox.docker._blocking_run", fake_run)

    sandbox = DockerSandbox(
        workspace_path=workspace_path,
        registry_getter=lambda name: sample_exec_profile,
    )

    action = Action(
        id="act:sub/unsafe@name#123",
        kind=ActionKind.TOOL,
        name="file_inspect",
        payload={"argv": ["ls"]},
        run_id="run-4",
        thread_id="th-4",
    )

    await sandbox.run(action)

    argv, _ = recorded[0]
    name_idx = list(argv).index("--name")
    container_name = argv[name_idx + 1]
    assert container_name == "warden-act-sub-unsafe-name-123"


@pytest.mark.asyncio
async def test_image_override_replaces_registry_image(
    monkeypatch: pytest.MonkeyPatch,
    workspace_path: Path,
    sample_exec_profile: ToolProfile,
) -> None:
    """image_override (e.g. Settings.sandbox_image) replaces the pinned image."""
    recorded: list[tuple[list[str], float]] = []

    def fake_run(argv: list[str], timeout_s: float) -> subprocess.CompletedProcess[bytes]:
        recorded.append((argv, timeout_s))
        return _completed()

    monkeypatch.setattr("warden.sandbox.docker._blocking_run", fake_run)

    sandbox = DockerSandbox(
        workspace_path=workspace_path,
        registry_getter=lambda name: sample_exec_profile,
        image_override="custom-registry/alpine:3.20",
    )

    action = Action(
        id="act-override",
        kind=ActionKind.TOOL,
        name="file_inspect",
        payload={"argv": ["ls"]},
        run_id="run-1",
        thread_id="th-1",
    )

    await sandbox.run(action)

    argv, _ = recorded[0]
    assert "custom-registry/alpine:3.20" in argv
    assert sample_exec_profile.image not in argv


@pytest.mark.asyncio
async def test_unknown_profile_raises_sandbox_unavailable(
    workspace_path: Path,
) -> None:
    """Unknown profile in registry must raise SandboxUnavailable."""
    sandbox = DockerSandbox(
        workspace_path=workspace_path,
        registry_getter=lambda name: None,
    )

    action = Action(
        id="act-1",
        kind=ActionKind.TOOL,
        name="nonexistent_tool",
        payload={"argv": ["echo", "test"]},
        run_id="run-1",
        thread_id="th-1",
    )

    with pytest.raises(SandboxUnavailable, match="nonexistent_tool"):
        await sandbox.run(action)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"argv": []},
        {"argv": "not-a-list"},
        {"argv": [1, 2, 3]},
        {"argv": [""]},
    ],
)
async def test_malformed_payload_exec_mode_raises(
    workspace_path: Path,
    sample_exec_profile: ToolProfile,
    payload: dict[str, Any],
) -> None:
    """Malformed payload for exec mode must raise SandboxUnavailable."""
    sandbox = DockerSandbox(
        workspace_path=workspace_path,
        registry_getter=lambda name: sample_exec_profile,
    )

    action = Action(
        id="act-bad-payload",
        kind=ActionKind.TOOL,
        name="file_inspect",
        payload=payload,
        run_id="run-1",
        thread_id="th-1",
    )

    with pytest.raises(SandboxUnavailable):
        await sandbox.run(action)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"command": ""},
        {"command": "   "},
        {"command": 123},
        {"command": ["not", "string"]},
    ],
)
async def test_malformed_payload_shell_mode_raises(
    workspace_path: Path,
    sample_shell_profile: ToolProfile,
    payload: dict[str, Any],
) -> None:
    """Malformed payload for shell mode must raise SandboxUnavailable."""
    sandbox = DockerSandbox(
        workspace_path=workspace_path,
        registry_getter=lambda name: sample_shell_profile,
    )

    action = Action(
        id="act-bad-shell",
        kind=ActionKind.TOOL,
        name="shell",
        payload=payload,
        run_id="run-1",
        thread_id="th-1",
    )

    with pytest.raises(SandboxUnavailable):
        await sandbox.run(action)


@pytest.mark.asyncio
async def test_timeout_handling_kills_and_removes_container(
    monkeypatch: pytest.MonkeyPatch,
    workspace_path: Path,
    sample_exec_profile: ToolProfile,
) -> None:
    """TimeoutExpired from _blocking_run triggers best-effort container cleanup."""
    recorded_runs: list[tuple[list[str], float]] = []
    cleaned: list[str] = []

    def fake_run(argv: list[str], timeout_s: float) -> subprocess.CompletedProcess[bytes]:
        recorded_runs.append((argv, timeout_s))
        raise subprocess.TimeoutExpired(cmd=argv, timeout=timeout_s)

    def fake_reconcile(container_name: str) -> None:
        cleaned.append(container_name)

    monkeypatch.setattr("warden.sandbox.docker._blocking_run", fake_run)
    monkeypatch.setattr("warden.sandbox.docker._blocking_reconcile", fake_reconcile)

    sandbox = DockerSandbox(
        workspace_path=workspace_path,
        registry_getter=lambda name: sample_exec_profile,
    )

    action = Action(
        id="act-timeout",
        kind=ActionKind.TOOL,
        name="file_inspect",
        payload={"argv": ["sleep", "60"]},
        run_id="run-t",
        thread_id="th-t",
    )

    result = await sandbox.run(action)

    assert result.ok is False
    assert result.exit_code is None
    assert result.timed_out is True
    assert result.duration_ms >= 0
    assert result.profile == "docker:file_inspect:exec-netnone"

    # Profile timeout must have been passed to the blocking call
    assert recorded_runs[0][1] == float(sample_exec_profile.timeout_s)
    # Container cleanup ran for this container
    assert cleaned == ["warden-act-timeout"]


@pytest.mark.asyncio
async def test_output_truncation_to_output_cap_bytes(
    monkeypatch: pytest.MonkeyPatch,
    workspace_path: Path,
    sample_exec_profile: ToolProfile,
) -> None:
    """Stdout and stderr exceeding OUTPUT_CAP_BYTES (64 KiB) are truncated with trailing marker."""
    oversized_stdout = b"A" * (OUTPUT_CAP_BYTES + 4096)
    oversized_stderr = b"E" * (OUTPUT_CAP_BYTES + 8192)

    def fake_run(argv: list[str], timeout_s: float) -> subprocess.CompletedProcess[bytes]:
        return _completed(stdout=oversized_stdout, stderr=oversized_stderr)

    monkeypatch.setattr("warden.sandbox.docker._blocking_run", fake_run)

    sandbox = DockerSandbox(
        workspace_path=workspace_path,
        registry_getter=lambda name: sample_exec_profile,
    )

    action = Action(
        id="act-trunc",
        kind=ActionKind.TOOL,
        name="file_inspect",
        payload={"argv": ["cat", "big_file"]},
        run_id="run-trunc",
        thread_id="th-trunc",
    )

    result = await sandbox.run(action)

    assert result.ok is True
    marker = "...[truncated]"
    assert result.stdout.endswith(marker)
    assert result.stderr.endswith(marker)

    # Content before marker must be exactly OUTPUT_CAP_BYTES characters
    content_stdout = result.stdout[: -len(marker)]
    content_stderr = result.stderr[: -len(marker)]
    assert len(content_stdout.encode("utf-8")) == OUTPUT_CAP_BYTES
    assert len(content_stderr.encode("utf-8")) == OUTPUT_CAP_BYTES


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error_stderr",
    [
        "docker: Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?",
        "docker: Error response from daemon: Is the docker daemon running?",
        "Unable to find image 'alpine:latest' locally\ndocker: Error response from daemon: pull access denied",
        "Error response from daemon: repository does not exist or may require 'docker login'",
    ],
)
async def test_docker_daemon_down_or_pull_failure_raises_sandbox_unavailable(
    monkeypatch: pytest.MonkeyPatch,
    workspace_path: Path,
    sample_exec_profile: ToolProfile,
    error_stderr: str,
) -> None:
    """Docker daemon unreachable or pull failure heuristics in stderr raise SandboxUnavailable."""
    def fake_run(argv: list[str], timeout_s: float) -> subprocess.CompletedProcess[bytes]:
        return _completed(stderr=error_stderr.encode("utf-8"), returncode=125)

    monkeypatch.setattr("warden.sandbox.docker._blocking_run", fake_run)

    sandbox = DockerSandbox(
        workspace_path=workspace_path,
        registry_getter=lambda name: sample_exec_profile,
    )

    action = Action(
        id="act-daemon-err",
        kind=ActionKind.TOOL,
        name="file_inspect",
        payload={"argv": ["ls"]},
        run_id="run-d",
        thread_id="th-d",
    )

    with pytest.raises(SandboxUnavailable):
        await sandbox.run(action)


@pytest.mark.asyncio
async def test_file_not_found_error_raises_sandbox_unavailable(
    monkeypatch: pytest.MonkeyPatch,
    workspace_path: Path,
    sample_exec_profile: ToolProfile,
) -> None:
    """When docker CLI executable is missing from PATH, raise SandboxUnavailable."""
    def fake_run(argv: list[str], timeout_s: float) -> subprocess.CompletedProcess[bytes]:
        raise FileNotFoundError(2, "No such file or directory", "docker")

    monkeypatch.setattr("warden.sandbox.docker._blocking_run", fake_run)

    sandbox = DockerSandbox(
        workspace_path=workspace_path,
        registry_getter=lambda name: sample_exec_profile,
    )

    action = Action(
        id="act-nodocker",
        kind=ActionKind.TOOL,
        name="file_inspect",
        payload={"argv": ["ls"]},
        run_id="run-f",
        thread_id="th-f",
    )

    with pytest.raises(SandboxUnavailable, match="not found"):
        await sandbox.run(action)


@pytest.mark.asyncio
async def test_normal_non_zero_exit_returns_sandbox_result(
    monkeypatch: pytest.MonkeyPatch,
    workspace_path: Path,
    sample_exec_profile: ToolProfile,
) -> None:
    """A command returning exit code 1 inside the container returns SandboxResult(ok=False, exit_code=1)."""
    def fake_run(argv: list[str], timeout_s: float) -> subprocess.CompletedProcess[bytes]:
        return _completed(stderr=b"grep: pattern not found\n", returncode=1)

    monkeypatch.setattr("warden.sandbox.docker._blocking_run", fake_run)

    sandbox = DockerSandbox(
        workspace_path=workspace_path,
        registry_getter=lambda name: sample_exec_profile,
    )

    action = Action(
        id="act-exit1",
        kind=ActionKind.TOOL,
        name="file_inspect",
        payload={"argv": ["grep", "something", "/workspace/file"]},
        run_id="run-1",
        thread_id="th-1",
    )

    result = await sandbox.run(action)

    assert result.ok is False
    assert result.exit_code == 1
    assert result.timed_out is False
    assert result.stderr == "grep: pattern not found\n"
    assert result.profile == "docker:file_inspect:exec-netnone"


@pytest.mark.asyncio
async def test_cancellation_cleans_up_container_and_reraises(
    monkeypatch: pytest.MonkeyPatch,
    workspace_path: Path,
    sample_exec_profile: ToolProfile,
) -> None:
    """When action execution is cancelled, container cleanup runs and CancelledError propagates."""
    cleaned: list[str] = []

    def fake_run(argv: list[str], timeout_s: float) -> subprocess.CompletedProcess[bytes]:
        time.sleep(0.5)
        return _completed()

    def fake_cleanup(container_name: str) -> None:
        cleaned.append(container_name)

    def fake_reconcile(container_name: str) -> None:
        fake_cleanup(container_name)

    monkeypatch.setattr("warden.sandbox.docker._blocking_run", fake_run)
    monkeypatch.setattr("warden.sandbox.docker._blocking_reconcile", fake_reconcile)

    sandbox = DockerSandbox(
        workspace_path=workspace_path,
        registry_getter=lambda name: sample_exec_profile,
    )

    action = Action(
        id="act-cancel",
        kind=ActionKind.TOOL,
        name="file_inspect",
        payload={"argv": ["ls"]},
        run_id="run-c",
        thread_id="th-c",
    )

    task = asyncio.create_task(sandbox.run(action))
    await asyncio.sleep(0.05)
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task

    assert cleaned == ["warden-act-cancel"]


def test_reconcile_retries_until_container_gone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_blocking_reconcile re-removes while docker inspect still sees the name."""
    from warden.sandbox.docker import _blocking_reconcile

    cleaned: list[str] = []
    seen: list[bool] = [True, True, False]

    def fake_cleanup(container_name: str) -> None:
        cleaned.append(container_name)

    def fake_exists(container_name: str) -> bool:
        assert container_name == "warden-late-container"
        return seen.pop(0)

    monkeypatch.setattr("warden.sandbox.docker._blocking_cleanup", fake_cleanup)
    monkeypatch.setattr("warden.sandbox.docker._container_exists", fake_exists)

    _blocking_reconcile("warden-late-container", attempts=5, delay_s=0.0)

    assert cleaned == ["warden-late-container"] * 3


def test_reconcile_gives_up_after_attempts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_blocking_reconcile stops after `attempts` even if the name persists."""
    from warden.sandbox.docker import _blocking_reconcile

    cleaned: list[str] = []

    def fake_cleanup(container_name: str) -> None:
        cleaned.append(container_name)

    monkeypatch.setattr("warden.sandbox.docker._blocking_cleanup", fake_cleanup)
    monkeypatch.setattr("warden.sandbox.docker._container_exists", lambda name: True)

    _blocking_reconcile("warden-stuck", attempts=3, delay_s=0.0)

    assert cleaned == ["warden-stuck"] * 3
