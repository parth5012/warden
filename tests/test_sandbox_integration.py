"""Integration proofs for DockerSandbox against real Docker daemon.

Validates:
1. Proof 1 (Network dead): Egress blocked by --network=none.
2. Proof 2 (Workspace cleanup & read-only rootfs): Writable workspace can delete
   files on host; root filesystem writes are rejected with read-only error.
3. Proof 3 (Read-only mount): Read-only tool profile prevents host file modification.
4. Proof 4 (Timeout kills): Execution timeout triggers SIGKILL and container removal;
   no lingering containers remain.
5. Proof 5 (No leftovers): No containers named warden-* left running or stopped.
"""

from __future__ import annotations

import asyncio
from collections.abc import Generator
from collections.abc import Coroutine
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Any, TypeVar

import pytest

from warden.models import Action, ActionKind
from warden.sandbox.docker import DockerSandbox
from warden.sandbox.port import SandboxResult
from warden.sandbox.registry import ToolProfile, get_profile

T = TypeVar("T")


def _is_docker_available() -> bool:
    """Check if Docker CLI is present and the Docker daemon is responding."""
    if not shutil.which("docker"):
        return False
    try:
        res = subprocess.run(
            ["docker", "info"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
        return res.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


pytestmark = pytest.mark.skipif(
    not _is_docker_available(),
    reason="Docker daemon is unavailable or not running",
)


def _run(coro: Coroutine[Any, Any, T]) -> T:
    """Run an async coroutine on a ProactorEventLoop on Windows.

    WindowsSelectorEventLoopPolicy does not support subprocess execution.
    Explicitly running on ProactorEventLoop isolates subprocess operations
    from any global selector policy without corrupting psycopg compatibility.
    """
    if sys.platform == "win32":
        loop = asyncio.ProactorEventLoop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()
    return asyncio.run(coro)


def _get_warden_containers() -> list[str]:
    """List any active or stopped container names matching 'warden-*'."""
    proc = subprocess.run(
        ["docker", "ps", "-a", "--filter", "name=warden-", "--format", "{{.Names}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    return [
        line.strip()
        for line in proc.stdout.splitlines()
        if line.strip().startswith("warden-")
    ]


@pytest.fixture(scope="module", autouse=True)
def initial_container_cleanup() -> Generator[None, None, None]:
    """Ensure no stale warden containers exist before running the suite."""
    stale = _get_warden_containers()
    for name in stale:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
    yield


@pytest.fixture
def workspace() -> Generator[Path, None, None]:
    """Provide workspace directory on host, cleaning any staged test artifacts."""
    d_tmp = Path("D:/tmp")
    ws = (
        d_tmp
        if d_tmp.exists() and d_tmp.is_dir()
        else Path(tempfile.gettempdir()) / "warden_test_ws"
    )
    ws.mkdir(parents=True, exist_ok=True)

    # Clean pre-existing test artifacts
    for filename in ("test_file.txt", "warden_probe"):
        target = ws / filename
        if target.exists():
            target.unlink(missing_ok=True)

    yield ws

    # Clean staged artifacts after test
    for filename in ("test_file.txt", "warden_probe"):
        target = ws / filename
        if target.exists():
            target.unlink(missing_ok=True)


def test_proof_1_network_dead(workspace: Path) -> None:
    """Proof 1: Outbound network egress is completely blocked by --network=none."""
    sandbox = DockerSandbox(workspace_path=workspace)
    action = Action(
        id="proof1-net-dead",
        kind=ActionKind.TOOL,
        name="shell",
        payload={
            "command": "wget -q -T 3 -O - http://example.com 2>&1 || echo BLOCKED"
        },
        run_id="run-net-1",
        thread_id="th-net-1",
    )

    result: SandboxResult = _run(sandbox.run(action))

    assert result.timed_out is False
    combined_output = f"{result.stdout}\n{result.stderr}".lower()
    assert (
        "blocked" in combined_output
        or "bad address" in combined_output
        or "unreachable" in combined_output
    )


def test_proof_2_workspace_cleanup_and_readonly_rootfs(workspace: Path) -> None:
    """Proof 2: Files in workspace can be deleted; writes to rootfs fail with read-only error."""
    # Step A: Stage file in workspace and delete it via file_cleanup tool
    test_file = workspace / "test_file.txt"
    test_file.write_text("temporary integration test payload", encoding="utf-8")
    assert test_file.exists()

    sandbox = DockerSandbox(workspace_path=workspace)
    cleanup_action = Action(
        id="proof2-cleanup",
        kind=ActionKind.TOOL,
        name="file_cleanup",
        payload={"argv": ["rm", "/workspace/test_file.txt"]},
        run_id="run-clean-2",
        thread_id="th-clean-2",
    )

    cleanup_result: SandboxResult = _run(sandbox.run(cleanup_action))
    assert cleanup_result.ok is True
    assert cleanup_result.exit_code == 0
    assert not test_file.exists(), f"File {test_file} should have been deleted on host"

    # Step B: Attempt writing to root / modifying read-only rootfs
    hack_action = Action(
        id="proof2-hack-rootfs",
        kind=ActionKind.TOOL,
        name="shell",
        payload={"command": "touch /etc/hacked"},
        run_id="run-clean-2",
        thread_id="th-clean-2",
    )

    hack_result: SandboxResult = _run(sandbox.run(hack_action))
    assert hack_result.ok is False
    assert hack_result.exit_code != 0
    combined_err = f"{hack_result.stdout} {hack_result.stderr}".lower()
    assert "read-only" in combined_err


def test_proof_3_readonly_mount(workspace: Path) -> None:
    """Proof 3: file_inspect has mount='ro', preventing modifications inside /workspace."""
    probe_file = workspace / "warden_probe"
    if probe_file.exists():
        probe_file.unlink(missing_ok=True)

    sandbox = DockerSandbox(workspace_path=workspace)
    probe_action = Action(
        id="proof3-ro-mount",
        kind=ActionKind.TOOL,
        name="file_inspect",
        payload={"argv": ["touch", "/workspace/warden_probe"]},
        run_id="run-ro-3",
        thread_id="th-ro-3",
    )

    probe_result: SandboxResult = _run(sandbox.run(probe_action))
    assert probe_result.ok is False
    assert probe_result.exit_code != 0
    combined_err = f"{probe_result.stdout} {probe_result.stderr}".lower()
    assert "read-only" in combined_err
    assert (
        not probe_file.exists()
    ), f"Host file {probe_file} must NOT have been created"


def test_proof_4_timeout_kills(workspace: Path) -> None:
    """Proof 4: Timeout triggers process termination, returning timed_out=True with no leftover containers."""
    timeout_profile = ToolProfile(
        name="sleep_tool",
        mode="exec",
        mount="none",
        timeout_s=1,
        memory="256m",
        cpus="1",
    )

    def custom_registry(name: str) -> ToolProfile | None:
        if name == "sleep_tool":
            return timeout_profile
        return get_profile(name)

    sandbox = DockerSandbox(workspace_path=workspace, registry_getter=custom_registry)
    timeout_action = Action(
        id="proof4-timeout-kill",
        kind=ActionKind.TOOL,
        name="sleep_tool",
        payload={"argv": ["sleep", "10"]},
        run_id="run-timeout-4",
        thread_id="th-timeout-4",
    )

    result: SandboxResult = _run(sandbox.run(timeout_action))

    assert result.timed_out is True
    assert result.ok is False
    assert result.duration_ms < 10000

    # Ensure this specific container is no longer lingering
    containers = _get_warden_containers()
    assert f"warden-{timeout_action.id}" not in containers


def test_proof_5_no_leftovers() -> None:
    """Proof 5: Assert that after all integration tests, no containers named warden-* remain running or stopped."""
    containers = _get_warden_containers()
    assert (
        containers == []
    ), f"Lingering warden container(s) detected after test suite: {containers}"
