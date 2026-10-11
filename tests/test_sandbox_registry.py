"""Tests for sandbox tool profile registry and seed profiles.

Validates:
A. Every Phase-1 seed tool ("shell", "file_inspect", "file_cleanup", "code") resolves via get_profile.
B. Unknown tool returns None.
C. Seeded caps match locked defaults: timeout_s=30, memory="256m", cpus="1", image="alpine:3.20".
D. "shell" ONLY seed profile mode="shell". Others mode="exec".
E. Mount settings: "shell" -> "rw", "file_inspect" -> "ro", "file_cleanup" -> "rw", "code" -> "rw".
F. ToolProfile instances are frozen (cannot mutate attributes).
"""

from __future__ import annotations

import dataclasses

import pytest

import warden.sandbox
from warden.sandbox import ToolProfile, get_profile
from warden.sandbox.registry import DEFAULT_IMAGE, SEED_PROFILES

PHASE_1_TOOLS: list[str] = ["shell", "file_inspect", "file_cleanup", "code"]


def test_seed_tools_resolve() -> None:
    """A. Every Phase-1 seed tool resolves via get_profile."""
    for tool_name in PHASE_1_TOOLS:
        profile = get_profile(tool_name)
        assert profile is not None
        assert isinstance(profile, ToolProfile)
        assert profile.name == tool_name


def test_unknown_tool_returns_none() -> None:
    """B. Unknown tool returns None."""
    assert get_profile("unknown_tool") is None
    assert get_profile("") is None
    assert get_profile("nonexistent") is None
    assert get_profile("drop_table") is None
    assert get_profile("python") is None


def test_seeded_caps_match_locked_defaults() -> None:
    """C. Seeded caps match locked defaults: timeout_s=30, memory='256m', cpus='1', image='alpine:3.20'."""
    for tool_name in PHASE_1_TOOLS:
        profile = get_profile(tool_name)
        assert profile is not None
        assert profile.timeout_s == 30
        assert profile.memory == "256m"
        assert profile.cpus == "1"
        assert profile.image == DEFAULT_IMAGE


def test_mode_settings_shell_only_has_shell_mode() -> None:
    """D. 'shell' ONLY seed profile has mode='shell'. Others have mode='exec'."""
    shell_profile = get_profile("shell")
    assert shell_profile is not None
    assert shell_profile.mode == "shell"

    exec_tools = ["file_inspect", "file_cleanup", "code"]
    for tool_name in exec_tools:
        profile = get_profile(tool_name)
        assert profile is not None
        assert profile.mode == "exec"

    # Ensure no other seeded profile has mode == 'shell'
    for name, prof in SEED_PROFILES.items():
        if name != "shell":
            assert prof.mode == "exec"


def test_mount_settings() -> None:
    """E. Mount settings: 'shell' -> 'rw', 'file_inspect' -> 'ro', 'file_cleanup' -> 'rw', 'code' -> 'rw'."""
    expected_mounts: dict[str, str] = {
        "shell": "rw",
        "file_inspect": "ro",
        "file_cleanup": "rw",
        "code": "rw",
    }
    for tool_name, expected_mount in expected_mounts.items():
        profile = get_profile(tool_name)
        assert profile is not None
        assert profile.mount == expected_mount


def test_tool_profile_frozen() -> None:
    """F. ToolProfile instances are frozen (cannot mutate attributes)."""
    profile = get_profile("shell")
    assert profile is not None

    with pytest.raises(dataclasses.FrozenInstanceError):
        profile.name = "mutated"  # type: ignore[misc]

    with pytest.raises(dataclasses.FrozenInstanceError):
        profile.mode = "exec"  # type: ignore[misc]

    with pytest.raises(dataclasses.FrozenInstanceError):
        profile.mount = "ro"  # type: ignore[misc]

    with pytest.raises(dataclasses.FrozenInstanceError):
        profile.timeout_s = 60  # type: ignore[misc]

    with pytest.raises(dataclasses.FrozenInstanceError):
        profile.memory = "512m"  # type: ignore[misc]

    with pytest.raises(dataclasses.FrozenInstanceError):
        profile.cpus = "2"  # type: ignore[misc]

    with pytest.raises(dataclasses.FrozenInstanceError):
        profile.image = "ubuntu:latest"  # type: ignore[misc]


def test_tool_profile_defaults() -> None:
    """ToolProfile dataclass defaults apply when optional fields are omitted."""
    custom = ToolProfile(name="custom_tool", mode="exec", mount="none")
    assert custom.name == "custom_tool"
    assert custom.mode == "exec"
    assert custom.mount == "none"
    assert custom.timeout_s == 30
    assert custom.memory == "256m"
    assert custom.cpus == "1"
    assert custom.image == DEFAULT_IMAGE


def test_reexports() -> None:
    """ToolProfile and get_profile must be re-exported by warden.sandbox."""
    assert hasattr(warden.sandbox, "ToolProfile")
    assert hasattr(warden.sandbox, "get_profile")
    assert warden.sandbox.ToolProfile is ToolProfile
    assert warden.sandbox.get_profile is get_profile
    assert "ToolProfile" in warden.sandbox.__all__
    assert "get_profile" in warden.sandbox.__all__
