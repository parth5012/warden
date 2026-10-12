"""Tests for warden.config settings and Groq LLM client."""

from __future__ import annotations

import pathlib
import sys
import pytest
from pydantic import SecretStr

from warden.config import Settings
from warden.demo_graph import draft_node


def test_settings_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    for k in [
        "CONNECTION_STRING",
        "DATABASE_URL",
        "POSTGRES_URI",
        "POSTGRES_URL",
        "WARDEN_PG_URI",
        "GROQ_API_KEY",
        "GROQ_MODEL",
    ]:
        monkeypatch.delenv(k, raising=False)

    s = Settings(
        groq_api_key=None,
        postgres_uri=None,
    )
    assert s.groq_api_key is None
    assert s.postgres_uri is None
    assert s.groq_model == "openai/gpt-oss-20b"
    expected_default_ws = (
        pathlib.Path("D:/tmp") if sys.platform == "win32" else pathlib.Path("/tmp")
    )
    assert s.sandbox_workspace == expected_default_ws
    assert s.sandbox_image == ""


@pytest.mark.parametrize(
    "env_key",
    ["CONNECTION_STRING", "DATABASE_URL", "POSTGRES_URI", "POSTGRES_URL", "WARDEN_PG_URI"],
)
def test_settings_postgres_aliases(
    monkeypatch: pytest.MonkeyPatch, env_key: str
) -> None:
    uri = "postgresql://user:pass@localhost:5432/testdb"
    for k in [
        "CONNECTION_STRING",
        "DATABASE_URL",
        "POSTGRES_URI",
        "POSTGRES_URL",
        "WARDEN_PG_URI",
    ]:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv(env_key, uri)

    s = Settings()
    assert s.postgres_uri == uri


def test_settings_groq_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GROQ_API_KEY", "gsk_test123")
    monkeypatch.setenv("GROQ_MODEL", "qwen/qwen3.8-27b")

    s = Settings()
    assert s.groq_api_key is not None
    assert s.groq_api_key.get_secret_value() == "gsk_test123"
    assert s.groq_model == "qwen/qwen3.8-27b"


def test_draft_node_without_llm(monkeypatch: pytest.MonkeyPatch) -> None:
    out = draft_node({"messages": [], "approved": False})
    assert "Drafted email: 'Weekly report ready'" in out["messages"][0]


@pytest.mark.parametrize("env_key", ["WARDEN_SANDBOX_WORKSPACE", "SANDBOX_WORKSPACE"])
def test_settings_sandbox_workspace_aliases(
    monkeypatch: pytest.MonkeyPatch, env_key: str
) -> None:
    custom_path = "D:/custom_workspace" if sys.platform == "win32" else "/custom_workspace"
    monkeypatch.delenv("WARDEN_SANDBOX_WORKSPACE", raising=False)
    monkeypatch.delenv("SANDBOX_WORKSPACE", raising=False)
    monkeypatch.setenv(env_key, custom_path)

    s = Settings(groq_api_key=None, postgres_uri=None)
    assert s.sandbox_workspace == pathlib.Path(custom_path)


@pytest.mark.parametrize("env_key", ["WARDEN_SANDBOX_IMAGE", "SANDBOX_IMAGE"])
def test_settings_sandbox_image_aliases(
    monkeypatch: pytest.MonkeyPatch, env_key: str
) -> None:
    custom_img = "custom/sandbox:v1"
    monkeypatch.delenv("WARDEN_SANDBOX_IMAGE", raising=False)
    monkeypatch.delenv("SANDBOX_IMAGE", raising=False)
    monkeypatch.setenv(env_key, custom_img)

    s = Settings(groq_api_key=None, postgres_uri=None)
    assert s.sandbox_image == custom_img


def test_settings_sandbox_workspace_resolves_relative(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WARDEN_SANDBOX_WORKSPACE", "relative_dir")
    s = Settings(groq_api_key=None, postgres_uri=None)
    assert s.sandbox_workspace.is_absolute()
    assert s.sandbox_workspace == pathlib.Path("relative_dir").resolve()
