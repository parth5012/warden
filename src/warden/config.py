"""Aegis configuration and environment settings."""

from __future__ import annotations

import asyncio
from pathlib import Path
import sys
from pydantic import AliasChoices, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def ensure_windows_event_loop() -> None:
    """Ensure WindowsSelectorEventLoopPolicy is active on Windows for psycopg async."""
    if sys.platform == "win32":
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        except Exception:
            pass


ensure_windows_event_loop()

_CURRENT_DIR = Path(__file__).resolve().parent
_WORKSPACE_ROOT = _CURRENT_DIR.parent.parent
_ENV_FILES = (
    str(_WORKSPACE_ROOT / ".env"),
    str(_CURRENT_DIR / ".env"),
    ".env",
)


class Settings(BaseSettings):
    """Runtime settings loaded from environment or .env file."""

    model_config = SettingsConfigDict(
        env_file=_ENV_FILES,
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    groq_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("GROQ_API_KEY", "groq_api_key"),
        description="API key for Groq LLM inference.",
    )
    groq_model: str = Field(
        default="openai/gpt-oss-20b",
        validation_alias=AliasChoices("GROQ_MODEL", "groq_model"),
        description="Model identifier to use with Groq.",
    )
    postgres_uri: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "CONNECTION_STRING",
            "DATABASE_URL",
            "POSTGRES_URI",
            "POSTGRES_URL",
            "WARDEN_PG_URI",
            "postgres_uri",
        ),
        description="PostgreSQL connection string.",
    )
    sandbox_workspace: Path = Field(
        default_factory=lambda: (
            Path("D:/tmp") if sys.platform == "win32" else Path("/tmp")
        ),
        validation_alias=AliasChoices(
            "WARDEN_SANDBOX_WORKSPACE",
            "SANDBOX_WORKSPACE",
            "sandbox_workspace",
        ),
        description="Host directory mounted into container as workspace.",
    )
    sandbox_image: str = Field(
        default="",
        validation_alias=AliasChoices(
            "WARDEN_SANDBOX_IMAGE",
            "SANDBOX_IMAGE",
            "sandbox_image",
        ),
        description="Override container image (empty string uses registry default).",
    )
    clef_account_id: str = Field(
        default="",
        validation_alias=AliasChoices("CLOUDFLARE_ACCOUNT_ID", "CLEF_ACCOUNT_ID", "clef_account_id"),
        description="Cloudflare account ID for Workers AI Clef endpoint.",
    )
    clef_api_token: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("CLOUDFLARE_API_TOKEN", "CLEF_API_TOKEN", "clef_api_token"),
        description="Cloudflare API token for Workers AI.",
    )
    clef_model: str = Field(
        default="@cf/cloudflare/clef-flash",
        validation_alias=AliasChoices("CLEF_MODEL", "clef_model"),
        description="Workers AI model id (@cf/cloudflare/clef-flash or @cf/cloudflare/clef).",
    )
    clef_timeout_s: float = Field(
        default=8.0,
        validation_alias=AliasChoices("CLEF_TIMEOUT_S", "clef_timeout_s"),
        description="Workers AI request timeout in seconds (fail closed on expiry).",
    )
    gate_deny_threshold: float = Field(
        default=0.85,
        validation_alias=AliasChoices("GATE_DENY_THRESHOLD", "gate_deny_threshold"),
        description="Score >= this denies (L1/L2).",
    )
    gate_clean_threshold: float = Field(
        default=0.20,
        validation_alias=AliasChoices("GATE_CLEAN_THRESHOLD", "gate_clean_threshold"),
        description="Score <= this is clean; between clean and deny escalates to HITL.",
    )

    @field_validator("sandbox_workspace")
    @classmethod
    def _resolve_sandbox_workspace(cls, v: Path) -> Path:
        resolved = v.resolve()
        try:
            resolved.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
        return resolved


settings = Settings()
