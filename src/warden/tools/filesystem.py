"""Sensitive file reading tool for Aegis governance.

Enforces:
- Canonical path checks against approved root directory
- Rejection of path traversal (..), root escapes, and unauthorized symlinks
- Rejection of prohibited sensitive files (.env, id_rsa, /etc/passwd, credentials, private keys)
- Safe fixture fallback
- Recursive secret redaction
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path

from warden.journal import redact_secrets_in_obj
from warden.models import Action

logger = logging.getLogger("warden.tools.filesystem")

MAX_FILE_BYTES = 65536  # 64 KB

PROHIBITED_FILE_PATTERNS = (
    r"\.env(?:\..*)?$",
    r".*id_rsa.*",
    r".*id_ed25519.*",
    r".*\.pem$",
    r".*\.key$",
    r".*credentials.*",
    r".*passwd.*",
    r".*shadow.*",
    r".*secret.*",
    r".*sudoers.*",
)

PROHIBITED_REGEX = re.compile(
    "|".join(f"(?:{p})" for p in PROHIBITED_FILE_PATTERNS),
    re.IGNORECASE,
)


@dataclass(frozen=True)
class FileContentResult:
    """Structured sensitive file reading result."""

    path: str
    content: str
    size_bytes: int


# Synthetic fixture files for demo / safe testing
_SAFE_FIXTURES: dict[str, str] = {
    "system_overview.md": "# System Overview\nAll microservices healthy.\nNo incidents in past 24h.",
    "audit_config.json": '{\n  "retention_days": 90,\n  "log_level": "INFO",\n  "compliance": "SOC2"\n}',
    "service_catalog.yaml": "services:\n  - api-gateway\n  - auth-service\n  - order-service",
}


def is_prohibited_sensitive_path(path_str: str) -> bool:
    """Check if a path matches unauthorized sensitive file patterns."""
    normalized = path_str.replace("\\", "/")
    # Traversal check
    if "../" in normalized or "/.." in normalized or normalized == ".." or normalized.startswith("../"):
        return True
    # System root escapes
    if normalized.startswith("/") or re.match(r"^[a-zA-Z]:", path_str):
        return True
    # Prohibited patterns check
    base_name = Path(normalized).name
    if PROHIBITED_REGEX.match(base_name) or PROHIBITED_REGEX.match(normalized):
        return True
    return False


def read_file_sensitive(
    action: Action,
    safe_root_dir: Path | None = None,
) -> FileContentResult:
    """Handler for read_file_sensitive.

    Validates:
    - Path string does not attempt traversal or match prohibited patterns
    - Resolves canonical path strictly inside safe_root_dir
    - Rejects unauthorized symlinks escaping safe root
    - Redacts any matching credential patterns
    """
    path_param = action.payload.get("path") or action.payload.get("file_path")
    if not isinstance(path_param, str) or not path_param.strip():
        raise ValueError("Payload must contain a non-empty 'path' string")

    # 1. Reject prohibited sensitive patterns and basic traversal syntax
    if is_prohibited_sensitive_path(path_param):
        raise PermissionError(
            f"Access denied: Path '{path_param}' matches prohibited sensitive file or traversal patterns"
        )

    content = ""
    # 2. Canonical path resolution if root directory is provided
    if safe_root_dir is not None:
        canonical_root = safe_root_dir.resolve()
        target_path = (canonical_root / path_param).resolve()

        # Enforce canonical containment
        try:
            target_path.relative_to(canonical_root)
        except ValueError:
            raise PermissionError(
                f"Access denied: Resolved path '{target_path}' escapes approved safe root '{canonical_root}'"
            )

        # Enforce symlink resolution containment
        raw_target = canonical_root / path_param
        if raw_target.is_symlink():
            real_target = Path(os.path.realpath(raw_target)).resolve()
            try:
                real_target.relative_to(canonical_root)
            except ValueError:
                raise PermissionError(
                    f"Access denied: Symlink '{raw_target}' escapes approved safe root '{canonical_root}'"
                )

        if not target_path.is_file():
            raise FileNotFoundError(f"File not found: {path_param}")

        with open(target_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read(MAX_FILE_BYTES)
    else:
        # Fallback to in-memory safe fixtures if no physical directory passed
        if path_param in _SAFE_FIXTURES:
            content = _SAFE_FIXTURES[path_param]
        else:
            raise FileNotFoundError(f"Safe fixture not found: {path_param}")

    # 3. Scrub secrets
    safe_content = str(redact_secrets_in_obj(content))

    return FileContentResult(
        path=path_param,
        content=safe_content,
        size_bytes=len(safe_content.encode("utf-8")),
    )
