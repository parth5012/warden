"""L0 static rules: instant deny on known-destructive patterns or escalation on scoped patterns.

Zero dependencies, zero latency budget. Runs before any model.
Distinguishes bounded, parseable destructive intent (escalate) from
unbounded or unparseable destructive intent (terminal deny).
"""

from __future__ import annotations

import re
from typing import Any

# (pattern, policy_id) — keep small and obvious; semantic stuff belongs in L1/L2.
_BLOCKED: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bdrop\s+database\b", re.IGNORECASE), "no-destructive-sql"),
    (re.compile(r"\bdelete\s+from\b", re.IGNORECASE), "no-destructive-sql"),
    (re.compile(r"\btruncate(\s+table)?\b", re.IGNORECASE), "no-destructive-sql"),
    (re.compile(r"mkfs(\.|$|\s)", re.IGNORECASE), "no-destructive-shell"),
    (re.compile(r":\(\)\s*\{\s*:\|\:&\s*\}\s*;", re.IGNORECASE), "no-forkbomb"),
)

# Unbounded root / wildcard / traversal shell deletion
_UNBOUNDED_SHELL_RM: re.Pattern[str] = re.compile(
    r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*\s+(/|\/\*|~\b|\*|\.\.)(?:\s|$)", re.IGNORECASE
)

# Single explicit table-name DDL: DROP TABLE [IF EXISTS] [schema.]<name> [;]
# Must not contain CASCADE, RESTRICT, multiple statements, wildcards, or multiple tables.
_SCOPED_DROP_TABLE_RE: re.Pattern[str] = re.compile(
    r"^\s*DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)?|\"[^\"]+\")\s*;?\s*$",
    re.IGNORECASE,
)

# Allowed directory boundary for scoped file operations
def is_scoped_path(path: str) -> bool:
    """Check if path is strictly /workspace/tmp or inside /workspace/tmp/."""
    if ".." in path:
        return False
    normalized = path.rstrip("/")
    return normalized == "/workspace/tmp" or path.startswith("/workspace/tmp/")


def is_scoped_drop_table(sql: str) -> tuple[bool, str | None]:
    """Check if SQL is a single explicit table-name DROP TABLE statement.

    Returns (True, table_name) if bounded and parseable, else (False, None).
    """
    clean = sql.strip()
    if not clean:
        return False, None
    if re.search(r"\b(cascade|restrict)\b", clean, re.IGNORECASE):
        return False, None
    if clean.rstrip(";").find(";") != -1:
        # Multi-statement detected
        return False, None
    match = _SCOPED_DROP_TABLE_RE.match(clean)
    if match:
        table_name = match.group(1).strip('"')
        return True, table_name
    return False, None


def is_scoped_fs_delete(action_name: str, payload: dict[str, Any]) -> tuple[bool, str | None]:
    """Check if action is a file operation confined under an explicit path prefix.

    Returns (True, path) if bounded under an allowed prefix, else (False, None).
    """
    # Check shell command payload
    cmd = str(payload.get("cmd") or payload.get("command") or "").strip()
    if cmd:
        # Disallow multi-command chaining or shell substitutions or newlines
        if any(c in cmd for c in (";", "&", "|", "`", "$", "\n")):
            return False, None
        tokens = cmd.split()
        if not tokens or tokens[0] != "rm":
            return False, None
        targets = [t.strip("\"'") for t in tokens[1:] if not t.startswith("-")]
        if not targets:
            return False, None
        for target in targets:
            if ".." in target or target in ("/", "/*", "*", "~"):
                return False, None
            if target.startswith(("/etc", "/boot", "/sys", "/proc", "/root", "/bin", "/usr")):
                return False, None
            if not is_scoped_path(target):
                return False, None
        return True, targets[0]

    # Check batch file deletion action
    if (
        action_name in ("batch_delete_files", "mass_delete", "delete_files")
        or payload.get("operation") == "FILE_BATCH_DELETE"
    ):
        target = str(payload.get("target_resource") or payload.get("path") or "")
        raw_targets: Any = payload.get("targets")
        target_list: list[str] = [str(t) for t in raw_targets] if isinstance(raw_targets, list) else []
        if target:
            target_list.append(target)

        if not target_list:
            return False, None

        for path in target_list:
            if ".." in path or path in ("/", "/*", "*", "~"):
                return False, None
            if path.startswith(("/etc", "/boot", "/sys", "/proc", "/root", "/bin", "/usr")):
                return False, None
            if not is_scoped_path(path):
                return False, None

        return True, target_list[0]

    return False, None


def find_scoped_escalation(action_name: str, payload: dict[str, Any]) -> str | None:
    """Return rule_id if action/payload matches a bounded scoped destructive pattern, else None."""
    # Check SQL in payload
    sql = str(payload.get("sql", ""))
    if sql:
        is_scoped, _ = is_scoped_drop_table(sql)
        if is_scoped:
            return "scoped-ddl-drop-table"

    # Check file deletion in action/payload
    is_scoped_fs, _ = is_scoped_fs_delete(action_name, payload)
    if is_scoped_fs:
        return "scoped-fs-batch-delete"

    return None


def _is_scoped_rm(text: str) -> bool:
    """Check if all rm -rf commands in text are strictly scoped under /workspace/tmp/."""
    rm_lines = [
        line for line in text.splitlines() if re.search(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*\s+", line, re.IGNORECASE)
    ]
    if not rm_lines or len(rm_lines) > 1:
        # Multi-command rm is unparseable/unbounded at L0
        return False
    rm_line = rm_lines[0]
    if any(c in rm_line for c in (";", "&", "|", "`", "$")):
        return False
    tokens = rm_line.split()
    try:
        rm_idx = tokens.index("rm")
    except ValueError:
        return False
    targets = [t.strip("\"'") for t in tokens[rm_idx + 1 :] if not t.startswith("-")]
    if not targets:
        return False
    for target in targets:
        if ".." in target or target in ("/", "/*", "*", "~"):
            return False
        if target.startswith(("/etc", "/boot", "/sys", "/proc", "/root", "/bin", "/usr")):
            return False
        if not is_scoped_path(target):
            return False
    return True


def find_static_violation(text: str) -> str | None:
    """Return policy_id if text matches a blocked pattern, else None."""
    for pattern, policy_id in _BLOCKED:
        if pattern.search(text):
            return policy_id

    if _UNBOUNDED_SHELL_RM.search(text):
        return "no-destructive-shell"

    rm_matches = re.findall(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*\s+", text, re.IGNORECASE)
    if len(rm_matches) > 1 or (len(rm_matches) == 1 and not _is_scoped_rm(text)):
        return "no-destructive-shell"

    # Any DROP TABLE in text that is not a single scoped table drop is a static violation
    if re.search(r"\bdrop\s+table\b", text, re.IGNORECASE):
        drop_matches = re.findall(r"\bdrop\s+table\b", text, re.IGNORECASE)
        if len(drop_matches) > 1:
            return "no-destructive-sql"
        # Validate the full SQL statement across lines
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if len(lines) > 1 and not re.search(r"\b(select|insert|update|delete|drop|create|alter|truncate)\b", lines[0], re.IGNORECASE):
            sql_lines = lines[1:]
        else:
            sql_lines = lines
        sql_text = " ".join(sql_lines) if sql_lines else text.strip()
        is_scoped, _ = is_scoped_drop_table(sql_text)
        if not is_scoped:
            return "no-destructive-sql"

    return None


def action_text(name: str, payload: dict[str, Any]) -> str:
    """Flatten action name + payload values into searchable text."""
    parts = [name]
    for value in payload.values():
        parts.append(str(value))
    return "\n".join(parts)
