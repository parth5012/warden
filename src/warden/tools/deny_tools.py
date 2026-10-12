"""Terminal-deny tools: DENY is terminal, no human override (lock 5).

Uses only existing policy seams: layers_static + PolicyEngine with its
default fake scorers. No new deps (no sqlglot).
"""

from __future__ import annotations

from pathlib import PurePath
from typing import Any
import re

from warden.models import Denied
from warden.policy.engine import PolicyDecision, PolicyEngine, PolicyError, PolicyVerdict
from warden.policy.layers_static import action_text, find_static_violation
from warden.tools.base import ToolSpec

EXEC_DB_MUTATION_SPEC = ToolSpec(
    name="exec_db_mutation",
    description="SQL mutation entry — destructive DDL denied terminally.",
    payload_schema={"sql": "str"},
    execution_path="aborted",
    triggers_rule=True,
)

READ_FILE_SENSITIVE_SPEC = ToolSpec(
    name="read_file_sensitive",
    description="File read with path-ACL guard (secret/traversal denied).",
    payload_schema={"path": "str"},
    execution_path="aborted",
    triggers_rule=True,
)

_BLOCKED_BASENAMES = {".env", "id_rsa", "id_ed25519", ".pem", "secrets.yaml", "shadow", "passwd"}
_BLOCKED_TOKENS = ("OPENAI_API_KEY", "WARDEN_PG_URI", "GROQ_API_KEY")

# Bare destructive keywords (covers "TRUNCATE orders" without TABLE, which the
# L0 static regex misses). Keep in sync with safe_tools._WRITE_KW_RE.
_DESTRUCTIVE_RE = re.compile(
    r"\b(drop|truncate|delete|insert|update|alter|create|grant|revoke)\b",
    re.IGNORECASE,
)


def evaluate_text(
    action_name: str,
    payload: dict[str, Any],
    engine: PolicyEngine | None = None,
) -> PolicyVerdict:
    eng = engine or PolicyEngine()
    text = action_text(action_name, payload)
    static_hit = find_static_violation(text)
    if static_hit is not None:
        from warden.policy.engine import PolicyVerdict as _V

        return _V(
            decision=PolicyDecision.DENY,
            reason=f"static rule matched: {static_hit}",
            policy=static_hit,
            layer="L0-static",
            scores={},
        )
    return eng.evaluate(action_name, payload)


def check_db_mutation(payload: dict[str, Any], engine: PolicyEngine | None = None) -> Denied | None:
    """Return Denied if the SQL must be refused, else None (allowed-preview)."""
    sql = str(payload.get("sql", ""))
    hit = find_static_violation(f"exec_db_mutation\n{sql}")
    if hit is None and _DESTRUCTIVE_RE.search(sql):
        hit = "no-destructive-sql"
    if hit is not None:
        return Denied(reason="Destructive DDL forbidden by policy", policy=hit)
    try:
        verdict = (engine or PolicyEngine()).evaluate("exec_db_mutation", payload)
    except PolicyError as exc:
        # Fail-closed maps to Error upstream; here signal via policy id.
        return Denied(reason="governance_unavailable", policy=str(exc))
    if verdict.decision == PolicyDecision.DENY:
        return Denied(reason=verdict.reason, policy=verdict.policy)
    return None


def check_path(path: str) -> Denied | None:
    """L0 path ACL. Returns Denied if blocked, else None."""
    lowered = path.replace("\\", "/")
    if ".." in lowered:
        return Denied(reason="Path traversal blocked by ACL policy", policy="path-acl")
    base = PurePath(lowered).name.lower()
    if base in _BLOCKED_BASENAMES or lowered in ("/etc/shadow", "/etc/passwd"):
        return Denied(reason="Secret file blocked by ACL policy", policy="path-acl")
    if any(tok in path for tok in _BLOCKED_TOKENS):
        return Denied(reason="Secret token in path blocked by policy", policy="secret-acl")
    return None


async def run_db_mutation(payload: dict[str, Any], engine: PolicyEngine | None = None) -> dict[str, Any]:
    denied = check_db_mutation(payload, engine)
    if denied is not None:
        # Terminal: journal + refusal upstream; never open a DB pool here.
        raise PermissionError(f"DENIED ({denied.policy}): {denied.reason}")
    return {"status": "allowed-preview", "note": "non-destructive mutation stub (no real DB write)"}


async def run_file_read(payload: dict[str, Any]) -> dict[str, Any]:
    path = str(payload.get("path", ""))
    denied = check_path(path)
    if denied is not None:
        raise PermissionError(f"DENIED ({denied.policy}): {denied.reason}")
    # Semantic layer: run text through the engine too (prompt-injection beat).
    verdict = evaluate_text("read_file_sensitive", payload)
    if verdict.decision == PolicyDecision.DENY:
        raise PermissionError(f"DENIED ({verdict.policy}): {verdict.reason}")
    return {"status": "allowed-preview", "path": path, "content": "<synthetic file stub>"}


__all__ = [
    "EXEC_DB_MUTATION_SPEC",
    "READ_FILE_SENSITIVE_SPEC",
    "check_db_mutation",
    "check_path",
    "evaluate_text",
    "run_db_mutation",
    "run_file_read",
]
