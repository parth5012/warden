"""PolicyEngine for Aegis.

Centralized policy evaluation boundary. Evaluates proposed Action objects
against configured rules and returns deterministic PolicyResult decisions:
- ALLOW: Action is permitted to proceed to execution.
- ESCALATE: Action requires human approval before execution.
- DENY: Action is prohibited; terminal rejection that cannot be approved.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Sequence

from warden.models import Action, ActionKind

logger = logging.getLogger("warden.policy.engine")


class PolicyDecision(str, Enum):
    """Possible policy evaluation decisions."""

    ALLOW = "allow"
    ESCALATE = "escalate"
    DENY = "deny"


@dataclass(frozen=True)
class PolicyResult:
    """Outcome of policy evaluation for an Action."""

    decision: PolicyDecision
    policy_name: str | None
    reason: str


class PolicyError(Exception):
    """Base exception for policy subsystem errors."""


class PolicyEvaluationError(PolicyError):
    """Raised when policy evaluation fails or encounters malformed inputs."""


class PolicyUnavailableError(PolicyEvaluationError):
    """Raised when a required policy component or rule store is unavailable."""


@dataclass(frozen=True)
class PolicyRule:
    """A policy rule matching action properties."""

    name: str
    decision: PolicyDecision
    action_names: tuple[str, ...] = ()
    action_kinds: tuple[ActionKind, ...] = ()
    predicate: Callable[[Action, Any], bool] | None = None
    description: str = ""


def _is_destructive_sql(action: Action) -> bool:
    """Check if action is a destructive SQL operation."""
    if action.name in ("drop_table", "truncate_table", "drop_database"):
        return True
    if not isinstance(action.payload, dict):
        return False
    query = str(
        action.payload.get("query")
        or action.payload.get("sql")
        or action.payload.get("command")
        or ""
    ).strip()
    if not query:
        return False
    normalized = query.lower()
    if any(
        kw in normalized
        for kw in (
            "drop table",
            "truncate table",
            "drop database",
            "drop schema",
            "alter table",
            "alter database",
            "alter schema",
            "truncate ",
        )
    ):
        return True

    try:
        import sqlglot
        from sqlglot import exp

        stmts = sqlglot.parse(query, read="postgres")
        for stmt in stmts:
            if stmt is None:
                continue
            if isinstance(stmt, (exp.Drop, exp.TruncateTable, exp.Alter)):
                return True
            if list(stmt.find_all(exp.Drop, exp.TruncateTable, exp.Alter)):
                return True
    except Exception:
        if "drop" in normalized or "truncate" in normalized or "alter" in normalized:
            return True
    return False


def _is_prohibited_sensitive_file(action: Action) -> bool:
    """Check if action targets unauthorized sensitive files or attempts path traversal."""
    if not isinstance(action.payload, dict):
        return True
    path_val = action.payload.get("path") or action.payload.get("file_path")
    if not isinstance(path_val, str) or not path_val.strip():
        return True
    from warden.tools.filesystem import is_prohibited_sensitive_path

    return is_prohibited_sensitive_path(path_val)


def get_seed_policies() -> list[PolicyRule]:
    """Default seed policy rules established in architecture."""
    return [
        PolicyRule(
            name="no_destructive_sql",
            decision=PolicyDecision.DENY,
            action_names=(),
            predicate=lambda action, ctx: _is_destructive_sql(action),
            description="Terminal policy: destructive SQL operations (DROP, TRUNCATE, ALTER) are strictly prohibited",
        ),
        PolicyRule(
            name="deny_unauthorized_sensitive_files",
            decision=PolicyDecision.DENY,
            action_names=("read_file_sensitive",),
            predicate=lambda action, ctx: _is_prohibited_sensitive_file(action),
            description="Terminal policy: unauthorized sensitive files and path traversal are strictly prohibited",
        ),
        PolicyRule(
            name="escalate_external_email",
            decision=PolicyDecision.ESCALATE,
            action_names=("send_email",),
            description="External communications require human authorization",
        ),
        PolicyRule(
            name="escalate_infrastructure_restart",
            decision=PolicyDecision.ESCALATE,
            action_names=("restart_service",),
            description="Infrastructure restarts require human authorization",
        ),
        PolicyRule(
            name="escalate_sensitive_operations",
            decision=PolicyDecision.ESCALATE,
            action_names=("exec_db_mutation", "read_file_sensitive"),
            description="Database mutations and sensitive file reads require human authorization",
        ),
        PolicyRule(
            name="allow_read_operations",
            decision=PolicyDecision.ALLOW,
            action_names=(
                "read_table",
                "query_table",
                "list_files",
                "get_status",
                "get_system_metrics",
                "read_service_logs",
                "query_db_readonly",
            ),
            description="Read-only operations allowed without manual review",
        ),
    ]


class PolicyEngine:
    """Evaluates an Action and returns ALLOW, ESCALATE, or DENY.

    Invariants:
    - Fails closed: errors/unavailability raise PolicyEvaluationError.
    - Deterministic evaluation: rules evaluated in fixed order.
    - Default deny: unmatched actions return DENY by default.
    - Never silently falls back to ALLOW.
    """

    def __init__(
        self,
        rules: Sequence[PolicyRule] | None = None,
        default_decision: PolicyDecision = PolicyDecision.DENY,
        is_available: bool = True,
    ) -> None:
        self._rules: list[PolicyRule] = (
            list(rules) if rules is not None else get_seed_policies()
        )
        self._default_decision = default_decision
        self._is_available = is_available

    @classmethod
    def with_seed_policies(cls) -> PolicyEngine:
        return cls(rules=get_seed_policies())

    @property
    def is_available(self) -> bool:
        return self._is_available

    def set_available(self, available: bool) -> None:
        self._is_available = available

    def add_rule(self, rule: PolicyRule) -> None:
        if not isinstance(rule, PolicyRule):
            raise PolicyEvaluationError(
                f"Expected PolicyRule, got {type(rule).__name__}"
            )
        self._rules.append(rule)

    async def evaluate(self, action: Action, ctx: Any = None) -> PolicyResult:
        """Evaluate action against policies.

        Raises PolicyEvaluationError / PolicyUnavailableError on failure.
        Returns PolicyResult with decision, policy_name, and reason.
        """
        if not self._is_available:
            raise PolicyUnavailableError("Policy engine is unavailable")

        self._validate_action(action)

        # Evaluate rules in deterministic sequence
        for rule in self._rules:
            if not isinstance(rule.decision, PolicyDecision):
                raise PolicyEvaluationError(
                    f"Invalid decision value {rule.decision!r} in rule '{rule.name}'"
                )

            # Check action kinds filter if specified
            if rule.action_kinds and action.kind not in rule.action_kinds:
                continue

            # Check action names filter if specified
            if rule.action_names and action.name not in rule.action_names:
                continue

            # Check predicate if specified
            if rule.predicate is not None:
                try:
                    pred_res = rule.predicate(action, ctx)
                except Exception as exc:
                    raise PolicyEvaluationError(
                        f"Policy rule '{rule.name}' evaluator raised error: {exc}"
                    ) from exc

                if not pred_res:
                    continue
            elif not rule.action_names:
                continue

            # Rule matched!
            logger.info(
                "policy.rule_matched",
                extra={
                    "rule": rule.name,
                    "decision": rule.decision.value,
                    "action_id": action.id,
                },
            )
            return PolicyResult(
                decision=rule.decision,
                policy_name=rule.name,
                reason=rule.description or f"Matched policy rule: {rule.name}",
            )

        # No rule matched -> Default decision (default DENY)
        if not isinstance(self._default_decision, PolicyDecision):
            raise PolicyEvaluationError(
                f"Invalid default decision: {self._default_decision!r}"
            )

        logger.info(
            "policy.unmatched_default",
            extra={
                "decision": self._default_decision.value,
                "action_id": action.id,
            },
        )
        return PolicyResult(
            decision=self._default_decision,
            policy_name=None,
            reason="Denied by default: no policy rule explicitly permitted or escalated action",
        )

    def _validate_action(self, action: Any) -> None:
        if not isinstance(action, Action):
            raise PolicyEvaluationError(
                f"Expected Action instance, got {type(action).__name__}"
            )
        if not isinstance(action.id, str) or not action.id.strip():
            raise PolicyEvaluationError("Action.id must be a non-empty string")
        if not isinstance(action.name, str) or not action.name.strip():
            raise PolicyEvaluationError("Action.name must be a non-empty string")
        if not isinstance(action.kind, ActionKind):
            raise PolicyEvaluationError(
                f"Action.kind must be an ActionKind, got {getattr(action, 'kind', None)!r}"
            )
        if not isinstance(action.payload, dict):
            raise PolicyEvaluationError("Action.payload must be a dict")
        if not isinstance(action.run_id, str) or not action.run_id.strip():
            raise PolicyEvaluationError("Action.run_id must be a non-empty string")
        if not isinstance(action.thread_id, str) or not action.thread_id.strip():
            raise PolicyEvaluationError("Action.thread_id must be a non-empty string")
