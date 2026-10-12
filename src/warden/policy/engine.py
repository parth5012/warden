"""Policy evaluation for Aegis's guarded executor and preview tools.

Action objects use the asynchronous, rule-based executor contract. String
action names use the synchronous L0/L1/L2 evaluator used by upstream preview
tools; both paths fail closed and share the same decision enum.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Sequence, overload

from warden.models import Action, ActionKind
from warden.policy.layer_clef import (
    ClefScores,
    ClefUnavailable,
    FakeClefClient,
)
from warden.policy.layer_deberta import FakeInjectionScorer, InjectionScorer
from warden.policy.layers_static import action_text, find_static_violation

logger = logging.getLogger("warden.policy.engine")


class PolicyDecision(str, Enum):
    """Possible policy evaluation decisions."""

    ALLOW = "allow"
    ESCALATE = "escalate"
    DENY = "deny"


@dataclass(frozen=True)
class PolicyResult:
    """Outcome of rule-based evaluation for an executor Action."""

    decision: PolicyDecision
    policy_name: str | None
    reason: str


@dataclass(frozen=True)
class PolicyVerdict:
    """Outcome and evidence from the synchronous layered evaluator."""

    decision: PolicyDecision
    reason: str
    policy: str
    layer: str
    scores: dict[str, float]


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
        keyword in normalized
        for keyword in (
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

        for statement in sqlglot.parse(query, read="postgres"):
            if statement is not None and (
                isinstance(statement, (exp.Drop, exp.TruncateTable, exp.Alter))
                or list(statement.find_all(exp.Drop, exp.TruncateTable, exp.Alter))
            ):
                return True
    except Exception:
        if any(keyword in normalized for keyword in ("drop", "truncate", "alter")):
            return True
    return False


def _is_prohibited_sensitive_file(action: Action) -> bool:
    """Check if action targets an unauthorized sensitive file."""
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
            predicate=lambda action, ctx: _is_destructive_sql(action),
            description="Destructive SQL operations are strictly prohibited",
        ),
        PolicyRule(
            name="deny_unauthorized_sensitive_files",
            decision=PolicyDecision.DENY,
            action_names=("read_file_sensitive",),
            predicate=lambda action, ctx: _is_prohibited_sensitive_file(action),
            description="Unauthorized sensitive files and path traversal are prohibited",
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
            description="Database mutations and sensitive file reads require authorization",
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
    """Compatible policy seam for guarded actions and upstream tool previews.

    ``evaluate(Action, ctx)`` returns a coroutine yielding ``PolicyResult``;
    this is the stable GuardedExecutor interface. ``evaluate(name, payload)``
    synchronously runs the layered evaluator for preview-only tools. The
    layered path defaults to deterministic fakes for demos/tests; deployments
    must inject configured scorer and Clef adapters explicitly.
    """

    def __init__(
        self,
        rules: Sequence[PolicyRule] | None = None,
        default_decision: PolicyDecision = PolicyDecision.DENY,
        is_available: bool = True,
        *,
        deny_threshold: float = 0.85,
        clean_threshold: float = 0.20,
        scorer: InjectionScorer | None = None,
        clef: Any | None = None,
    ) -> None:
        self._rules = list(rules) if rules is not None else get_seed_policies()
        self._default_decision = default_decision
        self._is_available = is_available
        self._deny_threshold = deny_threshold
        self._clean_threshold = clean_threshold
        self._scorer = scorer or FakeInjectionScorer()
        self._clef = clef or FakeClefClient()

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

    @overload
    def evaluate(self, action: Action, ctx: Any = None) -> Any: ...

    @overload
    def evaluate(
        self, action: str, ctx: dict[str, Any], role: str = "operator"
    ) -> PolicyVerdict: ...

    def evaluate(
        self,
        action: Action | str,
        ctx: Any = None,
        role: str = "operator",
    ) -> Any:
        if isinstance(action, Action):
            return self._evaluate_action(action, ctx)
        if isinstance(action, str):
            if not isinstance(ctx, dict):
                raise PolicyEvaluationError("Layered evaluation requires a payload dict")
            return self._evaluate_layers(action, ctx, role)
        if ctx is None:
            raise PolicyEvaluationError(
                f"Expected Action instance, got {type(action).__name__}"
            )
        raise PolicyEvaluationError(
            f"Expected Action or action name, got {type(action).__name__}"
        )

    async def _evaluate_action(self, action: Action, ctx: Any = None) -> PolicyResult:
        """Evaluate an executor Action against deterministic policy rules."""
        if not self._is_available:
            raise PolicyUnavailableError("Policy engine is unavailable")
        self._validate_action(action)

        static_hit = find_static_violation(action_text(action.name, action.payload))
        if static_hit is not None:
            return PolicyResult(
                decision=PolicyDecision.DENY,
                policy_name=static_hit.replace("-", "_"),
                reason=f"Static policy matched: {static_hit}",
            )

        for rule in self._rules:
            if not isinstance(rule.decision, PolicyDecision):
                raise PolicyEvaluationError(
                    f"Invalid decision value {rule.decision!r} in rule '{rule.name}'"
                )
            if rule.action_kinds and action.kind not in rule.action_kinds:
                continue
            if rule.action_names and action.name not in rule.action_names:
                continue
            if rule.predicate is not None:
                try:
                    if not rule.predicate(action, ctx):
                        continue
                except Exception as exc:
                    raise PolicyEvaluationError(
                        f"Policy rule '{rule.name}' evaluator raised error: {exc}"
                    ) from exc
            elif not rule.action_names:
                continue

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

    def _evaluate_layers(
        self, action_name: str, payload: dict[str, Any], role: str
    ) -> PolicyVerdict:
        if not self._is_available:
            raise PolicyUnavailableError("Policy engine is unavailable")
        text = action_text(action_name, payload)
        if (policy_id := find_static_violation(text)) is not None:
            return PolicyVerdict(
                decision=PolicyDecision.DENY,
                reason=f"static rule matched: {policy_id}",
                policy=policy_id,
                layer="L0-static",
                scores={},
            )

        try:
            injection = self._scorer.score(text)
        except Exception as exc:
            raise PolicyError(f"L1 deberta unavailable: {exc}") from exc
        if not 0.0 <= injection.score <= 1.0:
            raise PolicyError("L1 scorer returned an invalid risk score")
        if injection.score >= self._deny_threshold:
            return PolicyVerdict(
                decision=PolicyDecision.DENY,
                reason=f"prompt injection p={injection.score:.2f}",
                policy="prompt-injection",
                layer="L1-deberta",
                scores={"injection": injection.score},
            )
        if action_name in {"send_email", "restart_service"}:
            policy = (
                "POL_EGRESS_EXTERNAL_MSG"
                if action_name == "send_email"
                else "POL_INFRA_MUTATION"
            )
            return PolicyVerdict(
                decision=PolicyDecision.ESCALATE,
                reason="Explicit tool policy requires human approval",
                policy=policy,
                layer="L1-deberta",
                scores={"injection": injection.score},
            )

        try:
            scores: ClefScores = self._clef.judge(
                state=text,
                tool=action_name,
                args=str(payload.get("args", payload)),
                role=role,
            )
        except ClefUnavailable as exc:
            raise PolicyError(f"L2 clef unavailable: {exc}") from exc
        risk_scores = (
            scores.injection,
            scores.privilege_creep,
            scores.side_effect,
        )
        if any(not 0.0 <= score <= 1.0 for score in risk_scores):
            raise PolicyError("L2 evaluator returned an invalid risk score")
        worst = max(risk_scores)
        merged = {
            "l1_injection": injection.score,
            "clef_injection": scores.injection,
            "privilege_creep": scores.privilege_creep,
            "side_effect": scores.side_effect,
        }
        if worst >= self._deny_threshold:
            return PolicyVerdict(
                decision=PolicyDecision.DENY,
                reason=f"clef risk p={worst:.2f} ({scores.model})",
                policy="clef-risk",
                layer="L2-clef",
                scores=merged,
            )
        if worst <= self._clean_threshold and injection.score <= self._clean_threshold:
            return PolicyVerdict(
                decision=PolicyDecision.ALLOW,
                reason="L1 clean + Clef clean",
                policy="default-allow",
                layer="L2-clef",
                scores=merged,
            )
        return PolicyVerdict(
            decision=PolicyDecision.ESCALATE,
            reason=f"uncertain risk p={worst:.2f} needs human",
            policy="uncertain-hitl",
            layer="L2-clef",
            scores=merged,
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
