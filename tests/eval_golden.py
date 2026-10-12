"""Evaluation harness for the WARDEN golden dataset.

Loads tests/fixtures/golden_cases.jsonl and evaluates each case against the
ACTUAL implemented PolicyEngine (L0 seed rules) and GuardedExecutor — the
governance components themselves are NOT mocked.

What is real vs stubbed vs unavailable here
-------------------------------------------
- PolicyEngine (L0): REAL implementation with REAL seed policies.
- GuardedExecutor: REAL implementation with the real InMemoryAuditJournal.
- Sandbox: NOT IMPLEMENTED in this repository (docs/SECURITY_MODEL.md marks the
  subprocess adapter as PROPOSED). A TrackingSandboxStub is injected purely to
  OBSERVE whether the executor ever dispatches a denied tool call to the
  sandbox boundary — it measures containment violations, and is clearly labeled
  as a stub, not a sandbox.
- L1 (DeBERTa prompt-injection classifier): NOT implemented in the repo.
  Cases whose *primary* target is L1 are counted and excluded from scored
  metrics (reported as unavailable, never faked).
- L2 (Granite reasoning): NOT implemented. Same treatment as L1.
  Cases marked "L0->L2" are evaluable today via their L0 leg and ARE scored.

Run standalone:
    uv run python -m tests.eval_golden

Exit code 0 iff zero misclassifications, zero containment violations, and a
perfect full-stack pass rate.
"""

from __future__ import annotations

import asyncio
import json
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from warden.executor import ExecutionContext, GuardedExecutor
from warden.journal import InMemoryAuditJournal
from warden.models import Action, ActionKind
from warden.policy.engine import PolicyDecision, PolicyEngine

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATASET = REPO_ROOT / "tests" / "fixtures" / "golden_cases.jsonl"

OUTCOME_ALIASES: dict[str, PolicyDecision] = {d.value: d for d in PolicyDecision}

REQUIRED_FIELDS = (
    "id",
    "name",
    "payload",
    "expected_outcome",
    "expected_policy",
    "target_layer",
    "category",
    "edge_case",
    "description",
)


# ---------------------------------------------------------------------------
# Tracking sandbox stub (NOT a real sandbox)
# ---------------------------------------------------------------------------

@dataclass
class TrackingSandboxStub:
    """Observable stub: records every dispatch attempt so the harness can
    assert that policy-denied actions never reach the sandbox boundary."""

    calls: list[str] = field(default_factory=list)

    def has_tool(self, name: str) -> bool:
        return True  # simulate availability so any deny-gap becomes observable

    def run(self, action: Action) -> str:
        self.calls.append(action.name)
        return f"stub-ran:{action.name}"


# ---------------------------------------------------------------------------
# Case loading (with independent re-validation of the fixture file)
# ---------------------------------------------------------------------------

def load_cases(path: Path) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines()):
        if not raw.strip():
            continue
        try:
            rec = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"golden_cases.jsonl line {lineno + 1}: invalid JSON ({exc})"
            ) from exc
        missing = [key for key in REQUIRED_FIELDS if key not in rec]
        if missing:
            raise ValueError(
                f"golden_cases.jsonl line {lineno + 1} "
                f"(id={rec.get('id', '?')}): missing field(s) {missing}"
            )
        if rec["id"] in seen_ids:
            raise ValueError(
                f"golden_cases.jsonl line {lineno + 1}: duplicate id {rec['id']}"
            )
        seen_ids.add(rec["id"])
        cases.append(rec)
    return cases


def build_action(case: dict[str, Any], idx: int) -> Action:
    return Action(
        id=f"golden-{case['id']}-{idx}",
        kind=ActionKind(case.get("kind", "tool")),
        name=str(case["name"]),
        payload=dict(case["payload"]),
        run_id=f"golden-run-{case['id']}",
        thread_id=f"golden-thread-{case['id']}",
    )


# ---------------------------------------------------------------------------
# Metrics container
# ---------------------------------------------------------------------------

@dataclass
class EvalReport:
    total: int = 0
    evaluated: int = 0
    skipped_unavailable: list[dict[str, str]] = field(default_factory=list)
    correct: int = 0
    confusion: Counter[str] = field(default_factory=Counter)
    per_category_correct: Counter[str] = field(default_factory=Counter)
    per_category_total: Counter[str] = field(default_factory=Counter)
    false_allow: int = 0     # prohibited classified as allow
    false_deny: int = 0      # safe classified as deny
    incorrect_escalation: int = 0  # safe/prohibited classified as escalate
    executor_stack_pass: int = 0
    executor_stack_total: int = 0
    executor_stack_fail: list[dict[str, str]] = field(default_factory=list)
    containment_violations: list[dict[str, str]] = field(default_factory=list)
    policy_name_correct: int = 0
    policy_name_total: int = 0
    misclassified: list[dict[str, str]] = field(default_factory=list)

    @property
    def accuracy(self) -> float:
        return self.correct / self.evaluated if self.evaluated else 0.0

    def per_outcome(self) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for decision in ("allow", "escalate", "deny"):
            tp = self.confusion.get(f"{decision}|{decision}", 0)
            fp = sum(
                c for k, c in self.confusion.items()
                if k.endswith(f"|{decision}") and k != f"{decision}|{decision}"
            )
            fn = sum(
                c for k, c in self.confusion.items()
                if k.startswith(f"{decision}|") and k != f"{decision}|{decision}"
            )
            precision = tp / (tp + fp) if (tp + fp) else None
            recall = tp / (tp + fn) if (tp + fn) else None
            f1 = (
                (2 * precision * recall) / (precision + recall)
                if precision is not None and recall is not None and (precision + recall)
                else None
            )
            out[decision] = {"support": tp + fn, "precision": precision,
                             "recall": recall, "f1": f1}
        return out


# ---------------------------------------------------------------------------
# Evaluation core
# ---------------------------------------------------------------------------

def evaluate(dataset_path: Path | None = None) -> EvalReport:
    """Run the full harness synchronously (single event loop, no nested run)."""
    report = EvalReport()
    cases = load_cases(dataset_path or DEFAULT_DATASET)
    report.total = len(cases)

    engine = PolicyEngine.with_seed_policies()
    stub = TrackingSandboxStub()

    async def run_all() -> None:
        for idx, case in enumerate(cases):
            cid = case["id"]
            layer = case["target_layer"]

            # Pure L1 or pure L2 is not implemented in the repo -> unscored.
            if layer in ("L1", "L2"):
                report.skipped_unavailable.append(
                    {"id": cid, "reason": f"target_layer {layer} not implemented"}
                )
                continue

            expected = OUTCOME_ALIASES[case["expected_outcome"]]
            action = build_action(case, idx)

            # --- L0 policy classification (REAL PolicyEngine) ---
            result = await engine.evaluate(action)
            actual = result.decision

            # Policy-name check where the dataset expects one.
            ep = case.get("expected_policy")
            if ep:
                report.policy_name_total += 1
                if actual == expected and result.policy_name == ep:
                    report.policy_name_correct += 1

            report.evaluated += 1
            cat = case["category"]
            report.confusion[f"{expected.value}|{actual.value}"] += 1
            report.per_category_total[cat] += 1
            if expected == actual:
                report.correct += 1
                report.per_category_correct[cat] += 1
            else:
                report.misclassified.append(
                    {"id": cid, "expected": expected.value, "actual": actual.value,
                     "policy": result.policy_name or "<default-deny>"}
                )
            if cat == "prohibited" and actual == PolicyDecision.ALLOW:
                report.false_allow += 1
            if cat == "safe" and actual == PolicyDecision.DENY:
                report.false_deny += 1
            if cat in ("safe", "prohibited") and actual == PolicyDecision.ESCALATE:
                report.incorrect_escalation += 1

            # --- Full GuardedExecutor stack for resolvable actions ---
            if case.get("handler_registered") and case.get("kind", "tool") == "tool":
                report.executor_stack_total += 1
                executor = GuardedExecutor(
                    journal=InMemoryAuditJournal(),
                    policy=engine,
                    sandbox=stub,
                )
                executor.register_handler(case["name"], lambda a: f"ok:{a.name}")
                outcome = await executor.execute(
                    action,
                    ExecutionContext(run_id=action.run_id, thread_id=action.thread_id),
                )
                expected_cls: type
                if actual == PolicyDecision.ESCALATE:
                    expected_cls = type("Pending", (), {})
                    from warden.models import Pending as pending_cls
                    expected_cls = pending_cls
                elif actual == PolicyDecision.ALLOW:
                    from warden.models import Allowed as allowed_cls
                    expected_cls = allowed_cls
                else:
                    from warden.models import Denied as denied_cls
                    expected_cls = denied_cls

                if isinstance(outcome, expected_cls):
                    report.executor_stack_pass += 1
                else:
                    report.executor_stack_fail.append(
                        {"id": cid,
                         "reason": f"expected {expected_cls.__name__}, "
                                   f"got {type(outcome).__name__}"}
                    )

            # --- Containment: denied actions must never reach the sandbox ---
            if case["expected_outcome"] == "deny" and stub.calls:
                for tool_name in stub.calls:
                    report.containment_violations.append(
                        {"id": cid,
                         "reason": f"tool '{tool_name}' dispatched despite deny"}
                    )
                stub.calls.clear()

    asyncio.run(run_all())
    return report


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def format_report(report: EvalReport) -> str:
    lines: list[str] = []
    lines.append("WARDEN Golden Dataset Evaluation (L0 = real PolicyEngine + "
                 "GuardedExecutor; sandbox = tracking stub, not a real sandbox)")
    lines.append("=" * 74)
    lines.append(f"total cases:           {report.total}")
    lines.append(f"evaluated:             {report.evaluated}")
    if report.skipped_unavailable:
        lines.append("skipped, layer unavailable:")
        for s in report.skipped_unavailable:
            lines.append(f"  - {s['id']}: {s['reason']}")
    lines.append(f"accuracy:              {report.accuracy:.3f} "
                 f"({report.correct}/{report.evaluated})")
    lines.append("")
    lines.append("Confusion matrix (expected|actual):")
    for key in sorted(report.confusion):
        lines.append(f"  {key}: {report.confusion[key]}")
    lines.append("")
    lines.append("Per-outcome precision / recall / F1:")
    for decision, m in report.per_outcome().items():
        p, r, f1 = m["precision"], m["recall"], m["f1"]
        p_s = "n/a" if p is None else f"{p:.3f}"
        r_s = "n/a" if r is None else f"{r:.3f}"
        f1_s = "n/a" if f1 is None else f"{f1:.3f}"
        lines.append(f"  {decision:<9} support={m['support']}  "
                     f"precision={p_s}  recall={r_s}  F1={f1_s}")
    lines.append("")
    lines.append(f"false-allow (prohibited):   {report.false_allow}")
    lines.append(f"false-deny (safe):          {report.false_deny}")
    lines.append(f"incorrect escalation:       {report.incorrect_escalation}")
    lines.append(f"policy-name accuracy:       {report.policy_name_correct}/"
                 f"{report.policy_name_total}")
    if report.per_category_total:
        lines.append("per-category:")
        for cat in sorted(report.per_category_total):
            got = report.per_category_correct[cat]
            tot = report.per_category_total[cat]
            lines.append(f"  {cat:<10} {got}/{tot}")
    lines.append(f"executor full-stack:        "
                 f"{report.executor_stack_pass}/{report.executor_stack_total} pass")
    for f in report.executor_stack_fail:
        lines.append(f"  - {f['id']}: {f['reason']}")
    if report.misclassified:
        lines.append("misclassified:")
        for m in report.misclassified:
            lines.append(f"  - {m['id']}: expected {m['expected']}, "
                         f"got {m['actual']} ({m['policy']})")
    if report.containment_violations:
        lines.append("CONTAINMENT VIOLATIONS:")
        for v in report.containment_violations:
            lines.append(f"  - {v['id']}: {v['reason']}")
    return "\n".join(lines)


def main() -> int:
    report = evaluate()
    print(format_report(report))
    ok = (
        report.misclassified == []
        and report.executor_stack_fail == []
        and report.containment_violations == []
        and report.accuracy == 1.0
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
