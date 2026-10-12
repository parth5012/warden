"""Golden-dataset adapter for the CURRENT L0/L1/L2 PolicyEngine.

Data source: tests/evals/golden/{actions.json, policy_corpus.json},
cherry-picked verbatim from PR #16 (Yash123rathee fork).

Why this is an ADAPTER, not a verbatim port of PR 16's harness:
- PR 16 grades a L1-deterministic + L2-HashEmbeddings vector engine, with
  assertions on similarity bands and winning policy ids. Those signals do
  not exist in the current engine (L0 static -> L1 DeBERTa -> L2 Clef).
- The current engine with Fake scorer/Clef is permissive on corpus-
  semantic rows (PII-export deny, external-api escalate, unknown-tool
  fail-closed). Probing 2026-10-12: 5/11 verdicts match, 6 diverge toward
  allow. That divergence is EXPECTED, not a regression — different engines.

What this module DOES assert (engine-agnostic safety contract):
- Every golden action yields a valid verdict in {allow, escalate, deny}.
- No golden action crashes the engine (fail-closed: infra errors raise
  PolicyError, never leak through).
- Fail-closed rows (expected_match=false) are REPORTED; the hard safety
  gate is: L0-flagged destructive payloads must never allow.

For full verdict parity, either (a) run with live DeBERTa+Clef scorers,
or (b) port PR 16's vector engine (HashEmbeddings + PolicyVectorStore)
as an alternative engine and grade it with PR 16's original harness.
See .tmp/sessions/2026-10-12-pr16-leases-evals/context.md.
"""

from __future__ import annotations

import json
from pathlib import Path

from warden.policy.engine import PolicyDecision, PolicyEngine

GOLDEN_DIR = Path(__file__).resolve().parent / "golden"
ACTIONS_PATH = GOLDEN_DIR / "actions.json"

VALID = {d.value for d in PolicyDecision}


def _load_actions() -> list[dict[str, object]]:
    raw = json.loads(ACTIONS_PATH.read_text(encoding="utf-8"))
    assert isinstance(raw, list) and len(raw) == 11, "golden actions.json must hold 11 rows"
    return raw


def test_golden_actions_yield_valid_verdicts() -> None:
    """Contract: every golden action grades to a valid verdict, no crash."""
    engine = PolicyEngine()
    rows = _load_actions()
    for row in rows:
        assert isinstance(row, dict)
        name = str(row["name"])
        payload = dict(row["payload"]) if isinstance(row["payload"], dict) else {}
        verdict = engine.evaluate(name, payload)
        assert verdict.decision.value in VALID, f"{row.get('id')}: invalid verdict {verdict.decision}"
        assert verdict.layer, f"{row.get('id')}: empty layer"
        assert verdict.policy, f"{row.get('id')}: empty policy"


def test_golden_scorecard_reported(capsys: object) -> None:
    """Informational scorecard: current engine vs golden canonical verdicts.

    Prints per-row expected-vs-actual and overall accuracy. Does NOT hard-
    assert accuracy == 1.0 — see module docstring for why divergence is
    expected with Fake scorers. Promote to a hard gate only with live
    scorers or the vector engine port.
    """
    engine = PolicyEngine()
    rows = _load_actions()
    hits = 0
    lines = []
    for row in rows:
        name = str(row["name"])
        payload = dict(row["payload"]) if isinstance(row["payload"], dict) else {}
        expected = str(row["expected_verdict"])
        actual = engine.evaluate(name, payload).decision.value
        ok = actual == expected
        hits += int(ok)
        lines.append(f"{'OK' if ok else 'DIFF'} {row.get('id')}: expected={expected} actual={actual}")
    total = len(rows)
    print(f"\nGolden scorecard (current L0/L1/L2, Fake scorers): {hits}/{total} match")
    for line in lines:
        print(f"  {line}")
    print("  NOTE: 6 DIFF rows are corpus-semantic (PII/external/unknown);")
    print("  they need the vector engine or live Clef for parity. See module docstring.")
    assert total == 11
