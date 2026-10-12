"""Graded policy evals: the current engine must score 100% on the golden set.

This is the CI-gated run. It does not test the engine's internals — that is
tests/test_policy_engine.py. It tests the engine's behavior against a curated,
canonical set of actions and seed policies, so a rule edit or threshold change
fails here if it changes the graded outcome.

v1 asserts:
  - verdict accuracy (all rows, hard gate)
  - fail-closed integrity (all fail_closed rows: escalate + unmatched at threshold)
  - L2 retrieval correctness (per row where expected_policy_id is set: the engine's
    nearest stored policy must equal expected_policy_id and the actual similarity must
    fall inside expected_similarity_band)
  - threshold behavior is informational in v1 (reported, not hard-asserted)

L1 rows are intentionally absent: L1 matches come from patterns, not the stored
corpus, so there is no winning stored policy id to assert. L1 coverage lives in
tests/test_policy_engine.py.
"""

from __future__ import annotations

import json

from tests.evals.harness import (
    ActionRow,
    CORPUS_PATH,
    ACTIONS_PATH,
    PolicyRow,
    build_engine_from_corpus,
    format_scorecard,
    grade_engine,
    assert_scorecard,
)


def _load_corpus() -> list[PolicyRow]:
    raw = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    return [
        PolicyRow(id=i["id"], category=i["category"], verdict=i["verdict"], text=i["text"], note=i["note"])
        for i in raw
    ]


def _load_actions() -> list[ActionRow]:
    raw = json.loads(ACTIONS_PATH.read_text(encoding="utf-8"))
    rows: list[ActionRow] = []
    for i in raw:
        band = i.get("expected_similarity_band")
        band_list: list[float] | None = list(band) if isinstance(band, list) else None
        rows.append(
            ActionRow(
                id=i["id"],
                name=i["name"],
                payload=i["payload"],
                kind=i["kind"],
                expected_verdict=i["expected_verdict"],
                expected_match=i["expected_match"],
                expected_policy_id=i.get("expected_policy_id"),
                expected_similarity_band=band_list,
                layer_hint=i["layer_hint"],
                note=i["note"],
            )
        )
    return rows


def test_policy_engine_graded_against_golden_set() -> None:
    corpus = _load_corpus()
    actions = _load_actions()
    engine = build_engine_from_corpus(corpus, threshold=0.8)
    sc = grade_engine(engine, actions, threshold=0.8)
    print(format_scorecard(sc, engine_label="L1L2PolicyEngine (HashEmbeddings + InMemoryPolicyStore)"))
    # v1 hard gate: verdict accuracy (all rows) + fail-closed integrity + L2 retrieval
    # correctness where expected_policy_id / expected_similarity_band are set.
    assert_scorecard(sc)
