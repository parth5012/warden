# Warden — Policy Engine Evals Suite

> **Goal:** a golden dataset + grading harness that can score *any* policy engine against a fixed set of actions, and that can be re-run when the engine changes (HashEmbeddings → real embedder, in-memory store → pgvector, rule edits, threshold changes).
>
> This is separate from `tests/test_policy_engine.py`, which tests the *contract and internals* of the current engine. The evals test the *behavior against canonical inputs* — the thing you'd want before demoing the PG grader or before a policy edit ships.

## What this suite is for

1. **Regression grading.** After any change to the policy layer (engine, embedder, store, threshold, rule corpus), run the evals and compare the scorecard to the last known-good one.
2. **Engine comparison.** The harness is engine-agnostic: point it at the current `L1L2PolicyEngine`, a future pgvector-backed engine, or a stub, and it grades the same way.
3. **Demo readiness.** Before the PG demo, run the evals to confirm the engine behaves on a curated, realistic set of actions — not just the internally-authored unit cases.

## What this suite is NOT for

- It is not a replacement for the unit/integration tests in `tests/test_policy_engine.py`, `tests/test_multi_agent.py`, etc. Those still own the contract, lock compliance, seam drop-in, and real-PG multi-agent behavior.
- It is not yet an LLM-judge or a semantic-truth validator. With the current `HashEmbeddings`, similarity is token-hash bag-of-words, so the golden dataset is designed around shared vocabulary on purpose. Similarity bands are assertions about *the engine's behavior with the current embedder*, not claims about true semantic similarity. When a real embedder is wired, re-derive the bands (see "maintaining the dataset").

## Scope (v1)

- **Tool actions only** (`kind=tool`). LLM actions can be added later; the L1/L2 text path treats them the same today, and the seam path is where LLM actions diverge (dispatch vs telemetry).
- **Both layers.** The dataset exercises:
  - L2 matched verdicts (semantic retrieval picks a stored policy).
  - L2 fail-closed (below threshold, empty store, invalid stored verdict).
  - L1 dominance is tested in the unit suite; the graded golden set is intentionally L2-only where retrieval is the asserted signal.
  - L1 rows (destructive-sql denies, risky-tool escalates) are covered by the unit tests and are intentionally absent from this graded set.
- **The canonical verdict is always one of `allow`, `escalate`, `deny`** — the seam's three verdict strings. "Human deny" of a gate is a downstream HITL outcome, not a policy verdict; the evals do not model that.

## Dataset layout

```
tests/evals/
  golden/
    policy_corpus.json   # the seed policy rows the engine is evaluated against
    actions.json         # the action rows, each with a canonical verdict + expectations
  harness.py             # loads both, runs one or more engines, grades them
  run.py                 # thin CLI so you can run it outside pytest if you want
```

### `golden/policy_corpus.json`

Array of policy rows. Each row:

```json
{
  "id": "p-<name>",
  "category": "<destructive_sql | risky_tool | data_export | read_only | unknown | invalid>",
  "verdict": "allow" | "escalate" | "deny",
  "text": "<seed text that the engine will embed and search against>",
  "note": "<why this row exists; what it should win on>"
}
```

Categories are labels for the scorecard, not engine input. The engine only sees `id`, `verdict`, `text`.

### `golden/actions.json`

Array of action rows. Each row:

```json
{
  "id": "a-<name>",
  "name": "<action name>",
  "payload": {"<key>": "<value>", ...},
  "kind": "tool",
  "expected_verdict": "allow" | "escalate" | "deny",
  "expected_match": true | false,
  "expected_policy_id": "p-<name>" | null,
  "expected_similarity_band": [<low>, <high>] | null,
  "layer_hint": "l2_benign_allow" | "l2_deny" | "l2_allow" | "l2_escalate" | "fail_closed",
  "note": "<why this verdict is canonical; what would make it ambiguous>"
}
```

Fields:

- `expected_verdict` — the canonical seam verdict for this action against the golden corpus.
- `expected_match` — whether the engine should report `matched=True` (L2 match). Fail-closed cases are `matched=False`.
- `expected_policy_id` — which policy row should have won, if the winner is a stored L2 policy. `null` for fail-closed cases.
- `expected_similarity_band` — the similarity range a correct engine should land in for the winning L2 match, expressed as `[low, high]`. `null` when similarity is not the asserted signal (fail-closed cases). This is asserted against the current `HashEmbeddings`; see "maintaining the dataset."
- `layer_hint` — informational label for the scorecard that says which regime *should* decide this row. Useful for spotting regressions where the wrong regime takes over.
- `note` — human reasoning, including the ambiguity the dataset is deliberately testing.

## Grading rubric (v1)

For each engine under test, the harness computes:

| Metric | Definition |
|---|---|
| **Verdict accuracy** | Fraction of action rows where the engine's verdict equals `expected_verdict`. |
| **Match correctness** | Fraction of rows where `matched` equals `expected_match`. A row can have the right verdict but the wrong matchedness — this catches "right answer, wrong reason." |
| **L2 retrieval correctness** | For rows where `expected_policy_id` is non-null, fraction where the engine's winning policy id equals the expected one. This is the retrieval signal for matched L2 rows. |
| **Similarity-band adherence** | For rows where `expected_similarity_band` is non-null and the engine matched, fraction where the engine's similarity falls inside the band. Out-of-band similarities get flagged even if the verdict happened to be right. |
| **Per-layer verdict accuracy** | Same as verdict accuracy, broken down by `layer_hint`, so you can see whether one regime (e.g. L2 matched, fail-closed) regressed. |
| **Fail-closed integrity** | Of the rows that should be fail-closed (`expected_match=false` with `expected_verdict=escalate`), fraction that actually escalated rather than silently allowing. This is the most important safety number in the suite. |

The harness prints a scorecard and exits non-zero if any assertion in the graded run fails (so it can gate CI).

## What the v1 dataset deliberately stresses

- **Benign reads allow.** `list_orders`, `read_table`, `get_customer`, `search_kb` — the "nothing bad happened" baseline that must not be over-denied, with retrieval pointing at the right allow row.
- **L2 matched verdicts across domains.** Data export / PII deny, weekly-report export allow (a lookalike disambiguation against the PII row), external-api mutation escalate — with the closest stored row being the intended one, not just any row that shares a keyword.
- **Fail-closed edge cases.** Below-threshold similarity, and an invalid stored verdict (`maybe`) that must coerce to escalate and never passthrough — including a contrived case where the nearest stored neighbor is the garbage row on purpose.
- **Lookalike tension.** A pair of `db_export` rows where two stored policies are close in vocabulary but differ in verdict, so the dataset asks "which one wins?" and the note records the reasoning.

## What the v1 dataset does NOT assert

- L1 winner correctness. L1 matches come from patterns, not from the stored corpus, so there is no "winning stored policy id" for L1 rows. L1 coverage lives in `tests/test_policy_engine.py`.
- Hard `matched=True/False at 0.8` for L2 rows the current embedder cannot clear. The harness reports threshold behavior per row, but the v1 hard gate for retrieval rows is retrieval correctness, not whether the row clears the configured threshold. That distinction is what keeps the suite honest when the embedder's ceiling is below the threshold.

## Similarity bands in v1

- Similarity bands are the v1 hard assertion for L2 retrieval correctness. Each L2 row with `expected_policy_id` set also carries `expected_similarity_band`, derived from a real probe run against the final corpus/action texts (see `_probe_candidates.py`).
- The band is asserted as `[low, high]` around the observed similarity with a ±0.05 margin. A row is similarity-OK when the engine's actual similarity lands inside that band.
- Bands are human-reviewed before blessing. The probe prints a copy-pasteable snippet; I review it against the `note` reasoning and paste it into `actions.json` only after it looks right.
- When the embedder changes (HashEmbeddings → real provider, or dim changes), re-run the probe to derive fresh bands and re-review them. Do not blindly promote automated bands.

## Maintaining the dataset

- **When the embedder changes** (HashEmbeddings → a real provider, or dim changes): re-run `_probe_candidates.py` to derive fresh `expected_similarity_band` values for the L2 rows, then review them by hand against the `note` reasoning. Do not blindly accept automated bands — the band is a human-reviewed expectation, not a measurement you promote without looking.
- **When rules are added/edited:** add corresponding action rows (and possibly corpus rows) before shipping the change, so the change is graded against a dataset that includes its own domain.
- **When threshold changes:** update `expected_match` / `expected_similarity_band` for affected rows and re-grade. Threshold changes are exactly the kind of thing this suite exists to catch silently.
- **Don't over-fit to the embedder.** If an action row only passes because its text is a verbatim substring of a policy row's text, that's a weak row. Prefer rows where the engine must generalize across related vocabulary — within the limits of what `HashEmbeddings` can do.

## Running it

```bash
# Grade the default engine (the one harness.py is wired to) against the golden set
uv run pytest tests/evals/ -q

# CI-like: fail if any graded assertion is off
uv run pytest tests/evals/ -q --tb=short
```

The pytest run is the graded run. It exercises the current engine against the golden dataset and asserts the rubric above, so a regression fails the suite. For a non-grading "what does the engine do on this dataset" inspection, use `tests/evals/run.py` (or call `harness.py` directly) which prints the scorecard without asserting.

## Relation to the demo grader

The PG demo grader you mentioned ("prepare A GOLDEN DATASET FOR EVAL SUITE") is the eventual consumer of this dataset: a real-Postgres run where the engine under test is the pgvector-backed one, and the same `actions.json` + rubric are used to grade it. Until the pgvector store exists, the evals run against the in-memory `HashEmbeddings` store, which is the same contract (`PolicyVectorStore.search`) the pgvector adapter will satisfy. That is the point of the `PolicyVectorStore` protocol — the evals don't care which adapter is behind it.
