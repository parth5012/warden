# LOG.md — Warden

## 2026-10-11 — re-verification round: harness bug + missing regression tests

**Status:** Done (22 passed, mypy clean, PR #1 merge=CLEAN at ba0c939)

User asked "have you tested everything?" — audit found two gaps, both closed:

1. **Real harness bug**: `/quit` at the `resume>` prompt was consumed as a decision value → demo graph routed to abort (silent deny). Root cause of confusing smoke-test output ("approved: False" where send was expected). Fix: exit commands at the resume prompt return False, thread stays parked. TDD: red test first.
2. **Missing regression tests** for the 3 CodeRabbit fixes from the previous round: added tests/test_cli_chat.py (4 tests: /quit, empty re-prompt, failed-resume re-prompt, re-park loop) + 6-case _redact parametrize in test_checkpoint.py.

Environment learnings (see LEARNINGS.md):
- pgserver `cleanup_mode='stop'` stops the server at process exit (atexit); data dir persists — CLI restart re-attaches. Docstring corrected.
- Passing `--pg` with a URI obtained from a throwaway `get_server` process races the atexit stop → use the CLI's own resolution.
- `tests` is a package (empty `__init__.py` since 4fd3ff0); mypy needs `from tests import cli_chat`, no mypy_path.

Verified: pytest 22 passed (12 checkpoint + 4 cli loop + 6 redact); mypy 0 errors;
CLI e2e: single-process park→approve→sent; two-process park→/quit→restart→approve→sent, approved: True.
Checks after push: CodeRabbit pass, GitGuardian pass, merge=CLEAN, not behind.

## 2026-10-11 — PR #1 filed + CodeRabbit review fixes

**Status:** Done (checks green, PR OPEN — not merged)

- OCR review + 7 fixes committed as `4fd3ff0`; PR #1 opened against main:
  https://github.com/parth5012/warden/pull/1 (linked to thread).
- CodeRabbit triggered via `@coderabbitai review` (auto-skip on OSS repo); 3 comments, ALL applied as `1ad4ce4`:
  1. `_redact` — mask complete URI userinfo (malformed `password` with `@` leaked suffix); urlsplit-based, query `@` untouched; quoted keyword passwords covered. Verified vs 6 cases.
  2. `_prompt_for_resume` empty input → `continue` (stay in prompt loop; returning let plain text take the invoke path on a parked thread).
  3. `_prompt_for_resume` failed resume (None) → re-prompt, don't treat as decision.
- Verified after fixes: pytest 12 passed, mypy 0 errors, redaction case-check.
- Checks: CodeRabbit pass, GitGuardian pass; mergeStateStatus CLEAN; not behind main.
- Babysit loop: stopped at green. PR intentionally NOT merged — `merge-pr` or human merge required.
- OCR config note: gateway model `agy/gemini-3.7-flash-medium` dead upstream; review ran with `--model auto/best-coding` (config backup `/tmp/opencode/ocr-config-backup.json`).

## 2026-10-11 — OCR review round 1 + fixes (pre-PR)

**Status:** Done (verification green)

### What changed
- OCR review (`session db2a663c-f08b-4a6c-bcd6-202c48e02798`, 13 files, 11 findings: 1 high, 6 medium, 4 low-discarded). Config fix required first: gateway model `agy/gemini-3.7-flash-medium` dead upstream (requests hang); added `auto/best-coding` to `~/.opencodereview/config.json` models list (backup at `/tmp/opencode/ocr-config-backup.json`) and ran with `--model auto/best-coding`. One core-review request failed HTTP 402 (partial coverage on `.gitignore/.python-version/pyproject` headers — findings for pyproject still produced).
- Fixes applied (all 7 non-low findings):
  1. `pyproject.toml` — declared direct deps imported by first-party code: `psycopg-pool`, `langchain-core`, `typing-extensions` (were transitive-only).
  2. `pyproject.toml` — unified dev deps: moved `pgserver` from `[dependency-groups]` into `[project.optional-dependencies].dev` (pip `.[dev]` now complete).
  3. `checkpoint.py get_state_history` — `aget_state_history` yields newest-first; added `history.reverse()` to honor "oldest first" docstring contract.
  4. `checkpoint.py resume` — log `resume_value_type` instead of raw resume payload (PII into log aggregation).
  5. `checkpoint.py _redact` — now covers keyword-DSN `password=...` form, not just URI form (invariant: never log conn string unredacted).
  6. `cli_chat.py _prompt_for_resume` — EOF/Ctrl-C safe (returns False → clean exit, was traceback); loops until graph no longer parked (re-park re-prompts instead of sending next input down the wrong path).
  7. `cli_chat.py _resume_and_render` — returns result so callers detect re-park; `/resume` command also re-prompts on re-park.
- Added `.gitignore`; removed `uv init` leftover `src/t3code_377f8a81/`.
- Test strengthened: history test now asserts non-decreasing steps (locks oldest-first contract).

### Verification
- `uv run pytest` → 12 passed (real Postgres).
- `uv run mypy src tests` → 0 errors.
- CLI: EOF at `resume>` exits cleanly (no traceback); park → approve → complete flow green.

### Skipped
- ocr-review: DONE (this round). pr/repo-quality-orchestrator/retro: run at PR filing (current iteration).

## 2026-10-11 — Checkpointing system (Phase 0/1 foundation)

**Status:** Done (verification green)

### What changed
- Project scaffold: `pyproject.toml` (uv, Python 3.11), `src/warden/` package, `tests/`.
- `src/warden/models.py` — `Action`/`Outcome` types, gate types, `CheckpointInfo` view type.
- `src/warden/checkpoint.py` — `CheckpointManager`, the deep module for checkpoint infra:
  - `create(conn_string)` async context manager owns `AsyncPostgresSaver` lifecycle (setup idempotent on every boot).
  - `health_check()` probes the connection (handles connection AND pool).
  - `get_state_info` / `get_state_history` — logged state inspection, **fail-closed**: return `Error("governance_unavailable")`, never raise (lock 4).
  - `resume(graph, config, value)` — logging wrapper around `graph.ainvoke(Command(resume=...))`, fail-closed.
  - Connection string redacted in all logs.
- `src/warden/demo_graph.py` — draft → `interrupt(approval)` → send/abort demo graph (park/resume proof).
- `tests/test_checkpoint.py` — 12 tests vs **real PostgreSQL** (pgserver, bundled, no root): idempotent setup, park/resume approve+deny, no duplicate output on resume, **manager-restart recovery**, history walk, fail-closed after close (state/history/resume), bad-connection startup failure.
- `tests/cli_chat.py` — reusable CLI chat harness: takes any compiled graph, `/state /history /new /resume /quit`, auto-prompts resume when rejoining a parked thread. Auto-starts bundled pgserver (`--pg` / `WARDEN_PG_URI` to override); server intentionally left running so restart-and-resume is demoable.
- `tests/conftest.py` — session-scoped real-PG fixture.

### Design decisions (grilling outcomes)
- CheckpointManager does **NOT** wrap `interrupt()` — interrupt lives inside graph nodes. (Shallow-wrapper rejection.)
- No "attach checkpointer to graph" helper — `builder.compile(checkpointer=...)` is enough.
- Depth earned by: connection lifecycle ownership + fail-closed + health check + redacted logging, not by pass-through wrappers.
- `resume()` is the one logging wrapper kept (explicit user requirement: cohesive import + logging at transitions).

### Verification
- `uv run pytest` → **12 passed** (real Postgres each run).
- `uv run mypy src tests` → **Success: no issues in 12 files** (strict mode).
- CLI crash-recovery smoke test: run 1 parks + quits while parked → run 2 (fresh process, `--thread crash-demo`) detects park, resumes with `approve` → "Email sent", `approved: True`.
- Skipped skills (not applicable): `ocr-review` (no UI), `pr` (no PR/commit requested — not committing without explicit ask), `repo-quality-orchestrator` (repo-wide run deferred to Phase 1 completion).

### Next
- Wire the HITL re-entry helper (`run_gated` in `warden/hitl/runner.py`) on top of this + AuditJournal write-ahead (lock 2/3).
