# LOG.md — Warden

# LOG.md — Warden

## 2026-10-13 — Leases/grants repair: canonical agent tools + statement fallback + leases deprecation

**Status:** Done (484 passed, 8 skipped full suite; mypy strict clean on 6 touched files; uncommitted)

Grill locks (5/5): (1) deprecate /leases UI, grants-only — banner + docstring, routes left intact; (2) canonicalize agents to registry names; (3) canonical sql key with statement fallback; (4) keep legacy no-store chat approvals (no app/chat.py change); (5) minimal surgical scope.

Why: "leases and human grants are not working" traced to three app-layer breaks, not the kernel (e2e grants green throughout): (a) DBAgent proposed unregistered `sql_query`/`sql_schema_migration` with `statement` payloads and CodeAgent proposed unregistered `run_shell` — every such action ended `Error(missing handler)` even with a covering grant; (b) `ScopeRule` table-match + `derive_scope_from_payload` + `find_scoped_escalation` read only `payload[sql]`, so legacy `statement` payloads never matched grants and inbox-upgrade derived empty (over-broad) constraints; (c) `/leases` renders a demo-only store never consulted by `GuardedExecutor` (DECISIONS.md #3 dropped leases), presenting fake enforceability.

What changed:
- `src/warden/agent_engine.py`: DBAgent drop/migration → `exec_db_mutation` + `sql`; readonly → `query_db_readonly` + `query` (plain SELECT on demo table `service_status`); CodeAgent shadow → `exec_shell` + `rm -rf /etc/shadow` (matches L0 `no-destructive-shell`, making the reply's Terminal-Deny claim true — `rm -f` fell through L0 into missing-handler Error).
- `src/warden/grants.py`, `app/grants.py`, `src/warden/policy/layers_static.py`: `statement` fallback alongside canonical `sql`.
- `app/leases.py` + `app/templates/leases.html`: deprecation banner pointing to `/grants-view`.
- `tests/test_grants.py`: 5 regression tests (statement fallback, DBAgent canonical, DBAgent readonly shape, CodeAgent canonical, derive statement).

Verified live: readonly → Allowed end-to-end, CASCADE drop → Denied, shadow rm → Denied (was: Error/Error/Error).
Code review (2 axes): Standards — no hard violations; Duplicated-Code note (identical sql/statement fallback in kernel + app layer; extract `canonical_sql()` in `layers_static` when a third site appears). Spec — all 5 locks met; no scope creep.

Known gaps left intentionally (minimal scope; chat approvals untouched per lock 4):
- `exec_shell` has no registered handler (`register_tools` omits it) — scoped-shell allow/escalate-approve still ends `Error(missing handler)` in chat path. Needs sandbox-wired registration (architecture work, not a rename).
- OpsAssistant readonly stages `{"sql": SELECT...}` but registered `database.query_db_readonly` requires `query` — same key split, same Error at handler. Fix together with exec_shell registration.
- DBAgent CASCADE demo payload is terminal-deny by design — grants correctly never apply there; use scoped `DROP TABLE staging_imports;` to demo the grant path.
- `query` vs `sql` key split across handlers/golden (`query`) vs specs/OpsAssistant (`sql`) — unify to one canonical key with a shared `canonical_sql()` helper.
- `ocr-review` skipped (no UI rendering changed — banner markup only, verified via template read).

## 2026-10-12 — User-Granted Temporary Permissions ("Grants") Handover (Map #24)

**Status:** Done (458 passed, 6 skipped full suite; 0 mypy errors across 83 files, merged into main via PR #40)

Why: Replace supervisor-minted custody leases with user-minted, task-scoped, time-bound capability grants. Allows operators to pre-authorize or inbox-upgrade inherently risky operations for a task thread, auto-allowing covered `escalate` actions without human interruption, while maintaining Lock 5 terminal denials.

What changed:
- **Grant-01 (#26)**: Removed untracked PR-16 custody lease files (`src/warden/leases.py`, `tests/test_leases.py`) with zero remaining references. Preserved golden evals dataset in `tests/evals/` and registered grants specification. (Sub-PR #32)
- **Grant-02 (#25)**: Reclassified parseable, bounded destructive intent (`scoped-ddl-drop-table`, `scoped-fs-batch-delete`) from terminal `deny` to grantable `escalate`. Preserved Lock 5 terminal deny for unbounded/unparseable actions (`DROP DATABASE`, multi-statement DDL, `CASCADE`, unconfined `rm -rf /`, `/etc/shadow`, traversal `..`). (Sub-PR #34)
- **Grant-03 (#31)**: Built pure kernel module `src/warden/grants.py` containing `Grant`, `ScopeRule`, `GrantsStore` protocol, and `InMemoryGrantsStore` adapter with clock injection, exact-plus-prefix matching, multi-target validation, and path traversal defense. (Sub-PR #35)
- **Grant-04 (#30)**: Wired live covering grant lookup into `GuardedExecutor.execute()` on the escalation path, consuming uses and emitting `grant_consumed` events without parking. Maintained strict terminal deny invariant on deny path. Added grant event kinds to `EventKind`. (Sub-PR #36)
- **Grant-05 (#29)**: Implemented `app/grants.py` with `POST /grants`, `GET /grants`, and `POST /grants/{id}/revoke` endpoints (range validation 5..240m TTL, 1..50 uses, 404/409 error handling). Added inbox upgrade ("Grant Rest of Task") in `app/chat.py` and task form upfront grant block in `chat.html`. (Sub-PR #37)
- **Grant-06 (#27)**: Added grant audit kinds to search filters and seed datasets in `backend/api/audit.py` and `app/audit.py`. Updated decision-graph projection in `backend/api/runs.py` to preserve causal ordering, and rendered structured timeline events in `frontend/templates/run_detail.html`. (Sub-PR #38)
- **Grant-07 (#28)**: Added end-to-end integration proof `tests/test_e2e_grants.py`. Updated domain glossary in `CONTEXT.md`, added Decision 3 to `DECISIONS.md`, and updated demo flow in `ROADMAP.md`. (Sub-PR #39)
- **Merged PR #40**: Landed User-Granted Temporary Permissions into `main` (`4335c43`).

Demo Script:
1. **Upfront Task Grant**:
   - Open Chat or POST `/chat/message` with `attach_grant=1`, `grant_tool=*`, `grant_ttl=30`, `grant_uses=5`.
   - Run task with `batch_delete_files` on `/workspace/tmp/` followed by `DROP TABLE staging_imports;`.
   - Both actions auto-allow with zero human interruption; WAL logs `grant_consumed` (uses left: 4 -> 3).
2. **Revocation**:
   - Call `POST /grants/{id}/revoke`.
   - Next destructive action (`DROP TABLE staging_imports;`) immediately parks at interception gate (`gate_requested`).
3. **Inbox Upgrade ("Grant Rest of Task")**:
   - On parked gate in chat stream, operator clicks `⚡ Grant Rest of Task`.
   - Action payload derives scoped constraint; grant is issued and parked action executes to `Allowed` (1 use consumed).
   - Subsequent calls on the same thread auto-allow under the grant.
4. **Terminal Deny Security Guard**:
   - Submitting unbounded `DROP DATABASE prod;` or `rm -rf /` terminally denies (`no-destructive-sql` / `no-destructive-shell`). Lock 5 strictly upheld; grant is never consulted.
5. **Audit Explorer & Timeline**:
   - `/audit?kind=grant_consumed` displays consumption records with true approver attribution (Lock 8).
   - `/runs/{thread_id}` and `/api/runs/{thread_id}/graph` show full causal sequence: `grant_issued -> action_requested -> grant_consumed -> action_completed -> gate_requested`.

Verification:
- Full test suite: 458 passed, 6 skipped across unit, integration, and E2E suites.
- Static typing: Mypy strict mode clean across all 83 source and test files.

## 2026-10-13 — Chat UI theme fixes via Impeccable live mode

**Status:** Done (254 passed + 6 skipped full suite; /chat renders accepted variants in light mode)

Why: chat header bar and agent message bubble used dark-hardcoded colors
(navy bar background, sky-blue JSON args, dark-only verdict hues) that washed
out under the light theme; header text was near-unreadable with Light on.

What changed (2 live-mode accepts, both carbonized into source):
- `app/templates/chat.html` + `app/static/css/chat.css`: header bar is now
  theme-native (transparent over panel, `border-subtle`, compact 30px avatar,
  inline emerald guard status, ghost queue link). Replaces the hardcoded
  `rgba(15,23,42,0.8)` background.
- `app/templates/components/chat_message.html` + `chat.css`: agent bubble
  redesigned as a verdict-tinted "exhibit" (amber proposal box, theme-token
  args/code colors, verdict stamps). Tested verdict copy restored
  (`INTERCEPTION GATE ACTIVE`, `TERMINAL POLICY DENY (LOCK 5)`) plus the
  deny-branch `execution_result`, after 4 `tests/test_chat.py` failures
  caught the drift (red → green).
- Caught at commit time: `Path.read_text()` mojibake on Windows
  (see LEARNINGS.md 15); repaired spans, full suite re-greened.
- Left out of this commit: `app/templates/base.html` live-picker injection
  (dev-only live-mode artifact) and untracked `PRODUCT.md` / `DESIGN.md` /
  `.impeccable/`.

Verified: Jinja parse ok on 3 templates; full pytest 254 passed + 6 skipped;
unicode scan matches HEAD character sets; /chat snapshot shows accepted
header + exhibit bubble in light mode.

## 2026-10-12 — Landed PR #22 core spec + golden datasets (integration PR #33)

**Status:** Done (mypy clean on 90 files, 406 passed / 6 skipped locally; CI typecheck + py3.11 + py3.12 green; merged `bf55ba9`)

What changed:
- PR #22 (`yashitchugh:sync/upstream-main-20261012` → main) was DIRTY (4 conflicts) + a fork, so it couldn't merge directly. Built integration branch `integration/pr22-core-spec` off `origin/main` (`63311e3`, which already has PR #23's WAL + login audit) and merged pr22's history in.
- Resolved all 4 conflicts keeping BOTH sides: `app/audit.py` (HEAD's defensive `get_available_actors()`), `app/main.py` + `backend/main.py` (mounted pr23's `auth_router` AND pr22's `llm_router`/`guarded_llm_router`), `app/templates/base.html` (pr22's cache-busted stylesheet).
- Scope call: did NOT surgically strip the `/llm` web console (the "extra"). `app/llm.py` also serves the nav-linked `/inbox` Interception Gate (arch §6 core HITL) and `dashboard.html` embeds `/llm/stream` — removing it would have required editing core dashboard + `tests/test_web.py`. Documented in the merge commit and PR body.
- Local gates: `uv run mypy` → Success, 90 source files; `uv run pytest tests -q` → 406 passed, 6 skipped.
- PR #33 opened + linked to thread. Substantive CI green (Typecheck & Lint, Test py3.11, Test py3.12; CodeRabbit auto-skips on OSS).
- GitGuardian fail on #33 confirmed a **false positive**: incident `22087572` "Generic Password" at `.github/workflows/ci.yml:52` (`POSTGRES_PASSWORD: postgres` — the ephemeral GH Actions test-container). The branch's ci.yml is byte-identical to `origin/main` (empty diff) and main passes GitGuardian; it was flagged only because pr22 commit `9b5152d` re-authored that file inside the scanned PR range. User approved merging past it.
- Merge: `gh pr merge --rebase` failed ("This branch can't be rebased" — the integration head contains a merge commit), fell back to `--squash --delete-branch` to keep main linear. Landed as `bf55ba9` "Merge PR #22 core spec + golden datasets (#33)".
- Cleanup: remote `integration/pr22-core-spec` deleted manually (gh's local `--delete-branch` aborted because `main` is checked out in another worktree), local `integration/pr22-core-spec` + `pr22` deleted, `main` fast-forwarded at `/home/parth/projects/warden`.
- Verified: `origin/main` tree `eb30bfc` == tested branch tree (identical → CI results apply as-is); core content present (`src/warden/tools/*`, `src/warden/hitl/approvals.py`, `tests/fixtures/golden_cases.jsonl`, `scripts/generate_golden_cases.py`).
- Skipped: `ocr-review` (no UI authored this session — merge only), `code-simplifier`/`code-review` (code pre-reviewed + CI-validated pre-merge), `retro` (deferred).

## 2026-10-12 — PostgreSQL WAL persistence & login audit integration (PR #20)

**Status:** Done (263 passed, 6 skipped full suite, 0 mypy errors across 76 files)

What changed:
- Integrated PostgreSQL WAL persistence via `PostgresJournal` adapter in `app/audit.py`.
  - Connects using `psycopg_pool.ConnectionPool` reading `CONNECTION_STRING` / `POSTGRES_URI`.
  - Durable append-only tables (`journal_events`, `audit_logs`, `login_audit`) with SHA-256 hash chaining and `(run_id, action_id, kind)` idempotency index.
  - Implements both `JournalRepository` (for `/audit` UI) and `AuditJournal` (for `GuardedExecutor` engine).
  - Graceful fallback to `InMemoryDemoJournal` when Postgres is unconfigured or unavailable.
- Integrated `@audit_login` and `@login_required` decorators in `src/warden/wrappers.py` with sensitive data scrubbing and `login_audit` ledger logging.
- Mounted `/api/auth` and `/auth` routes via `backend/api/auth.py`.
- Reconciled conflicts with upstream `origin/main` (preserved GuardedExecutor seam, OpsAssistant live chat, panel projections, and strict typing).
- Verified: 263 passed, 6 skipped; mypy clean across 76 source files.

## 2026-10-12 — Live governed OpsAssistant wired into chat UI

**Status:** Done (240 passed + 6 skipped full suite, 0 mypy errors across 61 files, live /chat round-trip 200)

Why: `/chat` only talked to canned keyword stubs; the real Phase-1 ops agent
(live Groq + real tool suite from `scripts/governed_demo.py`) ran CLI-only and
never appeared in the chat picker.

What changed:
- `src/warden/agent_engine.py`: `OpsAssistant` is now live — replies via
  `draft_with_groq` (deterministic stub fallback offline), intent mapped onto
  real Phase-1 tools (`get_system_metrics`, `read_service_logs`,
  `query_db_readonly`, `send_email`→POL_EGRESS_EXTERNAL_MSG,
  `restart_service`→POL_INFRA_MUTATION, `exec_db_mutation`→terminal deny).
  Same registry name, so picker + existing tests unaffected. Actions cross the
  existing GuardedExecutor seam in `app/chat.py` (allow/deny/HITL approve UI).
- `tests/test_governed_chat_agent.py`: 6 new tests (registry, live reply,
  metrics/email/drop-table mapping, end-to-end POST /chat/message).

Verified: full pytest green, mypy strict clean, restarted `app.main:app` on
:8000 and POSTed a live metrics prompt as OpsAssistant → 200 with staged
`get_system_metrics`. Uncommitted (not requested).

Follow-ups in same session (all committed, pushed):
- `app/projections.py` + panel wiring: sandbox runs + policy evaluations
  projected from JOURNAL_STORE, so chat turns fill panels dynamically.
- Chat defaults flipped to OpsAssistant; fabricated approval telemetry
  removed in favor of journaled completions.
- `get_clef_client()` factory: live Clef L2 on the GuardedExecutor seam when
  Cloudflare creds exist, fake otherwise; explicit escalation-rule hints
  downgrade lone clef-risk DENYs to human gates (rulebook beats ML).

## 2026-10-12 — GuardedExecutor core seam & full multi-agent UI integration

**Status:** Done (234 passed full suite, 0 mypy errors across 71 files)

What changed:
- `src/warden/executor.py`:
  - Implemented the production `GuardedExecutor` — the single governance seam.
  - Enforces write-ahead journal logging (`action_requested`), 3-tier `PolicyEngine` evaluation, terminal `Denied` on invariant breach (Lock 5), `Pending(gate_request)` on escalation (Lock 2), human approval execution dispatch, fail-closed handling on policy or sandbox failure (Lock 4), and sandboxed execution via `DockerSandbox` (Lock 7).
- `src/warden/journal.py`:
  - Created `AuditJournal` interface and `InMemoryJournal` with SHA-256 hash chaining and write-ahead idempotency (`(run_id, action_id, kind)` deduplication, Lock 3).
- `src/warden/agent_engine.py` & `app/chat.py`:
  - Wired agent proposals to evaluate through `GuardedExecutor.execute()`.
  - Wired 1-click in-chat approvals to dispatch through `GuardedExecutor.execute(..., approval=decision)`, executing real tools and storing genuine results.
- `backend/main.py`:
  - Unified server mounting all Aegis UI routes (`/chat`, `/agents`, `/leases`, `/traces`, `/sandbox`, `/approvals`, `/actions/{id}`) alongside backend `/api/*` endpoints.
- `tests/test_executor.py`:
  - Added 10 tests covering safe allow, terminal deny, non-overridable deny, HITL escalation, approval execution, human denial abort, sandbox dispatch, fail-closed error handling, and LLM telemetry.
- Post-code-change pipeline:
  - `code-simplifier`: Verified readable structure, no redundant abstractions.
  - `code-review`: Verified 0 merge blockers against main.
  - `ocr-review`: Skipped (no UI image or screenshot rendering modified).
  - Verification: 234 passed, 6 skipped; mypy clean in strict mode on 71 source files.

## 2026-10-12 — unified backend & live journal integration

**Status:** Done (234 passed full suite, 35 passed web + audit tests)

What changed:
- `backend/main.py`:
  - Mounted Aegis routers (`chat_router`, `agents_router`, `leases_router`, `traces_router`, `sandbox_router`, `aegis_audit_router`, `aegis_policies_router`).
  - Added Aegis action review endpoints `/approvals` and `/actions/{action_id}`.
  - Implemented `MultiDirStaticFiles` to serve static assets transparently from both `frontend/static` and `app/static` under `/static`.
- `backend/api/audit.py`:
  - Connected `/api/audit` to live `JOURNAL_STORE.list_events` with dictionary mapping of `JournalEvent` models, preserving graceful fallback to default events if journal is empty or unfiltered.
- `frontend/views.py`:
  - Connected `dashboard_view`, `audit_view`, `inbox_view`, and `runs_view` to query live `JOURNAL_STORE` events and derive real runtime metrics (pending gates, total actions, token estimates, active threads).
- Fixed typing issues:
  - `tests/test_tools_router.py`: added `monkeypatch: pytest.MonkeyPatch` annotation on line 56.
  - `tests/test_governed_demo.py`: added `# type: ignore[import-not-found]` on dynamic script import.
  - `app/audit.py`: added `__all__` export list and email action seed event for search testing.
- Verification:
  - Full suite passed: 234 passed, 6 skipped.
  - Web & audit tests passed: 35 passed (`tests/test_web.py` + `tests/test_audit.py`).
  - Verified 21 unified API and page endpoints via TestClient.

## 2026-10-12 — connected demo: 2 governed agents on one enforced path

**Status:** Done (186 passed full suite, live demo green, timeline rendered)

What changed:
- Env repair: worktree `.venv` had corrupt langgraph install (dist-info only,
  no pytest) → force-reinstalled langgraph* + `.[dev]`. Checkpoint tests pass
  again (18 passed). Root cause of the earlier collection errors.
- `scripts/governed_demo.py` (DEMO-GRADE seam, not production GuardedExecutor):
  GovernedRunner enforces journal → PolicyEngine (+ tool-aware L0 guards) →
  HITL gate → DockerSandbox/in-process → journal for EVERY LLM+tool action.
  Live hash-chained journal (reuses app.audit event model, VERIFIED).
  Two agents share one runner+journal: ops-assistant (metrics→gated email→
  denied DROP→sandboxed shell) + db-researcher (select→denied shadow→gated
  restart). Interactive terminal HITL by default, `--auto-approve NAME` for CI.
- Live run: 34 events, chain Verified; per-agent telemetry (LLM calls, tools,
  gated, denied, tokens, latency); run.json + timeline.html in .tmp/.
- `tests/test_governed_demo.py`: 6 offline tests (fake LLM + fake sandbox).
- `scripts/render_demo_timeline.py`: self-contained HTML timeline.

## 2026-10-12 — governance audit: HITL, policy-per-call, sandbox routing, tracing

**Status:** Done — 7 probes, 7 findings (1 critical, 3 high, 1 medium, 2 info)

Method: `scripts/audit_probes.py` (live probes vs real code, evidence in
`.tmp/audit_evidence.json`) + visual report `.tmp/audit/report/index.html`.

Verdicts:
- Policy engine verdicts correct on all 10 payloads (PASS, advisory-only).
- CRITICAL: no agent call passes through policy — GuardedExecutor/journal/
  run_gated don't exist; demo_graph calls Groq directly.
- HIGH: inbox accepts any Warden-Key (incl. `mallory-intruder`), resolves by
  popping a mock dict, never journals or resumes; real park/resume currently
  unimportable (langgraph-checkpoint-postgres 3.1.2 layout change).
- MEDIUM: DockerSandbox proven live (net-none containment + egress blocked),
  but nothing auto-routes approved tools into it.
- HIGH: traces (4) + journal (15 events) are hardcoded seeds, no writers.
- HIGH: /api/telemetry returns constants; only GuardedLLMClient sink is live.
- INFO: live Groq via guarded client green (78/52/130 tokens, telemetry OK).

## 2026-10-12 — live Groq testing (key copied from main repo)

**Status:** Done (live Groq green end-to-end, 81 passed)

- Copied `GROQ_API_KEY` from the main checkout's `.env` into
  worktree `.env` (gitignored, never printed). `settings.groq_api_key` loads.
- `scripts/demo_tools.py`: all 4 beats green + REAL Groq draft returned
  (fixed cp1252 console crash on U+202F via ascii-safe print).
- New `scripts/live_groq_test.py`: GuardedLLMClient + real Groq provider —
  success=True, 764ms, usage 78/52/130 provider-reported, telemetry emitted.
- Finding: `openai/gpt-oss-20b` not in pricing catalog → cost unpriced.
  Left as-is (pricing data change, needs your call).
- Note: with key present, `test_groq_stub_string` now makes a real network call
  (still asserts str). Consider mocking if suite must stay offline.
- Suite: 81 passed (tools + llm + policy + config).

## 2026-10-12 — Phase-1 tool suite (ops-assistant, 8 tools + Groq router)

**Status:** Done (36 new tests green, 145 passed incl. pre-existing, mypy clean on src/warden/tools)

What changed (all additive — zero modifications to existing files):
- `src/warden/tools/` — base (ToolSpec/ToolContext/make_action), safe_tools
  (get_system_metrics, read_service_logs, query_db_readonly — synthetic stubs,
  read-only validators), hitl_tools (send_email→POL_EGRESS_EXTERNAL_MSG,
  restart_service→POL_INFRA_MUTATION — pending-previews, no side effects, never
  calls interrupt per lock 2), deny_tools (exec_db_mutation, read_file_sensitive —
  L0 ACL + PolicyEngine mapping, DENY terminal per lock 5), sandbox_tools
  (exec_shell→registry profile "shell"→DockerSandbox, fail-closed per lock 4),
  router (ToolRouter.preview: pure Action→Outcome over existing PolicyEngine;
  Groq via get_groq_llm + draft_with_groq stub fallback).
- `scripts/demo_tools.py` — 4 demo beats verified: ALLOW / Pending / DENIED / sandbox-route.
- `tests/test_tools_{safe,hitl,deny,sandbox,router}.py` — 36 tests.

Constraint honored: wired ONLY to existing seams (models, policy/*, sandbox/*,
config, llm). Did NOT create executor.py / journal.py / hitl/runner.py.

Notes:
- Parallel Task subagents all failed (transport closed x5) → built directly.
- Bare `TRUNCATE orders` (no TABLE) slipped L0 regex → deny_tools adds keyword
  fallback. FakeClef scores any `rm -rf`/send-email text high → sandbox demo beat
  uses benign `ls` command (Allowed route=sandbox); destructive shell stays DENY.
- Pre-existing env breakage (not mine): test_checkpoint/test_cli_chat/test_web
  fail collection — installed langgraph-checkpoint-postgres 3.1.2 no longer
  provides `langgraph.checkpoint.postgres.aio`. My files don't touch that path.
- GROQ_API_KEY unset in this env → Groq draft falls back to deterministic stub.

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

## 2026-10-13 - Grants/Leases browser tests on app/ UI (latest main e65b3a3)

**Status:** Done (grants 24 passed + e2e 3 passed; 14/14 app routes 200; grant issue/revoke + lease issue/revoke verified live on background server :8100)

- Pulled main (b89e4c4 -> e65b3a3, Grants PR #40); discarded local impeccable live-script edit to base.html.
- Server runs as background service: .venv Scripts uvicorn app.main:app on 127.0.0.1:8100 (app/ dir UI, not frontend/ dir).
- Browser (preview tab): Command Center, Interception Gate, Guarded LLM, User Grants dialog (issued grant thread_browser_test_01 live, persisted active), leases pages all render.
- Headless checks: POST /grants 201, ttl/missing-thread 422s, revoke flips to revoked; POST /leases creates LSE-*, revoke flips to REVOKED, bad id 404.
- Venv edge case: pydantic_core ImportError recurred (dual dist-infos, missing RECORD). Fixed via stop-server + uv pip install --force-reinstall pydantic-core; server restarted clean. Never run uv sync/install while uvicorn holds the .pyd.

## 2026-10-13 - Fixed console 404s: favicon + implemented legacy frontend /partials endpoints

**Status:** Done (10 new regression tests; 65 passed across test_web/test_app_llm_ui/test_audit_timeline/test_governance_pages; mypy clean 95 files; live server log shows zero 404s)

- Root causes: (1) no favicon anywhere - every page load logged GET /favicon.ico 404; (2) frontend/templates dashboard+runs+run_detail polled/posted 7 /partials/* endpoints that were never implemented.
- Fix: app/static + frontend/static favicon.svg, rel=icon links in both base.html, /favicon.ico routes in app/main.py and backend/main.py.
- Implemented in frontend/views.py wrapping existing backend services: GET /partials/telemetry/stats, /partials/runs/table, /partials/llm/stream (new partials/*.html fragments reusing dashboard markup); POST /partials/runs/create and /runs/{id}/resume return 204+HX-Refresh (400 empty prompt/bad decision, 404 unknown thread); POST /partials/llm/estimate|invoke render result slot HTML (DENY/pending/ok/error branches).
- Refactor: dashboard stats/runs derivation extracted to _dashboard_stats()/_dashboard_recent_runs(); dashboard now also passes recent_llm_records (stream table was always empty-state before).
- Note: user deleted src/warden/projections/ (was empty __init__.py) during session - intentional, left as-is.
