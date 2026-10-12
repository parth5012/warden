# Aegis — Testing Strategy

> Test inventory, acceptance criteria, fixture conventions, and the 18 required security scenarios.

---

## 1. Test Architecture

```
tests/
├── __init__.py                  # package marker — import as from tests import ...
├── conftest.py                  # session-scoped real-Postgres fixture (pg_uri)
├── cli_chat.py                  # CLI harness (importable library + entry point)
├── test_checkpoint.py           # 12 checkpoint tests — IMPLEMENTED ✅
├── test_cli_chat.py             # 4 CLI regression tests — IMPLEMENTED ✅
│
│   # Planned Phase 1 test files:
├── test_executor.py             # GuardedExecutor unit tests (with mocks)
├── test_policy.py               # PolicyEngine unit tests
├── test_journal.py              # AuditJournal append/query/idempotency
├── test_sandbox.py              # SandboxPort subprocess + timeout + env
├── test_hitl.py                 # HITL re-entry helper tests
├── test_projections.py          # Projection function unit tests
├── test_api.py                  # FastAPI route tests (TestClient)
├── test_executor_integration.py # Full stack integration (real Postgres)
└── test_e2e_demo.py             # Phase 1 four-beat e2e demo
```

---

## 2. Existing Tests — Implemented ✅

### `test_checkpoint.py` — 12 tests

All run against real PostgreSQL via `pgserver`.

| Test | What it verifies |
|---|---|
| `test_create_setup_is_idempotent` | Double-init does not fail |
| `test_checkpointer_unavailable_outside_context` | Accessing `.checkpointer` outside `async with` raises |
| `test_health_check_true_when_open` | `health_check()` returns `True` with open connection |
| `test_create_raises_on_bad_connection` | Bad Postgres URI raises on startup |
| `test_interrupt_parks_then_resume_completes` | Park + inspect + approve resume |
| `test_resume_with_deny_aborts` | Park + deny resume → `approved: False` |
| `test_resume_is_idempotent_per_decision` | Draft message appears exactly once after resume |
| `test_state_survives_manager_restart` | Park, close manager, reopen, resume — works |
| `test_state_history_walk` | History is oldest-first, non-decreasing steps |
| `test_state_info_fail_closed_after_close` | `get_state_info()` returns `Error` after close |
| `test_resume_fail_closed_after_close` | `resume()` returns `Error` after close |
| `test_history_fail_closed_after_close` | `get_state_history()` returns `Error` after close |
| `test_redact_masks_credentials` (×6) | URI userinfo, keyword DSN, `@` in query string |

### `test_cli_chat.py` — 4 tests

Unit tests for the CLI resume-prompt decision loop.

| Test | What it verifies |
|---|---|
| `test_quit_at_resume_prompt_leaves_parked` | `/quit` at resume prompt does not become a decision |
| `test_empty_input_reprompts` | Empty input re-prompts, does not route to graph |
| `test_failed_resume_reprompts` | Failed resume (None) re-prompts, does not count as decision |
| `test_repark_loops_until_decision_completes` | Re-park loops back to resume prompt |

---

## 3. Testing Pyramid for Phase 1

```
         E2E (Playwright / real stack)
              test_e2e_demo.py
           ─────────────────────────
       Integration (real Postgres, mock tools)
          test_executor_integration.py
       ─────────────────────────────────────
     Unit (in-memory mocks, fast, isolated)
  test_executor.py  test_policy.py  test_journal.py
  test_sandbox.py   test_hitl.py    test_projections.py
  test_api.py
```

### Unit test rules

- Use `MockJournal`, `MockPolicyEngine`, `MockSandbox`, `MockLLMClient` from [`docs/INTEGRATION_GUIDE.md`](INTEGRATION_GUIDE.md).
- No real Postgres in unit tests.
- No real LLM calls in unit tests.
- Each test should test one behaviour.

### Integration test rules

- Use the `pg_uri` fixture from `conftest.py` (real Postgres via pgserver).
- Each test gets a fresh thread ID (`_fresh_thread()`).
- Test the full executor stack: journal → policy → sandbox/LLM → journal.

---

## 4. Fixture Conventions

### Session-scoped Postgres (`conftest.py`)

```python
@pytest.fixture(scope="session")
def pg_uri() -> Iterator[str]:
    """Session-scoped PostgreSQL over a UNIX socket (no root required)."""
    dbdir = tempfile.mkdtemp(prefix="warden-pg-")
    srv = pgserver.get_server(dbdir)
    try:
        yield srv.get_uri()
    finally:
        srv.cleanup()
        shutil.rmtree(dbdir, ignore_errors=True)
```

### Fresh thread IDs

```python
def _fresh_thread() -> str:
    return f"test-{uuid.uuid4().hex[:12]}"
```

Always use fresh thread IDs in integration tests. Never reuse thread IDs across tests.

### Mock executor fixture pattern

```python
@pytest.fixture
def allow_all_executor() -> MockExecutor:
    return MockExecutor(default_outcome=Allowed(result="ok"))

@pytest.fixture
def deny_all_executor() -> MockExecutor:
    return MockExecutor(default_outcome=Denied(reason="blocked", policy="test_deny"))
```

---

## 5. The 18 Required Security Scenarios

These acceptance tests must exist before Phase 1 is considered complete.

| # | Scenario | Test location | Status |
|---|---|---|---|
| 1 | Safe action permitted and audited | `test_executor.py` | 📋 Planned |
| 2 | Risky email-send escalated to human | `test_executor.py` | 📋 Planned |
| 3 | Pending approval visible in inbox projection | `test_projections.py` | 📋 Planned |
| 4 | Authorized approval resumes the workflow | `test_hitl.py` + `test_executor_integration.py` | 📋 Planned |
| 5 | Rejection leaves action unexecuted | `test_hitl.py` | 📋 Planned |
| 6 | `DROP TABLE` denied with no human override path | `test_executor.py` + `test_policy.py` | 📋 Planned |
| 7 | Prohibited action never reaches sandbox | `test_executor.py` | 📋 Planned |
| 8 | Sandbox timeout fires and logs `timed_out=True` | `test_sandbox.py` | 📋 Planned |
| 9 | Journal write failure prevents side effects | `test_executor.py` (mock journal that raises) | 📋 Planned |
| 10 | PostgreSQL connection failure → `503` from API | `test_api.py` | 📋 Planned |
| 11 | Restart with pending action → resume works | `test_checkpoint.py` ✅ `test_state_survives_manager_restart` | ✅ Covered |
| 12 | Duplicate resume or repeated submission → `409` | `test_api.py` | 📋 Planned |
| 13 | Tampered or stale approval rejected | `test_api.py` + `test_executor.py` | 📋 Planned |
| 14 | LLM provider failure → `Error` outcome | `test_executor.py` | 📋 Planned |
| 15 | Missing or invalid approver key → `401` | `test_api.py` | 📋 Planned |
| 16 | Connection string redacted in all logs | `test_checkpoint.py` ✅ `test_redact_masks_credentials` | ✅ Covered |
| 17 | Projection failure does not corrupt journal | `test_projections.py` (mock that raises) | 📋 Planned |
| 18 | Journal recovery after process termination | `test_checkpoint.py` ✅ `test_state_survives_manager_restart` | ✅ Covered (via checkpoint) |

---

## 6. Acceptance Tests per Feature

### GuardedExecutor

```python
# Scenario 1: allow path
async def test_safe_action_allowed_and_journaled(executor, journal):
    action = make_action("read_table", kind=ActionKind.TOOL)
    outcome = await executor.execute(action, ctx)
    assert isinstance(outcome, Allowed)
    events = await journal.query()
    assert any(e["kind"] == "action_requested" for e in events)
    assert any(e["kind"] == "action_completed" for e in events)

# Scenario 6: deny is terminal
async def test_drop_table_denied_terminal(deny_policy_executor, journal):
    action = make_action("drop_table", kind=ActionKind.TOOL)
    outcome = await deny_policy_executor.execute(action, ctx)
    assert isinstance(outcome, Denied)
    # Verify sandbox was never called
    assert sandbox.calls == []

# Scenario 9: journal failure prevents execution
async def test_journal_failure_prevents_side_effects(failing_journal_executor):
    action = make_action("send_email", kind=ActionKind.TOOL)
    outcome = await failing_journal_executor.execute(action, ctx)
    assert isinstance(outcome, Error)
    assert outcome.reason == "governance_unavailable"
    assert sandbox.calls == []
```

### PolicyEngine

```python
async def test_drop_table_always_denied(engine):
    action = make_action("drop_table")
    result = await engine.evaluate(action, ctx)
    assert result.decision == PolicyDecision.DENY

async def test_send_email_escalates(engine):
    action = make_action("send_email")
    result = await engine.evaluate(action, ctx)
    assert result.decision == PolicyDecision.ESCALATE

async def test_unknown_action_deny_by_default(engine):
    action = make_action("some_unknown_tool")
    result = await engine.evaluate(action, ctx)
    assert result.decision == PolicyDecision.DENY  # deny-by-default
```

### HITL Re-entry

```python
async def test_run_gated_parks_and_resumes_on_approve(graph, manager):
    # Start graph — parks at approval interrupt
    result = await graph.ainvoke({"messages": []}, config)
    assert "__interrupt__" in result

    # Simulate approval decision
    resumed = await manager.resume(graph, config, "approve")
    assert isinstance(resumed, dict)
    assert resumed["approved"] is True
```

### SandboxPort

```python
async def test_subprocess_timeout_returns_timed_out(sandbox):
    action = make_action("run_shell", payload={"cmd": "sleep 100"})
    result = await sandbox.run(action)
    assert result.timed_out is True
    assert result.error_code == "timeout"

async def test_subprocess_env_is_scrubbed(sandbox, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-secret")
    action = make_action("run_shell", payload={"cmd": "echo $OPENAI_API_KEY"})
    result = await sandbox.run(action)
    assert "sk-secret" not in (result.result or "")
```

---

## 7. Type Coverage

All new modules must be mypy-clean at `strict = true` before merge. Add mypy to CI:

```bash
uv run mypy src tests
```

The `--strict` flag is already set in `pyproject.toml` — do not weaken it.

---

## 8. Test Data Conventions

- Use `uuid.uuid4().hex[:12]` prefixed with a module identifier for thread IDs.
- Use `datetime.now(timezone.utc)` for all timestamps in test fixtures.
- Do not hard-code action IDs — generate them.
- Never use production credentials in test fixtures.
- Mock LLM responses in unit tests — never make real API calls in tests without explicit `@pytest.mark.integration` marking.

---

## 9. CI Requirements

Before a PR can merge:

```bash
uv run pytest             # all tests pass
uv run mypy src tests     # 0 errors
```

When the FastAPI app exists, add:

```bash
uv run pytest tests/test_api.py   # API contract tests
```
