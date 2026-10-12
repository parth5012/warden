# Aegis — WAL & Audit Log Feature Documentation

> Single source of truth for the Write-Ahead Logging (WAL) and Audit Log implementation in Aegis.
> Distinguishes PostgreSQL's internal WAL from Aegis's application-level append-only event journal and transactional outbox.

---

## 1. Architectural Distinctions: WAL vs. Audit Log

In Aegis, four distinct log/journal layers operate together:

1. **PostgreSQL Internal Write-Ahead Log (WAL):**
   * Physical 8KB page level WAL on disk (`pg_wal`).
   * Managed by PostgreSQL for ACID crash recovery and replica streaming.
   * *Not application code.*

2. **Aegis Application-Level Event Journal (`journal_events`):**
   * Append-only domain event journal recording every state transition *before* action execution and *after* policy/human verdicts.
   * Provides idempotency locks (`(run_id, action_id, kind)`) so uncommitted or duplicate actions cannot execute twice.
   * Implemented in `app/audit.py` with in-memory adapter (`InMemoryDemoJournal`) and contract hooks for PostgreSQL persistence.

3. **Transactional Outbox:**
   * Hand-off queue for asynchronous execution workers (e.g. `SandboxPort`).
   * Guarantees at-least-once execution dispatch once a human or policy approves an action.

4. **Human-Readable Audit Dashboard (`/audit`):**
   * Server-rendered FastAPI + Jinja2 + HTMX monitoring console.
   * Allows security operators to inspect provenance, event timelines, payloads, and cryptographic integrity.

---

## 2. Event Schema & Canonical Event Kinds

### Event Fields (`JournalEvent`)
Compatible with `DATA_MODEL.md § 5`:

| Field | Type | Description |
|---|---|---|
| `id` | `str` (UUID) | Unique event identifier |
| `run_id` | `str` | Agent run identifier |
| `thread_id` | `str` | LangGraph thread identifier |
| `action_id` | `str \| None` | Associated action reference (e.g. `act_7129e3`) |
| `checkpoint_step` | `int \| None` | State checkpoint index |
| `kind` | `str` | Event kind (see below) |
| `actor` | `str` | Originating agent or human approver (e.g. `CodeAgent`, `Raghav`) |
| `status` | `str` | Lifecycle status (`Proposed`, `Allowed`, `Denied`, `Escalated`, `Succeeded`, `Failed`) |
| `description` | `str` | Readable summary of the action/decision |
| `payload` | `dict` | Untrusted domain parameters (arguments, SQL statements, tokens) |
| `ts` | `str` (ISO 8601 UTC) | Time event occurred |
| `prev_hash` | `str \| None` | SHA-256 digest of previous event in chain |
| `event_hash` | `str` | SHA-256 digest of this canonical event + `prev_hash` |
| `verification_status` | `str` | `Verified`, `Verification failed`, `Not verified`, or `Verification unavailable` |

### Supported Event Kinds

* `action_requested` — Action proposed by an agent (write-ahead intent)
* `policy_evaluated` — Policy rule evaluated (allow, escalate, or deny)
* `action_denied` — Terminal policy denial (Lock 5)
* `gate_requested` — Escalated to human-in-the-loop review
* `gate_decided` — Human approver decision submitted
* `execution_queued` — Action placed in execution outbox
* `execution_started` — Execution runner commenced work
* `action_completed` — Execution succeeded with output
* `action_failed` — Execution error or timeout
* `checkpoint_created` — LangGraph checkpoint persisted
* `lease_evaluated` — Ephemeral lease evaluated

---

## 3. Endpoints & Query Parameters

### 1. `GET /audit`
* **Content-Type:** `text/html; charset=utf-8`
* **Query Parameters:**
  * `q` (string): Full-text search across payload, description, IDs, and actor.
  * `kind` (string): Filter by event kind (default `all`).
  * `action_id` (string): Filter by exact or partial action ID.
  * `run_id` (string): Filter by run/thread ID.
  * `actor` (string): Filter by actor/agent.
  * `page` (int, `>= 1`): Page number (default `1`).
  * `limit` (int, `1..100`): Results per page (default `15`).
* **HTMX Support:**
  When `HX-Request: true` is present, returns `components/audit_table_fragment.html` for instant partial updates without full page reloads.

### 2. `GET /audit/events/{event_id}`
* **Content-Type:** `text/html; charset=utf-8`
* Returns the slide-over inspection drawer (`components/audit_event_detail.html`):
  * Provenance metadata (Actor, Status, Action ID, Checkpoint Step, Run ID, Thread ID)
  * Cryptographic Hash Chain (Current SHA-256, Previous Hash, Verification Status)
  * Untrusted Payload viewer with safe JSON rendering (neutralizes XSS)
  * Related lifecycle events sharing the same `action_id` or `run_id`

### 3. `GET /audit/export`
* **Content-Type:** `text/csv; charset=utf-8`
* Downloads filtered records with `Content-Disposition: attachment; filename="aegis_audit_log_<timestamp>.csv"`.
* **Formula Injection Defense:** Any cell beginning with `=`, `+`, `-`, `@`, `\t`, or `\r` is prepended with `'` per OWASP guidelines.

---

## 4. Security & Immutability Rules

1. **Strictly Append-Only:**
   * No `POST`, `PUT`, `PATCH`, or `DELETE` endpoints exist for audit records.
   * Direct mutation of historical events is impossible through the application layer.
2. **Untrusted Payload Isolation:**
   * Event payloads (which originate from LLMs or untrusted tool calls) are rendered using text-only escaping in `<pre><code>` blocks. No raw HTML interpretation is allowed.
3. **No Fabricated Verification:**
   * When running against local in-memory storage, the status displays **"Verification unavailable"** with a clear explanation that the PostgreSQL ledger from Gourav/Yashit is pending connection.
   * "Verified" is only displayed when the actual backend cryptographic verification validator (`verify_hash_chain`) confirms the hash linkage.

---

## 5. Running & Testing

### Run Development Server
```powershell
python -m uvicorn app.main:app --reload
```
Navigate to: `http://127.0.0.1:8000/audit`

### Run Test Suite
```powershell
python -m pytest tests/test_audit.py tests/test_approval_workflow.py -v
```

---

## 6. PostgreSQL WAL Persistence & Login Decorators

### Database Tables (`CONNECTION_STRING` in `.env`)
The system auto-connects to PostgreSQL via `CONNECTION_STRING` or `POSTGRES_URI` using `psycopg_pool.ConnectionPool`:
1. `journal_events` — Core append-only Write-Ahead Log table storing full event telemetry, SHA-256 hash chains, and the `(run_id, action_id, kind)` idempotency index.
2. `audit_logs` — General audit log table for system events, action audits, and security telemetry.
3. `login_audit` — Dedicated authentication audit ledger tracking all login attempts, authentication methods, client IP addresses, user agents, status (`attempted`, `success`, `failed`, `denied`), and failure reasons linked to WAL events.

### Login Decorators (`src/warden/wrappers.py`)
* `@audit_login(auth_method="password", actor_arg="username", require_success=True)`
  Decorates authentication/login functions. Writes write-ahead intent (`action_requested` with operation `USER_LOGIN`) prior to authentication, logs to `login_audit` table, scrubs passwords/tokens via `redact_sensitive_data()`, and records `action_completed` on success or `action_denied` on failure.
* `@login_required()` / `@require_login()`
  Protects sensitive route handlers and execution paths by validating `Warden-Key` headers or Bearer tokens against `WARDEN_APPROVER_KEYS`. Automatically logs unauthorized access attempts (`action_denied`) to the WAL journal and returns HTTP 401.

---

## 7. Integration Points with Teammate Modules

| Teammate | Module | Status & Integration Point |
|---|---|---|
| **Yashit** | Storage & Audit Table | Connected `PostgresJournal` to PostgreSQL tables `journal_events`, `audit_logs`, and `login_audit` using `psycopg_pool`. |
| **Gourav** | Sandbox & Verification | Connected `verify_hash_chain` to PostgreSQL write-ahead audit table verification runner with automatic `Verified` status. |
| **Parth** | LangGraph & Seam | Hooked `GuardedExecutor` and `@audit_login` to persist state transitions before and after execution. |
