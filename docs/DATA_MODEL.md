# Aegis — Data Model

> Single source of truth for domain types, action lifecycle, and persistence schemas.
> All feature READMEs link here instead of defining their own schemas.

---

## Status Legend

| Label | Meaning |
|---|---|
| ✅ IMPLEMENTED | Python type exists in `src/warden/models.py`, tests pass |
| 📋 PROPOSED | Schema documented; persistence not yet implemented |
| 🔒 LOCKED | Design decision in CONTEXT.md — do not change without discussion |

---

## 1. Action — the Unit Crossing the Seam ✅ IMPLEMENTED

**Source:** [`src/warden/models.py`](../src/warden/models.py)

```python
class ActionKind(str, Enum):
    TOOL = "tool"
    LLM  = "llm"

@dataclass(frozen=True)
class Action:
    id:        str               # unique action identity (UUID recommended)
    kind:      ActionKind        # tool | llm
    name:      str               # tool name or model identifier
    payload:   dict[str, Any]    # tool arguments or LLM messages
    run_id:    str               # identifies the agent run
    thread_id: str               # LangGraph thread identifier
```

**Rules:**
- Every action that crosses the executor seam must carry all five fields.
- `id` is the idempotency key for the write-ahead journal entry.
- Both `kind=tool` and `kind=llm` cross the same seam (Lock 1).
- `payload` for `kind=llm` carries the messages list; for `kind=tool` it carries tool arguments.

---

## 2. Outcome — the Four Verdicts ✅ IMPLEMENTED

**Source:** [`src/warden/models.py`](../src/warden/models.py)

```python
class OutcomeKind(str, Enum):
    ALLOWED = "allowed"
    DENIED  = "denied"
    PENDING = "pending"
    ERROR   = "error"

Outcome = Allowed | Denied | Pending | Error
```

### Allowed

```python
@dataclass(frozen=True)
class Allowed:
    result: Any               # tool return value or LLM response
    kind:   OutcomeKind       # always OutcomeKind.ALLOWED
```

### Denied 🔒

```python
@dataclass(frozen=True)
class Denied:
    reason: str               # human-readable explanation
    policy: str               # policy rule name or identifier
    kind:   OutcomeKind       # always OutcomeKind.DENIED
```

> **TERMINAL.** A `Denied` outcome cannot be overridden by any human. Policy `deny` is final (Lock 5). Human approval only applies to `escalate` decisions.

### Pending

```python
@dataclass(frozen=True)
class Pending:
    gate_request: GateRequest
    kind:         OutcomeKind  # always OutcomeKind.PENDING
```

> `execute()` returns `Pending` explicitly — it does NOT transparently interrupt the LangGraph workflow (Lock 2). The re-entry helper (`run_gated`) is responsible for parking via `interrupt()`.

### Error (Fail-Closed)

```python
@dataclass(frozen=True)
class Error:
    reason: str               # e.g. "governance_unavailable"
    kind:   OutcomeKind       # always OutcomeKind.ERROR
```

> `Error` is distinct from `Denied`. `Error` means the governance infrastructure itself failed. `Denied` means the policy evaluated and rejected. The action is not executed in either case (Lock 4).

---

## 3. Gate Types (HITL) ✅ IMPLEMENTED

**Source:** [`src/warden/models.py`](../src/warden/models.py)

### GateRequest

Emitted when a policy decision is `escalate`. Feeds the approvals inbox projection.

```python
class GateVerdict(str, Enum):
    APPROVE = "approve"
    DENY    = "deny"

@dataclass(frozen=True)
class GateRequest:
    gate_id:      str               # unique gate identity (UUID)
    action:       Action            # the action awaiting approval
    context:      dict[str, Any]    # additional context for reviewer
    requested_at: datetime          # UTC timestamp
```

### GateDecision

Recorded when a human reviewer submits a decision.

```python
@dataclass(frozen=True)
class GateDecision:
    gate_id:    str          # must match a GateRequest.gate_id
    verdict:    GateVerdict  # approve | deny
    reason:     str          # reviewer's stated reason
    decided_by: str          # named approver key principal
    decided_at: datetime     # UTC timestamp
```

> Human denial of a gate (`GateVerdict.DENY`) does not execute the action. It is distinct from policy `DENY` — it means the human reviewer declined to authorize, not that the policy rule blocked it.

---

## 4. Checkpoint View Type ✅ IMPLEMENTED

**Source:** [`src/warden/models.py`](../src/warden/models.py)

```python
@dataclass(frozen=True)
class CheckpointInfo:
    thread_id:                str
    checkpoint_id:            str
    parent_checkpoint_id:     str | None
    created_at:               str | None      # ISO string, not datetime
    step:                     int
    has_pending_interrupts:   bool
    pending_interrupt_values: list[Any]
```

This is a **view type** used for logging and inspection only. It is not a persistence schema. The actual checkpoint data is owned by LangGraph's `AsyncPostgresSaver`.

> **Gotcha from LEARNINGS.md:** `StateSnapshot.metadata` arrives as a plain `dict` after serde — `meta["step"]`, not `meta.step`. `created_at` is an ISO `str | None`, not a `datetime`.

---

## 5. Journal Event Schema 📋 PROPOSED

The `journal_events` table is append-only. Every event has a shared header and a kind-specific payload.

### Proposed table schema

```sql
-- PROPOSED: not yet implemented
CREATE TABLE journal_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id          TEXT        NOT NULL,
    thread_id       TEXT        NOT NULL,
    action_id       TEXT,                    -- NULL for system events
    checkpoint_step INTEGER,                 -- LangGraph step number
    kind            TEXT        NOT NULL,    -- see EventKind below
    actor           TEXT,                    -- agent name or approver key
    payload         JSONB       NOT NULL DEFAULT '{}',
    ts              TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Idempotency index for write-ahead events
-- (run_id, action_id, kind) must be unique for write-ahead kinds
CREATE UNIQUE INDEX journal_events_idempotency
    ON journal_events (run_id, action_id, kind)
    WHERE kind IN ('action_requested', 'gate_requested');
```

### Proposed event kinds

| Kind | When emitted | Idempotent? |
|---|---|---|
| `action_requested` | Before policy evaluation (write-ahead) | ✅ Yes — key: `(run_id, action_id)` |
| `action_denied` | Policy returns `deny` | No |
| `gate_requested` | Policy returns `escalate` | ✅ Yes — key: `(run_id, action_id)` |
| `gate_decided` | Human submits decision | No |
| `action_completed` | Action executed successfully | No |
| `action_failed` | Action execution error | No |
| `llm_usage` | LLM call completed (token/cost data) | No |

### Proposed event payload shapes

```python
# PROPOSED Python types for event payloads
# These are documentation proposals, not implemented code.

# action_requested / action_denied / action_completed
{
    "action_id":   str,
    "kind":        "tool" | "llm",
    "name":        str,
    "payload":     dict,          # tool args or LLM messages (may be redacted)
}

# gate_requested
{
    "gate_id":      str,
    "action_id":    str,
    "context":      dict,
    "requested_at": str,          # ISO 8601
}

# gate_decided
{
    "gate_id":    str,
    "verdict":    "approve" | "deny",
    "reason":     str,
    "decided_by": str,            # named approver principal
    "decided_at": str,            # ISO 8601
}

# llm_usage
{
    "action_id":              str,
    "provider":               str,                 # e.g. "openai", "anthropic", "google"
    "model":                  str,                 # model name or checkpoint
    "prompt_tokens":          int,                 # provider reported or estimated prompt tokens
    "completion_tokens":      int,                 # provider reported or estimated completion tokens
    "total_tokens":           int,                 # mutually-exclusive total
    "input_uncached_tokens":  int,                 # prompt_tokens - cached_tokens
    "input_cached_tokens":    int,                 # cached prompt tokens
    "output_standard_tokens": int,                 # completion_tokens - reasoning_tokens
    "output_reasoning_tokens":int,                 # reasoning tokens within completion
    "usage_source":           str,                 # "provider_reported" | "estimated" | "unavailable"
    "calculated_cost_usd":    float | None,        # exact Decimal calculated cost (None if model unknown)
    "estimated_cost_usd":     float | None,        # preflight estimated cost
    "pricing_version":        str | None,          # version string of applied pricing catalog
    "provider_request_id":    str | None,          # provider-assigned request ID
    "latency_ms":             int,                 # round-trip latency in ms
    "retry_count":            int,                 # retry count before final result
    "outcome_kind":           str,                 # "allowed" | "error"
    "error_code":             str | None,          # classified error class or None
    "error_detail":           str | None,          # sanitized, redacted error detail
}
```

---

## 6. Policy Schema 📋 PROPOSED

### Proposed `policies` table

```sql
-- PROPOSED: not yet implemented
CREATE TABLE policies (
    id          UUID    PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT    NOT NULL UNIQUE,
    action      TEXT    NOT NULL,    -- "deny" | "escalate" | "allow"
    description TEXT,
    rule_text   TEXT    NOT NULL,    -- human-readable rule description
    embedding   VECTOR(1536),        -- pgvector semantic embedding
    active      BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### Proposed `policy_versions` table (append-only — Lock 9)

```sql
-- PROPOSED: not yet implemented
CREATE TABLE policy_versions (
    id          UUID    PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id   UUID    NOT NULL REFERENCES policies(id),
    version     INTEGER NOT NULL,
    content     JSONB   NOT NULL,    -- full rule snapshot at this version
    who         TEXT    NOT NULL,    -- named approver key that made the change
    changed_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (policy_id, version)
);
```

> Policy versions are append-only. No row is ever updated or deleted. This is a locked design decision (Lock 9).

---

## 7. Approval Record 📋 PROPOSED

The approval record is a projection over `journal_events`, not a separate table. It combines `gate_requested` and `gate_decided` events for the same `gate_id`.

### Proposed approval projection shape

```python
# PROPOSED view model — output of the inbox projection function
@dataclass
class ApprovalRecord:
    gate_id:       str
    action_id:     str
    run_id:        str
    thread_id:     str
    action_name:   str
    action_kind:   str            # "tool" | "llm"
    action_payload: dict          # may be redacted
    context:       dict
    status:        str            # "pending" | "approved" | "rejected"
    requested_at:  str            # ISO 8601
    decided_by:    str | None     # None if still pending
    decided_at:    str | None
    verdict:       str | None     # "approve" | "deny" | None
    reason:        str | None
```

---

## 8. Execution Result 📋 PROPOSED

```python
# PROPOSED — output shape from SandboxPort / LLM adapter
@dataclass
class ExecutionResult:
    action_id:     str
    outcome_kind:  str           # "allowed" | "error"
    result:        Any | None    # tool return value or LLM response
    error_code:    str | None    # e.g. "timeout", "sandbox_error", "provider_error"
    error_detail:  str | None
    duration_ms:   int
    timed_out:     bool
    cancelled:     bool
```

---

## 9. Action Lifecycle

```
Action proposed by agent node
        │
        ▼
action_requested event journaled  ← write-ahead, idempotent
        │
        ▼
PolicyEngine.evaluate()
        │
        ├── allow ──────────────► sandbox.run() or llm.invoke()
        │                                │
        │                         action_completed journaled
        │                                │
        │                          Allowed(result)
        │
        ├── escalate ────────────► gate_requested journaled
        │                          Pending(gate_request) returned
        │                          run_gated() parks via interrupt()
        │                                │
        │                         Human reviews in inbox UI
        │                                │
        │                         gate_decided journaled
        │                                │
        │                    ┌─── verdict == approve ───────────► sandbox.run() or llm.invoke()
        │                    │                                          │
        │                    │                                    action_completed journaled
        │                    │                                          │
        │                    │                                     Allowed(result)
        │                    │
        │                    └─── verdict == deny ─────────────► action NOT executed
        │                                                         Denied(reason, "human_deny")
        │
        └── deny ───────────────► action_denied journaled
                                   TERMINAL — no approval path
                                   Denied(reason, policy)
```

---

## 10. Telemetry Event Shape 📋 PROPOSED

```python
# PROPOSED — input to the telemetry projection
@dataclass
class TelemetryPoint:
    run_id:              str
    thread_id:           str
    action_id:           str
    action_name:         str
    action_kind:         str          # "tool" | "llm"
    started_at:          str          # ISO 8601
    completed_at:        str | None
    duration_ms:         int | None
    prompt_tokens:       int | None   # LLM only
    completion_tokens:   int | None   # LLM only
    total_tokens:        int | None   # LLM only
    estimated_cost_usd:  float | None # LLM only
    outcome:             str          # "allowed" | "denied" | "pending" | "error"
```

---

## 11. Contract Consistency Rules

1. `Action`, `Outcome`, `GateRequest`, `GateDecision`, `CheckpointInfo` are the **canonical Python types** defined in `models.py`. No module may define its own incompatible variants.
2. Journal event payloads are **JSONB** in Postgres. Python-side serialization must round-trip through `Action` fields without loss.
3. `action_id` is the join key across `journal_events`, approval records, and execution results.
4. `gate_id` is the join key between `GateRequest` and `GateDecision`.
5. All timestamps are UTC (`datetime.now(timezone.utc)` or `TIMESTAMPTZ DEFAULT now()`).
6. Credential-bearing fields (connection strings, API keys) must never appear in journal payloads or log output. See [`SECURITY_MODEL.md`](SECURITY_MODEL.md).
