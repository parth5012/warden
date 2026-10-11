# Warden — Security Model

> Trusted and untrusted inputs, enforcement posture, threat model, and unresolved risks.

---

## 1. Core Security Posture

Warden's security is built on three principles:

1. **One seam.** Every action crosses `GuardedExecutor.execute()`. There is no bypass.
2. **Fail-closed.** If the governance infrastructure is unavailable, actions are blocked, not allowed.
3. **DENY is terminal.** A policy denial cannot be overridden by any human (Lock 5).

---

## 2. Trust Zones

### Untrusted Inputs

| Source | Risk |
|---|---|
| LLM model outputs (tool arguments, plans) | May contain adversarial payloads, prompt injection, or attempts to call prohibited tools |
| User-supplied instructions | May attempt to bypass policy via clever phrasing |
| Tool payloads (file paths, SQL, shell commands) | May contain path traversal, SQL injection, shell escape sequences |
| External API responses | May contain malicious data that the agent acts on |

All of these enter the system as the `payload` field of an `Action`. The `GuardedExecutor` and `PolicyEngine` treat them as untrusted.

### Trusted Inputs

| Source | Why trusted |
|---|---|
| Named approver keys (`Warden-Key` header) | Configured in environment, principal is logged in journal |
| Policy rules in Postgres | Loaded from controlled DB; changes are versioned and audited |
| Seed policies from repo | Loaded on first boot from controlled source |

### Internal Boundary

- `warden/` code runs in the governance kernel and is considered trusted relative to agent inputs.
- `agents/` code produces `Action` objects, which are untrusted payloads that must cross the seam.
- The seam itself (`execute()`) is trusted to enforce policy.

---

## 3. Tool Execution Boundary

### What crosses the seam

Every tool call must be represented as an `Action(kind=ActionKind.TOOL)`. No agent node may call a tool directly without going through `execute()`.

### Subprocess sandbox scope (Lock 7)

```
Tool kind        Adapter           Restrictions
──────────────   ───────────────   ──────────────────────────────────
run_shell        subprocess        Timeout enforced, env scrubbed
run_code         subprocess        Timeout enforced, env scrubbed
write_file       subprocess        Timeout enforced, env scrubbed
read_file        subprocess        Timeout enforced, env scrubbed
send_email       in-process        Provider allowlist, no subprocess
call_api         in-process        Provider allowlist, no subprocess
```

> ⚠️ **Subprocess is not a complete security sandbox.** It limits execution time and removes environment variables, but it does not provide:
> - Filesystem isolation (the subprocess can still read/write the filesystem)
> - Network isolation (the subprocess can still make network calls)
> - Memory limits
> - Container-level process isolation
>
> For Phase 1 this is acceptable. A Docker/gVisor adapter would be added only if judges or production requirements demand it.

### Environment scrubbing

The subprocess adapter must clear or replace the following before launching a subprocess:

```python
# PROPOSED scrubbed variables
SCRUBBED_ENV_VARS = {
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "WARDEN_APPROVER_KEYS",
    "WARDEN_PG_URI", "DATABASE_URL", "AWS_SECRET_ACCESS_KEY",
    "AWS_ACCESS_KEY_ID", "GOOGLE_API_KEY",
    # ... any key matching *_KEY, *_SECRET, *_TOKEN, *_PASSWORD
}
```

The subprocess receives a minimal environment: `PATH`, `HOME`, `TMPDIR` only (unless the tool explicitly requires more, which must be documented).

---

## 4. Policy Enforcement

### Deny-by-default

The `PolicyEngine` must deny any action for which no matching policy rule exists. This prevents gaps in policy coverage from accidentally allowing actions.

### Policy decision is not advisory

The policy decision (`allow` / `escalate` / `deny`) is enforced by `GuardedExecutor`. The agent receives only the `Outcome` — it cannot observe the intermediate policy decision and attempt to route around it.

### DENY is terminal (Lock 5)

Once a policy decision of `deny` is returned:
- `action_denied` is journaled.
- `Denied(reason, policy)` is returned from `execute()`.
- The action is **never executed**.
- No human can approve it.
- The only way to change this outcome is to edit the policy rule (which is versioned and audited).

This is enforced at the code level — `execute()` must not have any code path that calls `sandbox.run()` or `llm.invoke()` after receiving `deny`.

---

## 5. Human Approval (HITL) — Security Constraints

### Approval only applies to `escalate`

Human approval is only meaningful when the policy decision is `escalate`. A `deny` cannot be escalated.

### Approver identity (Lock 8)

- Approvers are identified by `Warden-Key: <key>` HTTP header.
- Keys are stored in environment variables (`WARDEN_APPROVER_KEYS=alice:key1,bob:key2`).
- The key is never logged or stored. The principal (`alice`) is journaled with the decision.
- This is a demonstration mechanism, not production authentication.

**Open risk:** Named keys in environment variables are not rotatable, do not support multi-factor authentication, and do not prevent key sharing. This is documented and accepted for the hackathon demo.

### Approval record integrity

The `gate_decided` journal event is the evidence of a decision. It is append-only and cannot be modified. If a gate decision is tampered with at the database level, there is no cryptographic detection (hash chaining is documented as a proposed extension, not implemented).

### Duplicate submission

A gate can only be decided once. A second `POST /gates/{gate_id}/decision` must return `409 Conflict`. The API must check the journal for an existing `gate_decided` event before accepting a new decision.

---

## 6. Audit Integrity

### Append-only journal

The `journal_events` table must never be updated or deleted. Any code that modifies existing rows is a bug.

### Write-ahead intent

`action_requested` is journaled **before** the policy is evaluated and before any side effect occurs. This ensures:
- Even if the process is killed after journaling but before execution, the intent is recorded.
- On restart, the system can detect "intent was recorded but outcome unknown" and flag the action for review.

### Secret redaction

No credential, connection string, API key, or personal information may appear in journal payloads or log output.

The `_redact()` function in `checkpoint.py` handles connection strings. All other secrets must be excluded from `Action.payload` before the action is constructed. The agent must never include an API key in a tool payload.

Verified redaction cases:
- URI userinfo (username + password)
- Malformed password containing `@`
- Keyword-DSN `password=...` form
- Quoted keyword-DSN passwords
- `@` in query string (must not be incorrectly masked)

---

## 7. LLM Protection

### LLM calls cross the seam

Every call to an LLM model must be represented as `Action(kind=ActionKind.LLM)` and must pass through `execute()`. This is Lock 1 — it is what makes telemetry and decision-graph possible without a second logging path.

### Prompt injection risk

An LLM receiving adversarial content (e.g. in a tool result or user message) may be manipulated into proposing a malicious action. The policy engine is the defense: the resulting `Action` must still pass policy evaluation before execution.

Warden does not implement prompt-level input sanitization. This is an acknowledged gap.

### Provider allowlist

The LLM adapter must refuse to call a provider not in the configured allowlist. An action targeting an unlisted provider returns `Error("unlisted_provider")`.

---

## 8. Threat Model

| Threat | Mitigation | Gap |
|---|---|---|
| LLM proposes `DROP TABLE` | Policy denies it (terminal, journaled) | None |
| LLM proposes `rm -rf /` | Sandboxed subprocess with timeout | No FS isolation |
| LLM leaks a secret in payload | Redaction required before `Action` construction | Agent must not include secrets |
| Attacker reuses a stale approval | `409 Conflict` on duplicate gate decision | Clock skew / expiration not implemented |
| Attacker submits approval with invalid key | `401 Unauthorized` | Keys in env — not rotatable |
| Journal row modified at DB level | Append-only constraint | No hash chaining / tamper detection |
| Projection failure corrupts source data | Projections are read-only | None |
| Infrastructure outage allows action to slip through | Fail-closed: `Error("governance_unavailable")` | None |
| Prompt injection in tool result | Policy evaluates the *action*, not the prompt | No prompt sanitization |

---

## 9. Unresolved Risks

The following risks are explicitly acknowledged and not mitigated in Phase 1:

1. **Subprocess has no filesystem or network isolation.** A malicious shell command can read local files or make network calls within the timeout window.
2. **Named-key authentication is not real auth.** Keys in environment variables are not rotatable and do not support MFA.
3. **No approval expiration.** A pending gate request does not expire. It can be approved arbitrarily late.
4. **No hash chaining in journal.** Database-level tampering of audit events is undetectable.
5. **No prompt sanitization.** Adversarial content in tool results can influence subsequent LLM calls.
6. **`external side effect uncertainty after crash.`** If a process is killed after an action begins execution but before `action_completed` is journaled, the system cannot determine whether the side effect completed. Operators must manually verify.

Each risk must be reviewed before any production deployment of Warden.
