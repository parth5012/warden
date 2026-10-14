# Warden USP — What Is Actually Different, and How to Sell It

> Date: 2026-10-14. Source: competitive deep-research + internal audit of
> `CONTEXT.md` locks, `DECISIONS.md`, `ARCHITECTURE.md`, `docs/SECURITY_MODEL.md`.
> Status: strategy + proof plan. Numbers marked "target/measure" are NOT yet benchmarked —
> do not quote them externally until measured (see §5).

## One-sentence pitch

> Other harnesses watch what agents did. Warden decides what agents may do — and can prove it.

Tagline options:

- `The execution seam agents can't bypass.`
- `Observability tells you what happened. Warden decides what may happen.`
- `HITL without rubber stamps.`

---

## 1. The 7 real differentiators (ranked by defensibility)

### 1. One seam for `tool + llm` (CONTEXT lock 1)

Graph nodes never call a model or tool directly. Both cross
`GuardedExecutor.execute(action, ctx) -> Allowed | Denied | Pending | Error`.
Telemetry + decision graph are pure journal projections — no join against
callback logs.

Why competitors miss it: NeMo, Guardrails AI, Lakera, Portkey govern LLM
*text*. HumanLayer decorates *tools*. LangSmith/Langfuse only trace *after
the fact*. All of them leave the classic two-pipeline lie open (telemetry
says X, enforcement did Y). Warden kills it by construction.

Evidence: `src/warden/executor.py`, `src/warden/models.py` (`Action.kind ∈ {tool, llm}`).

### 2. `Pending` as data, not exception (CONTEXT lock 2)

`execute()` returns `Pending(gate_request)` explicitly. Park logic lives ONCE
in the HITL re-entry path — no invisible `interrupt()` inside the seam that a
broad `except Exception` can swallow (contrast LangGraph `interrupt()`).

Provable: kill mid-park, resume, no duplicate side effect via
`(run_id, action_id)` idempotency key.

Evidence: `src/warden/executor.py`, `tests/test_checkpoint.py` (park/resume,
manager-restart recovery, no-duplicate-output).

### 3. Write-ahead + checkpointer split (CONTEXT lock 3)

Checkpointer = where parked + resume value (LangGraph owns). Journal = what
happened, forever. Inbox reads the journal, never parses checkpoint state.
`action_requested` is appended *before* the gate.

No competitor does this: LangSmith has traces but no control; Temporal has
durable control but no governance evidence; Portkey Gateway has logs but no
park/resume. LangSmith Gateway (launched May 2026) couples policy + traces in
SaaS but owns neither the tool-execution context nor the resume path.

Evidence: `src/warden/journal.py` (write-ahead, SHA-256 hash chain,
`(run_id, action_id, kind)` dedup), `src/warden/checkpoint.py`.

### 4. DENY is terminal + fail-closed (CONTEXT locks 4+5)

`deny` can never be approved by any human. Wrong rule → edit the versioned
policy, audited. `Error(governance_unavailable)` is distinct from `Denied`:
store/sidecar down → block, not allow.

Contrast: HumanLayer lets any human approve anything (rubber-stamp risk);
network gateways fail open for availability. This is the EU AI Act / SOC 2
story: `approver: alice` must be a true statement in the journal.

Evidence: `src/warden/executor.py` (terminal-deny, fail-closed branches),
`tests/test_executor.py` (deny non-overridable, fail-closed error paths).

### 5. Policy + sandbox in the same transaction (DECISIONS #1, lock 7 reopened)

Docker-only containment: `--network=none`, read-only rootfs, 256MB / 1 CPU /
30s caps, tmpfs scratch, single bind mount, `--rm`. API tools stay in-process;
code/shell/file tools always go through the container.

NeMo / Portkey / HumanLayer / Langfuse have zero execution containment.
E2B / Daytona have containment but zero policy. Only Warden does
`policy.evaluate → sandbox.run → journal.append` atomically per action.

Evidence: `src/warden/sandbox/`, `scripts/demo_tools.py` beat 4 (sandbox route),
audit probe note (DockerSandbox net-none containment proven live).

### 6. Tiered L0/L1/L2 policy (DECISIONS #2)

- L0 static AST/regex, target `<1ms`.
- L1 DeBERTa-v3 ONNX, target `10–25ms`; high-confidence attack → terminal DENY,
  benign read-only fast-paths to ALLOW, skipping L2.
- L2 Granite Guardian, target `80–150ms`, for mutating/ambiguous calls only.

NeMo runs ~5 guardrails in parallel (~500ms claim) on everything; LLM-only
evaluators tax even safe reads. Warden design target: safe reads ~12ms,
mutations ~110–130ms. **Targets only — benchmark not yet run (see §5).**

Evidence: `src/warden/policy/` (`layers_static.py`, `layer_deberta.py`,
`layer_clef.py`, `engine.py`), `docs/LAYERED_SAFETY_ARCHITECTURE.md`.

### 7. Policies in DB — one store tells the story (CONTEXT lock 9)

`journal_events + policies + policy_versions` (append-only: who/when/what) +
pgvector live in the same Postgres. Seed loaded on boot, then DB owns truth.

NeMo: YAML/Colang files, no who-changed audit. Portkey: dashboard configs, no
version evidence. LangSmith Gateway: policies in SaaS UI, SaaS-locked.

Evidence: lock 9 + `policy_versions` guardrail; pgvector index beside the rows
(no file-sync pipeline).

Cheap dev moat (not a USP alone, but compounds): kernel `warden/` imports
nothing from `app/agents`; Jinja + HTMX single process, no build step;
JSON-clean endpoints so React can lift later; local-first
(`uv sync`, `pgserver` auto-starts, `pytest` green, mypy strict) — self-hostable,
no SaaS key, no YAML DSL to learn.

---

## 2. Competitor map — why each loses

| Competitor | What it is | What it misses vs Warden |
|---|---|---|
| LangSmith + LLM Gateway (2026) | Observe + evaluate + deploy + runtime gateway. Closest rival. | SaaS-locked, LLM-centric, no tool sandbox, no DENY-terminal, no write-ahead evidence split. Policy fires without tool-execution context. |
| Langfuse / Braintrust / Arize | Observability + evals. | Post-hoc. Cannot preempt. No HITL park, no deny enforcement. |
| NVIDIA NeMo Guardrails | Input/output rails, Nemotron NIMs. | Content safety only. No tool-execution seam, no HITL inbox, no journal idempotency; Colang/YAML not audited. (NeMo Platform migration; Microservices sunset Oct 2026.) |
| Guardrails AI / Lakera / Patronus | Validators / prompt-threat decisions. | LLM-text validators. No sandbox, no cost telemetry, no approvals with identity. |
| HumanLayer (YC) | `@require_approval()` decorator + Slack/SMS/email HITL. | HITL only. No policy engine, no deny-terminal, no sandbox, no telemetry, no audit journal. Any approval overrides anything. (Since pivoted toward coding IDE/cloud.) |
| Portkey (+ MCP / Agent Gateway) | 250+ model router + guardrails + observability. | Network-layer gateway. No LangGraph park/resume, no Docker containment, no layered intent check (role vs `user_intent`). |
| CrewAI / AutoGen / Microsoft Agent Framework | Orchestration. | No governance kernel. Rely on Foundry/LangSmith add-ons. |
| Akka Verify / Credo / watsonx | Eval + governance SaaS. | Heavyweight enterprise SaaS, no code-seam library story. |

Warden wedge: **in-process library + local Postgres + Docker, not a SaaS proxy.**
You don't re-point `base_url`. You run *through*.

---

## 3. How to sell — three pitches

### Judge 90s (demo beats, cf. `ARCHITECTURE.md` §9)

1. `email report` → gated → approve as `alice` → timeline
   `requested → decided(approve, alice) → completed`.
2. `DROP TABLE` → red card: `Denied, not approvable`.
3. `rm -rf` → contained, network-none logged.
4. `kill -9` mid-park → restart → resume, nothing lost; dashboard fills live
   tokens / cost / latency.

Runnable today: `scripts/governed_demo.py` (2 governed agents, 34-event
hash-chained journal, timeline render), `scripts/demo_tools.py` (4 beats:
ALLOW / Pending / DENIED / sandbox-route). Playwright E2E for the 4 beats is
still TODO.

### Enterprise (accountability)

> Every high-stakes action has admitted-under-what-authority plus replayable
> evidence. DENY can't be clicked through. Policy edits are versioned
> who/when. One Postgres tells auditors the whole story. Try that with a
> gateway log plus a Slack approval.

Maps to EU AI Act logging / human-oversight and SOC 2 change-management
expectations. Do not claim certification — claim *evidence shape*.

### Developer (integration)

`BaseAgent` + registry, 3 lines to route through the seam, local
`uv sync`, `pgserver` auto-starts, `pytest` green, mypy strict. No SaaS key,
no YAML DSL, no second observability surface.

---

## 4. Honest current state (read before pitching)

- Core seam pieces now exist on this branch: `src/warden/executor.py`
  (`GuardedExecutor`), `src/warden/journal.py` (`AuditJournal` +
  `InMemoryJournal`), `src/warden/policy/`, `src/warden/sandbox/`,
  `src/warden/tools/` (+ router), `scripts/governed_demo.py`,
  `tests/test_executor.py`. Full suite green per `LOG.md` 2026-10-12
  (234 passed, 6 skipped; mypy strict clean). **Note:** root `STATUS.md` still
  says these are "NOT built" — it is stale (last updated 2026-10-11) and needs
  a refresh pass.
- Still Postgres-`JournalStore` wiring vs in-memory, FastAPI approvals inbox
  on live journal, and Playwright E2E remain work-in-progress — verify before
  demoing as "done".
- `docs/SECURITY_MODEL.md` §9 risks still apply: no hash-chain tamper
  detection beyond the journal chain, no approval expiry, named-keys are not
  real auth, no prompt sanitization. Disclose them — judges trust honesty +
  fail-closed design over perfect-security claims.
- Naming leftover: `Aegis` references in `AUDIT_LOG.md` /
  `AGENT_INTEGRATION.md` predate the Warden rename (lock 11) — clean up before
  selling.

---

## 5. How to prove — artifacts, not claims

1. **Live demo script** (`ARCHITECTURE.md` §9): must run end-to-end. Playwright
   E2E for the 4 beats is the load-bearing proof — still TODO.
2. **Containment proofs**: network-none, read-only rootfs, timeout kill, zero
   leftover containers. Keep a skip-gate for CI without a daemon, but show
   video with a daemon.
3. **Journal dump**: one run's `journal_events` rows —
   `action_requested (run, action, kind) → gate_requested →
   gate_decided(alice) → action_completed` — plus duplicate resume =
   idempotent no-op.
4. **Latency table (TODO — do not quote yet)**: measure L0 `<1ms`, L1 `~15ms`,
   L2 `~120ms`, fast-path vs full-path, vs NeMo 5-rails ~500ms claim. This is
   the cost-USP number once measured.
5. **Decision graph**: journal events joined to checkpoint steps. Competitors
   can't show this because they don't own both.
6. **Policy-version demo (Phase 2)**: change a rule live → next action behaves
   differently; `policy_versions` shows who/when.

Next load-bearing proof order: Phase-1 green (`pytest` + kill-9 replay +
Docker proofs) → latency benchmark with published numbers → journal-dump +
decision-graph screenshots in the deck. That turns narrative USP into
measured USP.

---

## 6. Recommended USP ladder (README / deck order)

1. One seam for tools + LLM.
2. DENY-terminal + fail-closed.
3. Write-ahead evidence + park/resume split.
4. Policy + sandbox in one call.
5. Tiered policy = cheap + fast.
6. One DB = audit + versions + vectors.
7. Local-first library, not SaaS gateway.
