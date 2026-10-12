# DECISIONS.md — Warden

One entry per decision that reopens, amends, or adds to the locks in `CONTEXT.md`. Pre-map locks 1–12 remain recorded in `CONTEXT.md`; this file starts from the first reopen (2026-10-11).

---

## 1. Lock 7 reopened — Docker is the only containment adapter (2026-10-11)

**Status:** Accepted. **Reopens:** lock 7 ("One sandbox port, adapter routes itself" — subprocess for code/shell/file tools).

**Decision.** The subprocess adapter is dropped. Everything the sandbox runs goes through Docker: `--network=none`, read-only rootfs, tmpfs scratch, 30s / 256MB / 1 CPU caps, `--rm`, single bind mount (configured workspace dir, default `D:\tmp\`). API tools stay in-process.

**Context.** The sandbox slice was extended to promise *network isolation* of tool execution. On Windows there are no network namespaces available to a bare subprocess — a genuine egress kill requires a container (or a Linux VM). Subprocess + scrubbed env + timeout cannot honestly claim "no network."

**Alternatives considered.**
- *Keep subprocess, weaken the claim to "network isolation best-effort"* — rejected: a governance product cannot ship a containment promise it can't keep; judges (and threat models) read "best-effort" as a hole.
- *Keep Docker parked until judges demand it* — rejected: the demand arrived as a product requirement (network isolation), not a demo flourish.
- *Linux VM per tool call* — rejected: heavyweight, slow, far beyond hackathon scope; Docker already installed (Docker Desktop 29.6.2, WSL2 backend).

**Consequences.**
- `SandboxPort` interface unchanged: `run(action) -> SandboxResult`, async; one exception type `SandboxUnavailable` for daemon-down / missing image / unknown tool profile (fail-closed; executor maps to `Error(governance_unavailable)`).
- Tool → execution profile mapping lives in a registry *inside* the sandbox package; the future GuardedExecutor classifier decides *whether* to sandbox, the sandbox decides *how*.
- Execution mode per profile: `exec` (argv, default) or `shell` (`sh -c` inside container, shell tool only). Host side always argv to `docker`, no shell, ever.
- Unknown tool profile → `SandboxUnavailable` (refuse, never run unprofiled), overriding an earlier C′ "default-strict profile" proposal — see wayfinder map notes.
- Separate decisions recorded alongside: 30s/256MB/1CPU defaults, `D:\tmp\` as the single accessible host folder, shared-across-runs noted as Phase-1 accepted risk.

**Maps to:** wayfinder map "Network isolation & sandboxed tool execution service" (GitHub issues, `wayfinder:map`).

---

## 2. Layered Policy Engine Architecture: L0 Static + L1 DeBERTa + L2 Granite Guardian (2026-10-12)

**Status:** Accepted. **Complements:** lock 5 ("DENY is terminal"), lock 1 ("Both tool and LLM calls cross the seam"), lock 4 ("Fail-closed").

**Decision.**
`PolicyEngine.evaluate(action, ctx)` evaluates actions through a tiered 3-layer architecture:
1. **L0 Deterministic Static Analysis (<1ms):** In-process AST parsers (`sqlglot`, `bashlex`), path traversal checks, and sensitive key regex. Instant `DENY` or rule-driven `ESCALATE`.
2. **L1 Discriminative Fast Filter (10–25ms):** Sequence classification (`deberta-v3-small` / prompt-injection tuned checkpoint via ONNX Runtime). High-confidence attacks (score >= 0.85) immediately trigger terminal `DENY`. Benign read-only tools (score < 0.20) fast-path `ALLOW` bypassing L2.
3. **L2 Generative Semantic Reasoner (80–150ms):** IBM Granite Guardian (`granite-guardian-3.1-2b` or `8b` via vLLM/Triton sidecar). Evaluates semantic intent, agent role authorization, and destructive side-effects. Emits `ALLOW`, `DENY`, or `ESCALATE` (HITL approval).

**Context.**
Static rules alone miss contextual prompt injection, natural language jailbreaks, and authorization drift. Heavy LLMs alone introduce excessive latency (>150ms) and token expense on benign read-only operations. A tiered pipeline provides sub-millisecond rejection for known bad patterns, fast-path approvals for safe reads, and reserves deep model inference for mutating or ambiguous calls.

**Alternatives considered.**
- *Pure Static Rules (Regex + AST only):* Rejected. Fails against semantic jailbreaks and subtle privilege creep in agentic tool arguments.
- *LLM / Granite-only Evaluation:* Rejected. Adding 100–300ms to every tool call, including safe queries, bottlenecks agent throughput and inflates inference costs.
- *Upstream Proxy / Gateway (outside GuardedExecutor):* Rejected. Violates Lock 1 (single seam) and Lock 3 (write-ahead journal idempotency before execution).

**Consequences.**
- Model evaluation runs inside `policy.evaluate()` or via a local inference sidecar container; Warden kernel remains lightweight Python without direct PyTorch dependencies.
- Fail-closed invariant preserved: Sidecar timeout or crash returns `Error("governance_unavailable")`.
- Terminal DENY invariant preserved: Any layer issuing `deny` immediately appends `action_denied` to `AuditJournal` and aborts.
- Documented in `docs/LAYERED_SAFETY_ARCHITECTURE.md`.
