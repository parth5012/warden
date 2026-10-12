"""Policy engines: the L1/L2 vector policy and L0/L1/L2 layered safety gate.

The L1/L2 engine provides deterministic rules and vector-policy matching.
The layered engine combines static checks, DeBERTa injection scoring, and
Clef risk scoring. Both fail closed for unrecognized or unavailable policy
checks.

The layered engine maps decisions to executor outcomes:
  allow    -> continue to sandbox/LLM
  escalate -> journal gate_requested -> Pending (HITL inbox)
  deny     -> journal denied, TERMINAL (no human override)
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol

from langchain_core.embeddings import Embeddings

from warden.policy.layer_clef import ClefScores, ClefUnavailable, FakeClefClient
from warden.policy.layer_deberta import FakeInjectionScorer, InjectionScorer
from warden.policy.layers_static import action_text, find_static_violation
from warden.models import Action

logger = logging.getLogger("warden.policy")

VERDICT_ALLOW = "allow"
VERDICT_ESCALATE = "escalate"
VERDICT_DENY = "deny"


# ---------------------------------------------------------------------------
# L1 — deterministic rules (no IO, short-circuits the vector search)
# ---------------------------------------------------------------------------

# Terminal, unapprovable: destructive SQL text anywhere in the payload.
_DESTRUCTIVE_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"\bdrop\s+(?:table|database|schema|index|view)",
        r"\bdelete\s+from\b",
        r"\btruncate\s+table\b",
        r"\balter\s+table\b.*\b(?:drop|rename)\b",
        r"rm\s+-rf\b",
    )
)

# Tool names that always cross a human gate when L1 handles them.
RISKY_ACTION_NAMES: frozenset[str] = frozenset(
    {"send_email", "run_shell", "db_write", "make_payment", "upload_file"}
)


@dataclass(frozen=True)
class L1Verdict:
    """L1's answer. `matched=False` defers to L2."""

    verdict: str
    matched: bool
    rule: str = ""


def evaluate_l1(
    action: Action,
    *,
    risky_names: frozenset[str] = RISKY_ACTION_NAMES,
) -> L1Verdict:
    """Fast layer: named risky tools escalate; destructive payloads deny."""
    text = _action_text(action)
    for pattern in _DESTRUCTIVE_PATTERNS:
        if pattern.search(text):
            return L1Verdict(
                verdict=VERDICT_DENY,
                matched=True,
                rule=f"destructive_payload:{pattern.pattern}",
            )
    if action.name in risky_names:
        return L1Verdict(verdict=VERDICT_ESCALATE, matched=True, rule=f"risky_tool:{action.name}")
    return L1Verdict(verdict=VERDICT_ALLOW, matched=False, rule="")


def _action_text(action: Action) -> str:
    """Flatten an action into one searchable string (name + payload values)."""
    parts: list[str] = [action.name]
    for value in action.payload.values():
        if isinstance(value, str):
            parts.append(value)
        else:
            parts.append(str(value))
    return " ".join(parts)


# ---------------------------------------------------------------------------
# L2 — similarity retrieval over a policy store
# ---------------------------------------------------------------------------


class VerdictRule(str):
    """A policy row's verdict: 'allow' | 'escalate' | 'deny'."""


class PolicyVectorStore(Protocol):
    """The only surface L2 needs. pgvector adapter implements this."""

    def search(self, query_embedding: list[float], k: int = 1) -> list[tuple[float, str, str]]:
        """Return [(similarity, policy_id, verdict)] ordered best-first."""
        ...


@dataclass
class InMemoryPolicyStore(PolicyVectorStore):
    """Cosine-similarity store over injected embeddings. Tests + CLI.

    Parth's pgvector adapter is a drop-in third implementation: point
    `search` at DB rows + stored embeddings; this engine is untouched.
    """

    embeddings: Embeddings  # langchain Embeddings (async not needed here)
    _rows: list[tuple[list[float], str, str]] = field(default_factory=list)

    def add_policy(self, policy_id: str, verdict: str, text: str) -> None:
        """Store one policy row with its embedding (repo ships seed rules)."""
        vec = list(self.embeddings.embed_query(text))
        self._rows.append((vec, policy_id, verdict))

    def search(self, query_embedding: list[float], k: int = 1) -> list[tuple[float, str, str]]:
        """Best-matching policies by cosine similarity, ordered best-first."""
        scored: list[tuple[float, str, str]] = []
        for vec, policy_id, verdict in self._rows:
            scored.append((_cosine(query_embedding, vec), policy_id, verdict))
        scored.sort(key=lambda item: item[0], reverse=True)
        return scored[:k]


def _cosine(a: list[float], b: list[float]) -> float:
    """Cosine similarity; zero vectors score -1 (never match)."""
    if not a or not b or len(a) != len(b):
        return -1.0
    dot = float(sum(x * y for x, y in zip(a, b, strict=True)))
    n_a = float(sum(x * x for x in a)) ** 0.5
    n_b = float(sum(y * y for y in b)) ** 0.5
    if n_a == 0.0 or n_b == 0.0:
        return -1.0
    result: float = dot / (n_a * n_b)
    return result


@dataclass(frozen=True)
class L2Verdict:
    """L2's answer. `matched=False` means nothing was similar enough."""

    verdict: str
    matched: bool
    policy_id: str = ""
    similarity: float = 0.0


def evaluate_l2(
    action: Action,
    store: PolicyVectorStore,
    embeddings: Embeddings,
    *,
    threshold: float = 0.8,
) -> L2Verdict:
    """Similarity layer: most-similar stored policy decides if close enough.

    Below threshold (or an empty store) -> NOT matched; the caller decides
    the fallback. `L1L2PolicyEngine` fails this case CLOSED to escalate.
    A stored verdict that is not one of the three seam verdicts is treated
    as an unmatched policy (fail-closed) — garbage rows can never authorize.
    """
    query = list(embeddings.embed_query(_action_text(action)))
    hits = store.search(query, k=1)
    if not hits:
        return L2Verdict(verdict=VERDICT_ESCALATE, matched=False)
    similarity, policy_id, verdict = hits[0]
    if verdict not in (VERDICT_ALLOW, VERDICT_ESCALATE, VERDICT_DENY):
        logger.warning(
            "policy.l2.invalid_verdict",
            extra={"policy_id": policy_id, "verdict": verdict},
        )
        return L2Verdict(verdict=VERDICT_ESCALATE, matched=False, policy_id=policy_id, similarity=similarity)
    if similarity < threshold:
        logger.info(
            "policy.l2.below_threshold",
            extra={"policy_id": policy_id, "similarity": round(similarity, 3), "threshold": threshold},
        )
        return L2Verdict(verdict=VERDICT_ESCALATE, matched=False, policy_id=policy_id, similarity=similarity)
    logger.info(
        "policy.l2.match",
        extra={"policy_id": policy_id, "similarity": round(similarity, 3), "verdict": verdict},
    )
    return L2Verdict(verdict=verdict, matched=True, policy_id=policy_id, similarity=similarity)


# ---------------------------------------------------------------------------
# The seam-facing engine
# ---------------------------------------------------------------------------


class L1L2PolicyEngine:
    """Drop-in replacement for `SequencingPolicy` (same evaluate contract).

    Order of authority (recorded decision):
      1. L1 matched       -> L1 verdict is FINAL (deny stays deny, lock 5;
                             an L1 escalate never overruled by vectors).
      2. L2 matched       -> the stored policy's verdict applies.
      3. Nothing matched  -> ESCALATE (fail-closed: unrecognized actions
                             reach a human, never plain allow).
    """

    def __init__(
        self,
        embeddings: Embeddings,
        store: PolicyVectorStore | None = None,
        *,
        threshold: float = 0.8,
        risky_names: frozenset[str] | None = None,
    ) -> None:
        self._store = store if store is not None else InMemoryPolicyStore(embeddings)
        self._embeddings = embeddings
        self._threshold = threshold
        self._risky_names = risky_names if risky_names is not None else RISKY_ACTION_NAMES

    @property
    def store(self) -> PolicyVectorStore:
        """The underlying vector store (Parth's pgvector adapter plugs here)."""
        return self._store

    def evaluate(self, action: Action) -> str:
        """The seam's contract: 'allow' | 'escalate' | 'deny'."""
        l1 = evaluate_l1(action, risky_names=self._risky_names)
        if l1.matched:
            logger.info(
                "policy.l1.final", extra={"rule": l1.rule, "verdict": l1.verdict, "action": action.name}
            )
            return l1.verdict

        l2 = evaluate_l2(action, self._store, self._embeddings, threshold=self._threshold)
        if l2.matched:
            return l2.verdict

        # Nothing recognized -> human review. Never silently allow.
        logger.info(
            "policy.unrecognized.escalate", extra={"action": action.name, "action_id": action.id}
        )
        return VERDICT_ESCALATE


# ---------------------------------------------------------------------------
# Test/seed embeddings helper — deterministic, no network
# ---------------------------------------------------------------------------


class HashEmbeddings(Embeddings):
    """Deterministic, dependency-free embedder for tests and offline demo.

    Token-hashing bag-of-words into a fixed-dim vector; NOT semantic —
    tests control similarity via shared vocabulary. Production wires a
    real embedder (OpenAI/HF) or Parth's pgvector-side embeddings.
    """

    def __init__(self, dim: int = 64) -> None:
        self._dim = dim

    def _embed(self, text: str) -> list[float]:
        vec = [0.0] * self._dim
        import hashlib

        for token in re.findall(r"\w+", text.lower()):
            digest = hashlib.sha256(token.encode()).digest()
            idx = int.from_bytes(digest[:4], "big") % self._dim
            sign = 1.0 if digest[4] % 2 == 0 else -1.0
            vec[idx] += sign
        return vec

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return [self._embed(t) for t in texts]

    def embed_query(self, text: str) -> list[float]:
        return self._embed(text)


class PolicyDecision(str, Enum):
    ALLOW = "allow"
    ESCALATE = "escalate"
    DENY = "deny"


class PolicyError(RuntimeError):
    """Layer infrastructure failed. Caller must fail closed."""


@dataclass(frozen=True)
class PolicyVerdict:
    decision: PolicyDecision
    reason: str
    policy: str
    layer: str
    scores: dict[str, float]


@dataclass
class PolicyEngine:
    deny_threshold: float = 0.85
    clean_threshold: float = 0.20
    scorer: InjectionScorer | None = None
    clef: FakeClefClient | object = None

    def __post_init__(self) -> None:
        if self.scorer is None:
            self.scorer = FakeInjectionScorer()
        if self.clef is None:
            self.clef = FakeClefClient()

    def evaluate(
        self,
        action_name: str,
        payload: dict[str, object],
        role: str = "operator",
    ) -> PolicyVerdict:
        text = action_text(action_name, payload)

        # L0 — static deny list.
        if (policy_id := find_static_violation(text)) is not None:
            return PolicyVerdict(
                decision=PolicyDecision.DENY,
                reason=f"static rule matched: {policy_id}",
                policy=policy_id,
                layer="L0-static",
                scores={},
            )

        # L1 — DeBERTa injection score.
        assert self.scorer is not None
        try:
            injection = self.scorer.score(text)
        except RuntimeError as exc:
            raise PolicyError(f"L1 deberta unavailable: {exc}") from exc
        if injection.score >= self.deny_threshold:
            return PolicyVerdict(
                decision=PolicyDecision.DENY,
                reason=f"prompt injection p={injection.score:.2f}",
                policy="prompt-injection",
                layer="L1-deberta",
                scores={"injection": injection.score},
            )
        if injection.score <= self.clean_threshold:
            l1_clean = injection.score
        else:
            l1_clean = injection.score  # uncertain band -> consult L2 below

        # L2 — Clef privilege / side-effect / injection re-check.
        try:
            # mypy: clef adapters share judge() shape; typed as object-safe call.
            judge = getattr(self.clef, "judge")
            scores: ClefScores = judge(
                state=text, tool=action_name,
                args=str(payload.get("args", payload)), role=role,
            )
        except ClefUnavailable as exc:
            raise PolicyError(f"L2 clef unavailable: {exc}") from exc

        worst = max(scores.injection, scores.privilege_creep, scores.side_effect)
        merged = {
            "l1_injection": l1_clean,
            "clef_injection": scores.injection,
            "privilege_creep": scores.privilege_creep,
            "side_effect": scores.side_effect,
        }
        if worst >= self.deny_threshold:
            return PolicyVerdict(
                decision=PolicyDecision.DENY,
                reason=f"clef risk p={worst:.2f} ({scores.model})",
                policy="clef-risk",
                layer="L2-clef",
                scores=merged,
            )
        if worst <= self.clean_threshold and l1_clean <= self.clean_threshold:
            return PolicyVerdict(
                decision=PolicyDecision.ALLOW,
                reason="L1 clean + Clef clean",
                policy="default-allow",
                layer="L2-clef",
                scores=merged,
            )
        return PolicyVerdict(
            decision=PolicyDecision.ESCALATE,
            reason=f"uncertain risk p={worst:.2f} needs human",
            policy="uncertain-hitl",
            layer="L2-clef",
            scores=merged,
        )
