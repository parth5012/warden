"""Domain types for the Guarded LLM Client in Warden.

Includes token usage buckets, pricing records, rate-limiting configs,
budget constraints, and telemetry event models.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from typing import Any


class TokenUsageSource(str, Enum):
    """Source of token count values."""
    PROVIDER_REPORTED = "provider_reported"
    ESTIMATED = "estimated"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class NormalizedUsage:
    """Mutually-exclusive token accounting buckets.

    Guarantees no double-counting across cached, reasoning, and standard tokens:
    - prompt_tokens = input_uncached_tokens + input_cached_tokens
    - completion_tokens = output_standard_tokens + output_reasoning_tokens
    - total_tokens = input_uncached_tokens + input_cached_tokens + output_standard_tokens + output_reasoning_tokens
    """

    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    input_uncached_tokens: int
    input_cached_tokens: int = 0
    output_standard_tokens: int = 0
    output_reasoning_tokens: int = 0
    source: TokenUsageSource = TokenUsageSource.PROVIDER_REPORTED
    raw_usage: dict[str, Any] = field(default_factory=dict)

    @property
    def is_reported(self) -> bool:
        return self.source == TokenUsageSource.PROVIDER_REPORTED

    @property
    def is_estimated(self) -> bool:
        return self.source == TokenUsageSource.ESTIMATED

    def to_dict(self) -> dict[str, Any]:
        return {
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "input_uncached_tokens": self.input_uncached_tokens,
            "input_cached_tokens": self.input_cached_tokens,
            "output_standard_tokens": self.output_standard_tokens,
            "output_reasoning_tokens": self.output_reasoning_tokens,
            "source": self.source.value,
        }


@dataclass(frozen=True)
class CostRecord:
    """Precision-safe cost record in Decimal USD."""

    calculated_cost: Decimal | None
    estimated_cost: Decimal | None
    currency: str
    pricing_version: str
    model: str
    provider: str
    matched_pattern: str | None = None
    is_exact_match: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "calculated_cost_usd": float(self.calculated_cost) if self.calculated_cost is not None else None,
            "estimated_cost_usd": float(self.estimated_cost) if self.estimated_cost is not None else None,
            "currency": self.currency,
            "pricing_version": self.pricing_version,
            "model": self.model,
            "provider": self.provider,
            "matched_pattern": self.matched_pattern,
            "is_exact_match": self.is_exact_match,
        }


@dataclass(frozen=True)
class LLMRequest:
    """Standardized LLM invocation request crossing the client seam."""

    model: str
    messages: list[dict[str, Any]]
    provider: str = "openai"
    max_tokens: int | None = None
    temperature: float | None = None
    timeout_s: float = 30.0
    extra_params: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class LLMResponse:
    """Standardized LLM invocation response."""

    content: str
    model: str
    provider_request_id: str | None = None
    raw_response: Any = None
    usage_metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class BudgetConfig:
    """Budget constraints for request and run-level token & cost limits."""

    max_input_tokens_per_request: int | None = None
    max_output_tokens_per_request: int | None = None
    max_total_tokens_per_request: int | None = None
    max_spend_per_request: Decimal | None = None
    max_spend_per_run: Decimal | None = None


@dataclass(frozen=True)
class RateLimitConfig:
    """Local concurrency, throttling, and retry configuration."""

    max_requests_per_minute: int = 60
    max_tokens_per_minute: int = 100_000
    max_concurrent_requests: int = 5
    max_retries: int = 3
    initial_backoff_s: float = 0.5
    max_backoff_s: float = 10.0
    backoff_multiplier: float = 2.0
    timeout_s: float = 30.0


@dataclass(frozen=True)
class LLMUsageTelemetry:
    """Telemetry record for AuditJournal and downstream projections.

    Never logs sensitive prompts, keys, or response bodies.
    """

    action_id: str
    run_id: str
    thread_id: str
    provider: str
    model: str
    usage: NormalizedUsage
    cost: CostRecord | None
    latency_ms: int
    retry_count: int
    outcome_kind: str
    provider_request_id: str | None = None
    error_code: str | None = None
    error_detail: str | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_journal_payload(self) -> dict[str, Any]:
        """Generate payload for 'llm_usage' journal event."""
        return {
            "action_id": self.action_id,
            "provider": self.provider,
            "model": self.model,
            "prompt_tokens": self.usage.prompt_tokens,
            "completion_tokens": self.usage.completion_tokens,
            "total_tokens": self.usage.total_tokens,
            "input_uncached_tokens": self.usage.input_uncached_tokens,
            "input_cached_tokens": self.usage.input_cached_tokens,
            "output_standard_tokens": self.usage.output_standard_tokens,
            "output_reasoning_tokens": self.usage.output_reasoning_tokens,
            "usage_source": self.usage.source.value,
            "calculated_cost_usd": float(self.cost.calculated_cost) if self.cost and self.cost.calculated_cost is not None else None,
            "estimated_cost_usd": float(self.cost.estimated_cost) if self.cost and self.cost.estimated_cost is not None else None,
            "pricing_version": self.cost.pricing_version if self.cost else None,
            "provider_request_id": self.provider_request_id,
            "latency_ms": self.latency_ms,
            "retry_count": self.retry_count,
            "outcome_kind": self.outcome_kind,
            "error_code": self.error_code,
            "error_detail": self.error_detail,
        }


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class LLMClientError(Exception):
    """Base exception for Guarded LLM Client."""


class ContextWindowExceededError(LLMClientError):
    """Raised when preflight check determines the request exceeds model context window."""

    def __init__(self, model: str, required_tokens: int, limit: int) -> None:
        super().__init__(
            f"Context window exceeded for model '{model}': "
            f"requires {required_tokens} tokens, but limit is {limit} tokens"
        )
        self.model = model
        self.required_tokens = required_tokens
        self.limit = limit


class TokenLimitExceededError(LLMClientError):
    """Raised when request tokens exceed configured per-request limits."""


class BudgetExceededError(LLMClientError):
    """Raised when request cost exceeds per-request limit or per-run remaining budget."""

    def __init__(self, message: str, required_spend: Decimal, limit: Decimal) -> None:
        super().__init__(message)
        self.required_spend = required_spend
        self.limit = limit


class RateLimitExceededError(LLMClientError):
    """Raised when local rate limits or concurrency throttles are exceeded."""


class RetryableProviderError(LLMClientError):
    """Raised on temporary errors from LLM provider (HTTP 429, 502, 503, connection errors)."""

    def __init__(self, message: str, retry_after_s: float | None = None, status_code: int | None = None) -> None:
        super().__init__(message)
        self.retry_after_s = retry_after_s
        self.status_code = status_code


class NonRetryableProviderError(LLMClientError):
    """Raised on permanent errors from LLM provider (HTTP 400, 401, 403, 404)."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
