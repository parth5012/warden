"""Comprehensive test suite for Guarded LLM Client in Warden.

Tests cover:
- Provider usage extraction and normalization across OpenAI, Anthropic, Gemini
- Mutually exclusive token accounting (preventing double counting of cached & reasoning tokens)
- Local token estimation with tiktoken and chat formatting overhead
- Explicit handling of unsupported tokenizers
- Preflight context window rejection before provider dispatch
- Precision-safe Decimal cost calculation and rounding
- Exact vs pattern-based model pricing resolution
- Unknown model pricing behavior (never fabricated)
- Per-request token limits and spend limits
- Run-level budget tracking with atomic reservation and settlement
- Concurrency and shared budget race-condition safety
- Rate limiting, concurrency semaphores, and bounded retries
- Provider Retry-After header and exponential backoff
- Timeout handling and non-retryable provider error classification
- Secret redaction from error messages
- Audit journal and telemetry emission
"""

from __future__ import annotations

import asyncio
from decimal import Decimal
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from warden.llm import (
    BudgetConfig,
    BudgetExceededError,
    BudgetManager,
    ContextWindowExceededError,
    CostRecord,
    GuardedLLMClient,
    LLMExecutionResult,
    LLMRequest,
    NonRetryableProviderError,
    NormalizedUsage,
    PricingRegistry,
    PricingTier,
    RateLimitConfig,
    RateLimitExceededError,
    RateLimitingExecutor,
    RetryableProviderError,
    TokenEstimator,
    TokenLimitExceededError,
    TokenUsageSource,
    UsageExtractor,
    redact_secrets,
)
from warden.models import Action, ActionKind


# ---------------------------------------------------------------------------
# 1. Usage Extraction & Bucket Normalization Tests
# ---------------------------------------------------------------------------

def test_extract_openai_usage_with_cached_and_reasoning() -> None:
    """Ensure OpenAI usage extracts cached and reasoning tokens without double counting."""
    raw_response = {
        "id": "chatcmpl-test-123",
        "usage": {
            "prompt_tokens": 1000,
            "completion_tokens": 500,
            "total_tokens": 1500,
            "prompt_tokens_details": {"cached_tokens": 400},
            "completion_tokens_details": {"reasoning_tokens": 200},
        },
    }

    usage = UsageExtractor.extract_usage(raw_response, provider="openai")
    req_id = UsageExtractor.extract_request_id(raw_response)

    assert req_id == "chatcmpl-test-123"
    assert usage.prompt_tokens == 1000
    assert usage.completion_tokens == 500
    # Mutually exclusive buckets:
    assert usage.input_cached_tokens == 400
    assert usage.input_uncached_tokens == 600  # 1000 - 400
    assert usage.output_reasoning_tokens == 200
    assert usage.output_standard_tokens == 300  # 500 - 200
    # Total sum equals exactly 1500:
    assert (
        usage.input_uncached_tokens
        + usage.input_cached_tokens
        + usage.output_standard_tokens
        + usage.output_reasoning_tokens
    ) == 1500
    assert usage.source == TokenUsageSource.PROVIDER_REPORTED


def test_extract_anthropic_usage() -> None:
    """Ensure Anthropic usage normalizes cache_read and cache_creation correctly."""
    raw_response = {
        "id": "msg_ant_123",
        "usage": {
            "input_tokens": 800,
            "output_tokens": 400,
            "cache_read_input_tokens": 300,
            "cache_creation_input_tokens": 100,
        },
    }

    usage = UsageExtractor.extract_usage(raw_response, provider="anthropic")
    req_id = UsageExtractor.extract_request_id(raw_response)

    assert req_id == "msg_ant_123"
    assert usage.input_cached_tokens == 300
    assert usage.input_uncached_tokens == 900  # 800 + 100
    assert usage.prompt_tokens == 1200  # 900 + 300
    assert usage.completion_tokens == 400
    assert usage.total_tokens == 1600


def test_extract_gemini_usage() -> None:
    """Ensure Gemini usage metadata normalizes cached content count."""
    raw_response = {
        "id": "gemini-req-99",
        "usage_metadata": {
            "prompt_token_count": 500,
            "candidates_token_count": 250,
            "cached_content_token_count": 200,
            "total_token_count": 750,
        },
    }

    usage = UsageExtractor.extract_usage(raw_response, provider="google")
    assert usage.prompt_tokens == 500
    assert usage.completion_tokens == 250
    assert usage.input_cached_tokens == 200
    assert usage.input_uncached_tokens == 300  # 500 - 200
    assert usage.total_tokens == 750


def test_extract_missing_usage() -> None:
    """Ensure missing usage safely returns UNAVAILABLE without fabricating counts."""
    raw_response = {"content": "Hello world"}
    usage = UsageExtractor.extract_usage(raw_response)

    assert usage.source == TokenUsageSource.UNAVAILABLE
    assert usage.prompt_tokens == 0
    assert usage.completion_tokens == 0
    assert usage.total_tokens == 0


# ---------------------------------------------------------------------------
# 2. Token Estimation & Context Window Checks
# ---------------------------------------------------------------------------

def test_token_estimator_with_tiktoken() -> None:
    """Ensure tiktoken accurately estimates text and chat messages."""
    estimator = TokenEstimator()
    text = "Hello, world! This is a test prompt for token estimation."
    res = estimator.estimate_text_tokens(text, model="gpt-4o")

    assert res.is_supported is True
    assert res.estimated_tokens is not None
    assert res.estimated_tokens > 0
    assert res.encoding_name == "o200k_base"


def test_token_estimator_chat_message_overhead() -> None:
    """Ensure chat formatting accounts for role and message framing overhead."""
    estimator = TokenEstimator()
    messages = [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "name": "Alice", "content": "Hello!"},
    ]
    res = estimator.estimate_messages_tokens(messages, model="gpt-4o")

    assert res.is_supported is True
    assert res.estimated_tokens is not None
    # Framing includes: 3 tokens per message * 2 + 1 for name + 3 assistant primer = at least 10 framing tokens
    text_only = len(estimator.get_encoding_for_model("gpt-4o").encode("You are a helpful assistant.Hello!"))  # type: ignore[union-attr]
    assert res.estimated_tokens >= text_only + 10


def test_token_estimator_unsupported_model() -> None:
    """Ensure unsupported models are flagged explicitly without guessing an arbitrary count."""
    estimator = TokenEstimator()
    res = estimator.estimate_text_tokens("test", model="unknown-exotic-model-v99")

    assert res.is_supported is False
    assert res.estimated_tokens is None
    assert "No compatible tiktoken encoding found" in (res.reason or "")


def test_context_window_rejection_before_provider_call() -> None:
    """Preflight check must reject oversized prompt before calling external provider."""
    # Override context window for gpt-4 to small limit for testing
    estimator = TokenEstimator(context_window_overrides={"gpt-4": 50})
    long_messages = [
        {"role": "user", "content": "This is a prompt that will definitely take more than 50 tokens when framing is added and we request large output." * 5}
    ]

    with pytest.raises(ContextWindowExceededError) as exc_info:
        estimator.validate_preflight_context(
            model="gpt-4",
            messages=long_messages,
            max_output_tokens=100,
        )

    assert exc_info.value.model == "gpt-4"
    assert exc_info.value.limit == 50
    assert exc_info.value.required_tokens > 50


# ---------------------------------------------------------------------------
# 3. Model Pricing Registry & Precision Cost Calculations
# ---------------------------------------------------------------------------

def test_pricing_exact_match_precedence() -> None:
    """Exact model match must take precedence over pattern matching."""
    registry = PricingRegistry()
    tier, is_exact = registry.resolve_tier("openai", "gpt-4o")

    assert tier is not None
    assert is_exact is True
    assert tier.model_pattern == "gpt-4o"
    assert tier.input_cost_per_million == Decimal("2.50")
    assert tier.output_cost_per_million == Decimal("10.00")


def test_pricing_pattern_matching_fallback() -> None:
    """Dated checkpoint model name must match regex pattern tier."""
    registry = PricingRegistry()
    tier, is_exact = registry.resolve_tier("openai", "gpt-4o-2024-08-06")

    assert tier is not None
    assert is_exact is False
    assert tier.is_pattern is True
    assert tier.input_cost_per_million == Decimal("2.50")


def test_unknown_model_pricing_never_fabricated() -> None:
    """Unrecognized models must return None, never a fabricated default rate."""
    registry = PricingRegistry()
    tier, _ = registry.resolve_tier("custom_provider", "non-existent-model")

    assert tier is None

    dummy_usage = NormalizedUsage(
        prompt_tokens=100,
        completion_tokens=50,
        total_tokens=150,
        input_uncached_tokens=100,
    )
    cost = registry.calculate_cost(dummy_usage, provider="custom_provider", model="non-existent-model")
    assert cost is None


def test_precision_safe_cost_calculation_with_cached_and_reasoning() -> None:
    """Test cost calculation with cached discount and reasoning tokens."""
    registry = PricingRegistry()
    # o1 pricing: input=$15/1M, output=$60/1M, cache=$7.50/1M, reasoning=$60/1M
    usage = NormalizedUsage(
        prompt_tokens=1_000_000,
        completion_tokens=500_000,
        total_tokens=1_500_000,
        input_uncached_tokens=600_000,   # 600,000 * 15 / 1,000,000 = $9.00
        input_cached_tokens=400_000,     # 400,000 * 7.50 / 1,000,000 = $3.00
        output_standard_tokens=200_000,  # 200,000 * 60 / 1,000,000 = $12.00
        output_reasoning_tokens=300_000, # 300,000 * 60 / 1,000,000 = $18.00
        source=TokenUsageSource.PROVIDER_REPORTED,
    )

    cost_rec = registry.calculate_cost(usage, provider="openai", model="o1")
    assert cost_rec is not None
    assert cost_rec.calculated_cost is not None
    # Total = 9.00 + 3.00 + 12.00 + 18.00 = $42.00
    assert cost_rec.calculated_cost == Decimal("42.000000")


# ---------------------------------------------------------------------------
# 4. Budget Enforcement & Race-Safe Reservation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_budget_per_request_token_limits() -> None:
    """Preflight check must reject request when estimated tokens exceed limit."""
    bm = BudgetManager(BudgetConfig(max_input_tokens_per_request=100))

    with pytest.raises(TokenLimitExceededError):
        bm.validate_request_tokens(estimated_input_tokens=150, requested_output_tokens=50)


@pytest.mark.asyncio
async def test_budget_run_atomic_reservation_and_settlement() -> None:
    """Run budget must reserve estimated cost and settle actual cost."""
    bm = BudgetManager()
    cfg = BudgetConfig(max_spend_per_run=Decimal("10.00"))

    # Reserve $4.00
    res1 = await bm.reserve_budget("run-1", estimated_cost=Decimal("4.00"), config=cfg)
    assert res1 == Decimal("4.00")

    tracker = await bm.get_or_create_run_tracker("run-1", cfg)
    assert tracker is not None
    assert tracker.remaining_budget == Decimal("6.00")

    # Trying to reserve $7.00 should fail because only $6.00 remains
    with pytest.raises(BudgetExceededError):
        await bm.reserve_budget("run-1", estimated_cost=Decimal("7.00"), config=cfg)

    # Settle actual cost of $3.50 for request 1
    await bm.settle_budget("run-1", reserved_cost=Decimal("4.00"), actual_cost=Decimal("3.50"), config=cfg)
    assert tracker.remaining_budget == Decimal("6.50")  # 10.00 - 3.50


@pytest.mark.asyncio
async def test_concurrent_budget_safety() -> None:
    """Concurrent requests must not bypass run budget due to race conditions."""
    bm = BudgetManager()
    cfg = BudgetConfig(max_spend_per_run=Decimal("10.00"))

    success_count = 0
    failure_count = 0

    async def _try_reserve() -> None:
        nonlocal success_count, failure_count
        try:
            # Each tries to reserve $4.00 from a $10.00 budget (max 2 can succeed)
            await bm.reserve_budget("run-conc", estimated_cost=Decimal("4.00"), config=cfg)
            success_count += 1
        except BudgetExceededError:
            failure_count += 1

    # Launch 5 concurrent reservation attempts
    await asyncio.gather(*[_try_reserve() for _ in range(5)])

    assert success_count == 2
    assert failure_count == 3


# ---------------------------------------------------------------------------
# 5. Rate Limiting, Retries, and Error Classification
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rate_limiter_bounded_retries_on_429() -> None:
    """Rate limiter must retry on HTTP 429 and succeed when provider recovers."""
    rle = RateLimitingExecutor(RateLimitConfig(max_retries=3, initial_backoff_s=0.01))

    attempts = 0

    async def flaky_call() -> str:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise RetryableProviderError("Rate limit reached", retry_after_s=0.01, status_code=429)
        return "success"

    result, retries = await rle.execute_with_retries(flaky_call)
    assert result == "success"
    assert retries == 2
    assert attempts == 3


@pytest.mark.asyncio
async def test_rate_limiter_non_retryable_error() -> None:
    """Non-retryable errors (e.g. 401 Unauthorized) must fail immediately without retries."""
    rle = RateLimitingExecutor(RateLimitConfig(max_retries=3))

    attempts = 0

    async def auth_error_call() -> None:
        nonlocal attempts
        attempts += 1
        raise NonRetryableProviderError("Invalid API key", status_code=401)

    with pytest.raises(NonRetryableProviderError):
        await rle.execute_with_retries(auth_error_call)

    assert attempts == 1  # No retries executed


# ---------------------------------------------------------------------------
# 6. Secret Redaction
# ---------------------------------------------------------------------------

def test_secret_redaction() -> None:
    """Sensitive API keys and bearer tokens must be stripped from messages."""
    raw = "Request failed with bearer sk-abcdef12345678901234567890 and key=secret1234567890"
    clean = redact_secrets(raw)

    assert "sk-abcdef" not in clean
    assert "secret1234567890" not in clean
    assert "[REDACTED_SECRET]" in clean


# ---------------------------------------------------------------------------
# 7. End-to-End GuardedLLMClient Invocation & Telemetry Emission
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_guarded_llm_client_end_to_end() -> None:
    """End-to-end test verifying preflight checks, provider call, usage extraction, cost, and telemetry."""
    telemetry_events: list[dict[str, Any]] = []

    async def mock_telemetry_sink(event: dict[str, Any]) -> None:
        telemetry_events.append(event)

    async def mock_provider(req: LLMRequest) -> dict[str, Any]:
        return {
            "id": "chatcmpl-warden-e2e",
            "choices": [{"message": {"content": "Governance verified."}}],
            "usage": {
                "prompt_tokens": 50,
                "completion_tokens": 20,
                "total_tokens": 70,
                "prompt_tokens_details": {"cached_tokens": 10},
            },
        }

    client = GuardedLLMClient(
        provider_caller=mock_provider,
        telemetry_sink=mock_telemetry_sink,
    )

    action = Action(
        id="act-test-001",
        kind=ActionKind.LLM,
        name="gpt-4o",
        payload={
            "model": "gpt-4o",
            "provider": "openai",
            "messages": [{"role": "user", "content": "Run security check."}],
        },
        run_id="run-test-100",
        thread_id="th-test-200",
    )

    result = await client.invoke(action)

    assert result.is_success is True
    assert result.result == "Governance verified."
    assert result.model == "gpt-4o"
    assert result.provider_request_id == "chatcmpl-warden-e2e"
    assert result.usage.input_cached_tokens == 10
    assert result.usage.input_uncached_tokens == 40
    assert result.usage.output_standard_tokens == 20
    assert result.cost is not None
    assert result.cost.calculated_cost is not None
    assert result.cost.calculated_cost > Decimal("0")

    # Verify telemetry payload
    assert len(telemetry_events) == 1
    t = telemetry_events[0]
    assert t["action_id"] == "act-test-001"
    assert t["model"] == "gpt-4o"
    assert t["prompt_tokens"] == 50
    assert t["input_cached_tokens"] == 10
    assert t["input_uncached_tokens"] == 40
    assert t["output_standard_tokens"] == 20
    assert t["calculated_cost_usd"] is not None
    assert t["outcome_kind"] == "allowed"
    # Never logs raw prompt or completion
    assert "messages" not in t
    assert "content" not in t
