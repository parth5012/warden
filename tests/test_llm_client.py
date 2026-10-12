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


# ---------------------------------------------------------------------------
# 8. Dedicated Telemetry Emission Tests (_emit_telemetry)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_emit_telemetry_none_sink() -> None:
    """_emit_telemetry must do nothing and not raise if telemetry_sink is None."""
    client = GuardedLLMClient(telemetry_sink=None)
    dummy_res = LLMExecutionResult(
        action_id="act-none-01",
        run_id="run-01",
        thread_id="th-01",
        outcome_kind="allowed",
        result="hello",
        usage=NormalizedUsage(10, 5, 15, 10),
        cost=None,
        latency_ms=50,
        retry_count=0,
        model="gpt-4o",
        provider="openai",
    )
    # Must execute silently without error
    await client._emit_telemetry(dummy_res)


@pytest.mark.asyncio
async def test_emit_telemetry_fault_tolerance_on_sink_exception() -> None:
    """_emit_telemetry must safely swallow sink exceptions without crashing."""
    async def broken_sink(payload: dict[str, Any]) -> None:
        raise ConnectionResetError("Telemetry DB connection dropped")

    client = GuardedLLMClient(telemetry_sink=broken_sink)
    dummy_res = LLMExecutionResult(
        action_id="act-sink-fail",
        run_id="run-01",
        thread_id="th-01",
        outcome_kind="allowed",
        result="hello",
        usage=NormalizedUsage(10, 5, 15, 10),
        cost=None,
        latency_ms=50,
        retry_count=0,
        model="gpt-4o",
        provider="openai",
    )
    # Must catch and not raise
    await client._emit_telemetry(dummy_res)


@pytest.mark.asyncio
async def test_emit_telemetry_sink_failure_does_not_mask_successful_invocation() -> None:
    """A failure during telemetry emission must not turn an authorized call into an error."""
    async def broken_sink(payload: dict[str, Any]) -> None:
        raise RuntimeError("Audit journal disk full")

    async def mock_provider(req: LLMRequest) -> dict[str, Any]:
        return {
            "choices": [{"message": {"content": "Primary success."}}],
            "usage": {"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 30},
        }

    client = GuardedLLMClient(
        provider_caller=mock_provider,
        telemetry_sink=broken_sink,
    )
    action = Action(
        id="act-sink-survive",
        kind=ActionKind.LLM,
        name="gpt-4o",
        payload={"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]},
        run_id="run-01",
        thread_id="th-01",
    )

    result = await client.invoke(action)
    assert result.is_success is True
    assert result.result == "Primary success."


@pytest.mark.asyncio
async def test_emit_telemetry_payload_token_usage_and_cost_fidelity() -> None:
    """Verify that _emit_telemetry constructs full token buckets and precision costs."""
    captured: list[dict[str, Any]] = []

    async def sink(payload: dict[str, Any]) -> None:
        captured.append(payload)

    client = GuardedLLMClient(telemetry_sink=sink)
    usage = NormalizedUsage(
        prompt_tokens=150,
        completion_tokens=60,
        total_tokens=210,
        input_uncached_tokens=100,
        input_cached_tokens=50,
        output_standard_tokens=40,
        output_reasoning_tokens=20,
        source=TokenUsageSource.PROVIDER_REPORTED,
    )
    cost = CostRecord(
        calculated_cost=Decimal("0.001234"),
        estimated_cost=Decimal("0.001000"),
        currency="USD",
        pricing_version="2024-10-01",
        model="gpt-4o",
        provider="openai",
    )
    res = LLMExecutionResult(
        action_id="act-fidelity-01",
        run_id="run-fid-01",
        thread_id="th-fid-01",
        outcome_kind="allowed",
        result="ok",
        usage=usage,
        cost=cost,
        latency_ms=125,
        retry_count=1,
        model="gpt-4o",
        provider="openai",
        provider_request_id="req-fid-xyz",
    )

    await client._emit_telemetry(res)

    assert len(captured) == 1
    p = captured[0]
    assert p["action_id"] == "act-fidelity-01"
    assert p["provider"] == "openai"
    assert p["model"] == "gpt-4o"
    assert p["provider_request_id"] == "req-fid-xyz"
    assert p["prompt_tokens"] == 150
    assert p["completion_tokens"] == 60
    assert p["total_tokens"] == 210
    assert p["input_uncached_tokens"] == 100
    assert p["input_cached_tokens"] == 50
    assert p["output_standard_tokens"] == 40
    assert p["output_reasoning_tokens"] == 20
    assert p["usage_source"] == "provider_reported"
    assert p["calculated_cost_usd"] == 0.001234
    assert p["estimated_cost_usd"] == 0.001000
    assert p["pricing_version"] == "2024-10-01"
    assert p["latency_ms"] == 125
    assert p["retry_count"] == 1
    assert p["outcome_kind"] == "allowed"
    assert p["error_code"] is None
    assert p["error_detail"] is None


@pytest.mark.asyncio
async def test_emit_telemetry_on_rate_limiting_retries() -> None:
    """Telemetry must record retry_count when rate limiter encounters 429 and recovers."""
    captured: list[dict[str, Any]] = []

    async def sink(payload: dict[str, Any]) -> None:
        captured.append(payload)

    attempts = 0

    async def retry_provider(req: LLMRequest) -> dict[str, Any]:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise RetryableProviderError("Rate limit 429", retry_after_s=0.01, status_code=429)
        return {
            "choices": [{"message": {"content": "Recovered from rate limit."}}],
            "usage": {"prompt_tokens": 40, "completion_tokens": 15, "total_tokens": 55},
        }

    client = GuardedLLMClient(
        provider_caller=retry_provider,
        telemetry_sink=sink,
        rate_limiter=RateLimitingExecutor(RateLimitConfig(max_retries=3, initial_backoff_s=0.01)),
    )
    action = Action(
        id="act-retry-telemetry",
        kind=ActionKind.LLM,
        name="gpt-4o",
        payload={"model": "gpt-4o", "messages": [{"role": "user", "content": "test"}]},
        run_id="run-retry-01",
        thread_id="th-retry-01",
    )

    result = await client.invoke(action)
    assert result.is_success is True
    assert result.retry_count == 2

    assert len(captured) == 1
    p = captured[0]
    assert p["action_id"] == "act-retry-telemetry"
    assert p["retry_count"] == 2
    assert p["outcome_kind"] == "allowed"
    assert p["total_tokens"] == 55


@pytest.mark.asyncio
async def test_emit_telemetry_on_exhausted_rate_limit_failure() -> None:
    """When retries are exhausted on rate limits, telemetry must be emitted with outcome_kind='error'."""
    captured: list[dict[str, Any]] = []

    async def sink(payload: dict[str, Any]) -> None:
        captured.append(payload)

    async def always_429_provider(req: LLMRequest) -> dict[str, Any]:
        raise RetryableProviderError("Persistent 429", retry_after_s=0.01, status_code=429)

    client = GuardedLLMClient(
        provider_caller=always_429_provider,
        telemetry_sink=sink,
        rate_limiter=RateLimitingExecutor(RateLimitConfig(max_retries=2, initial_backoff_s=0.01)),
    )
    action = Action(
        id="act-fail-429",
        kind=ActionKind.LLM,
        name="gpt-4o",
        payload={"model": "gpt-4o", "messages": [{"role": "user", "content": "test"}]},
        run_id="run-fail-01",
        thread_id="th-fail-01",
    )

    with pytest.raises(RetryableProviderError):
        await client.invoke(action)

    assert len(captured) == 1
    p = captured[0]
    assert p["action_id"] == "act-fail-429"
    assert p["outcome_kind"] == "error"
    assert p["error_code"] == "RetryableProviderError"
    assert "Persistent 429" in (p["error_detail"] or "")
    assert p["retry_count"] == 2


@pytest.mark.asyncio
async def test_emit_telemetry_on_budget_exceeded() -> None:
    """When preflight budget fails, telemetry must be emitted with outcome_kind='error'."""
    captured: list[dict[str, Any]] = []

    async def sink(payload: dict[str, Any]) -> None:
        captured.append(payload)

    async def mock_provider(req: LLMRequest) -> dict[str, Any]:
        return {"choices": [{"message": {"content": "Never reached."}}]}

    client = GuardedLLMClient(
        provider_caller=mock_provider,
        telemetry_sink=sink,
    )
    action = Action(
        id="act-budget-fail",
        kind=ActionKind.LLM,
        name="gpt-4o",
        payload={"model": "gpt-4o", "messages": [{"role": "user", "content": "test"}]},
        run_id="run-bgt-fail",
        thread_id="th-bgt-fail",
    )

    cfg = BudgetConfig(max_spend_per_request=Decimal("0.0000001"))

    with pytest.raises(BudgetExceededError):
        await client.invoke(action, budget_config=cfg)

    assert len(captured) == 1
    p = captured[0]
    assert p["action_id"] == "act-budget-fail"
    assert p["outcome_kind"] == "error"
    assert p["error_code"] == "BudgetExceededError"
    assert "limit" in (p["error_detail"] or "").lower() or "cost" in (p["error_detail"] or "").lower()


@pytest.mark.asyncio
async def test_emit_telemetry_secret_redaction_in_error_detail() -> None:
    """Telemetry error_detail must have API keys redacted when an exception is logged."""
    captured: list[dict[str, Any]] = []

    async def sink(payload: dict[str, Any]) -> None:
        captured.append(payload)

    async def leaking_provider(req: LLMRequest) -> dict[str, Any]:
        raise NonRetryableProviderError("Failed using key sk-secretkey12345678901234567890", status_code=401)

    client = GuardedLLMClient(
        provider_caller=leaking_provider,
        telemetry_sink=sink,
    )
    action = Action(
        id="act-redact-telemetry",
        kind=ActionKind.LLM,
        name="gpt-4o",
        payload={"model": "gpt-4o", "messages": [{"role": "user", "content": "test"}]},
        run_id="run-redact-01",
        thread_id="th-redact-01",
    )

    with pytest.raises(NonRetryableProviderError):
        await client.invoke(action)

    assert len(captured) == 1
    p = captured[0]
    assert p["outcome_kind"] == "error"
    assert p["error_code"] == "NonRetryableProviderError"
    assert "sk-secretkey12345678901234567890" not in p["error_detail"]
    assert "[REDACTED_SECRET]" in p["error_detail"]


# ---------------------------------------------------------------------------
# 9. Provider Execution & Budget Settlement Tests (lines 170-192)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unconfigured_provider_caller_raises_runtime_error() -> None:
    """When provider_caller is None, invoke must raise RuntimeError and log error telemetry."""
    telemetry_events: list[dict[str, Any]] = []

    async def sink(payload: dict[str, Any]) -> None:
        telemetry_events.append(payload)

    client = GuardedLLMClient(
        provider_caller=None,
        telemetry_sink=sink,
    )
    action = Action(
        id="act-no-provider",
        kind=ActionKind.LLM,
        name="gpt-4o",
        payload={"model": "gpt-4o", "messages": [{"role": "user", "content": "hello"}]},
        run_id="run-no-prov",
        thread_id="th-no-prov",
    )

    with pytest.raises(RuntimeError) as exc_info:
        await client.invoke(action)

    assert "No provider caller configured" in str(exc_info.value)
    assert len(telemetry_events) == 1
    assert telemetry_events[0]["outcome_kind"] == "error"
    assert telemetry_events[0]["error_code"] == "RuntimeError"


@pytest.mark.asyncio
async def test_postflight_usage_and_cost_settlement_less_than_reservation() -> None:
    """Preflight reserves estimated spend; postflight settles lower actual cost and frees remainder."""
    bm = BudgetManager()
    cfg = BudgetConfig(max_spend_per_run=Decimal("10.00"))

    # Mock provider returning 100 prompt tokens, 50 completion tokens on gpt-4o
    # Actual cost: (100 * $2.50 + 50 * $10.00) / 1M = $0.00025 + $0.00050 = $0.000750
    async def mock_provider(req: LLMRequest) -> dict[str, Any]:
        return {
            "id": "chatcmpl-settle-less",
            "choices": [{"message": {"content": "short response"}}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
        }

    client = GuardedLLMClient(
        provider_caller=mock_provider,
        budget_manager=bm,
    )
    action = Action(
        id="act-settle-less",
        kind=ActionKind.LLM,
        name="gpt-4o",
        payload={
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Summarize this small text."}],
            "max_tokens": 4000,  # Large max_tokens causes high preflight estimate
        },
        run_id="run-settle-less",
        thread_id="th-settle-less",
    )

    result = await client.invoke(action, budget_config=cfg)

    assert result.is_success is True
    assert result.cost is not None
    assert result.cost.calculated_cost == Decimal("0.000750")

    tracker = await bm.get_or_create_run_tracker("run-settle-less", cfg)
    assert tracker is not None
    # Reservation is completely cleared
    assert tracker.reserved_spend == Decimal("0")
    # Settled spend matches actual calculated cost
    assert tracker.settled_spend == Decimal("0.000750")
    assert tracker.remaining_budget == Decimal("10.00") - Decimal("0.000750")
    assert tracker.total_tokens == 150


@pytest.mark.asyncio
async def test_postflight_settlement_with_unknown_model_pricing() -> None:
    """When model pricing is unknown, actual cost is None and reservation is cleanly released."""
    bm = BudgetManager()
    cfg = BudgetConfig(max_spend_per_run=Decimal("5.00"))

    async def mock_provider(req: LLMRequest) -> dict[str, Any]:
        return {
            "id": "custom-resp-01",
            "choices": [{"message": {"content": "ok"}}],
            "usage": {"prompt_tokens": 200, "completion_tokens": 100, "total_tokens": 300},
        }

    client = GuardedLLMClient(
        provider_caller=mock_provider,
        budget_manager=bm,
    )
    action = Action(
        id="act-unknown-pricing",
        kind=ActionKind.LLM,
        name="unmapped-local-model",
        payload={
            "model": "unmapped-local-model",
            "provider": "custom-host",
            "messages": [{"role": "user", "content": "hi"}],
        },
        run_id="run-unknown-p",
        thread_id="th-unknown-p",
    )

    result = await client.invoke(action, budget_config=cfg)

    assert result.is_success is True
    assert result.cost is None  # Never fabricated
    assert result.usage.total_tokens == 300

    tracker = await bm.get_or_create_run_tracker("run-unknown-p", cfg)
    assert tracker is not None
    assert tracker.reserved_spend == Decimal("0")
    assert tracker.settled_spend == Decimal("0")
    assert tracker.total_tokens == 300


@pytest.mark.asyncio
async def test_postflight_extraction_from_sdk_like_object() -> None:
    """Tests lines 179-181 when provider returns a native Python object (like openai-python model)."""
    class UsageDetails:
        cached_tokens = 50
        reasoning_tokens = 25

    class MockUsage:
        prompt_tokens = 120
        completion_tokens = 60
        total_tokens = 180
        prompt_tokens_details = UsageDetails()
        completion_tokens_details = UsageDetails()

    class MockMessage:
        content = "Object extracted cleanly"

    class MockChoice:
        message = MockMessage()

    class MockSDKResponse:
        id = "resp-sdk-obj-99"
        choices = [MockChoice()]
        usage = MockUsage()

    async def object_provider(req: LLMRequest) -> Any:
        return MockSDKResponse()

    client = GuardedLLMClient(provider_caller=object_provider)
    action = Action(
        id="act-sdk-obj",
        kind=ActionKind.LLM,
        name="gpt-4o",
        payload={"model": "gpt-4o", "messages": [{"role": "user", "content": "test"}]},
        run_id="run-sdk",
        thread_id="th-sdk",
    )

    result = await client.invoke(action)

    assert result.is_success is True
    assert result.result == "Object extracted cleanly"
    assert result.provider_request_id == "resp-sdk-obj-99"
    assert result.usage.input_cached_tokens == 50
    assert result.usage.input_uncached_tokens == 70  # 120 - 50
    assert result.usage.output_reasoning_tokens == 25
    assert result.usage.output_standard_tokens == 35   # 60 - 25
    assert result.cost is not None
    assert result.cost.calculated_cost is not None

