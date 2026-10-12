"""Manual Interactive Test Harness for WARDEN Guarded LLM Client.

Run this script directly in the terminal to inspect:
- Token usage extraction (cached, uncached, standard, reasoning)
- Precision-safe Decimal cost calculation
- Preflight context window rejection
- Per-request and run-level budget limits
- Rate limiting and retry backoff on HTTP 429

Usage:
    uv run python scripts/manual_test_llm.py
"""

from __future__ import annotations

import asyncio
from decimal import Decimal
from typing import Any

from warden.llm import (
    BudgetConfig,
    BudgetExceededError,
    ContextWindowExceededError,
    GuardedLLMClient,
    LLMRequest,
    RateLimitConfig,
    RetryableProviderError,
    TokenEstimator,
)
from warden.models import Action, ActionKind


def print_header(title: str) -> None:
    print(f"\n{'=' * 70}")
    print(f"  SCENARIO: {title}")
    print(f"{'=' * 70}")


async def scenario_openai_cached_and_reasoning() -> None:
    print_header("1. OpenAI Execution with Cached and Reasoning Tokens")

    async def mock_openai(req: LLMRequest) -> dict[str, Any]:
        return {
            "id": "chatcmpl-manual-001",
            "choices": [{"message": {"content": "Governance analysis completed successfully."}}],
            "usage": {
                "prompt_tokens": 1000,
                "completion_tokens": 500,
                "total_tokens": 1500,
                "prompt_tokens_details": {"cached_tokens": 400},
                "completion_tokens_details": {"reasoning_tokens": 200},
            },
        }

    client = GuardedLLMClient(provider_caller=mock_openai)
    action = Action(
        id="act-manual-01",
        kind=ActionKind.LLM,
        name="gpt-4o",
        payload={
            "model": "gpt-4o",
            "provider": "openai",
            "messages": [{"role": "user", "content": "Analyze system vulnerabilities."}],
        },
        run_id="run-manual-01",
        thread_id="th-manual-01",
    )

    res = await client.invoke(action)
    print(f"[OK] Outcome:               {res.outcome_kind}")
    print(f"[OK] Completion:            {res.result}")
    print(f"[OK] Provider Request ID:   {res.provider_request_id}")
    print("--- Token Usage Buckets ---")
    print(f"     Prompt (Raw):          {res.usage.prompt_tokens}")
    print(f"     -> Input Uncached:     {res.usage.input_uncached_tokens}")
    print(f"     -> Input Cached:       {res.usage.input_cached_tokens}")
    print(f"     Completion (Raw):      {res.usage.completion_tokens}")
    print(f"     -> Output Standard:    {res.usage.output_standard_tokens}")
    print(f"     -> Output Reasoning:   {res.usage.output_reasoning_tokens}")
    print(f"     Total Physical Tokens: {res.usage.total_tokens}")
    print("--- Cost Calculation ---")
    if res.cost:
        print(f"     Calculated Cost:       ${res.cost.calculated_cost} {res.cost.currency}")
        print(f"     Pricing Version:       {res.cost.pricing_version}")


async def scenario_anthropic_cache_read() -> None:
    print_header("2. Anthropic Execution with Prompt Cache Reads")

    async def mock_anthropic(req: LLMRequest) -> dict[str, Any]:
        return {
            "id": "msg_ant_manual_99",
            "content": "Claude policy verification passed.",
            "usage": {
                "input_tokens": 800,
                "output_tokens": 300,
                "cache_read_input_tokens": 500,
            },
        }

    client = GuardedLLMClient(provider_caller=mock_anthropic)
    action = Action(
        id="act-manual-02",
        kind=ActionKind.LLM,
        name="claude-3-5-sonnet",
        payload={
            "model": "claude-3-5-sonnet",
            "provider": "anthropic",
            "messages": [{"role": "user", "content": "Verify policy."}],
        },
        run_id="run-manual-02",
        thread_id="th-manual-02",
    )

    res = await client.invoke(action)
    print(f"[OK] Outcome:               {res.outcome_kind}")
    print(f"[OK] Completion:            {res.result}")
    print(f"[OK] Total Tokens:          {res.usage.total_tokens}")
    print(f"     -> Input Uncached:     {res.usage.input_uncached_tokens}")
    print(f"     -> Input Cached:       {res.usage.input_cached_tokens}")
    print(f"     -> Output Standard:    {res.usage.output_standard_tokens}")
    if res.cost:
        print(f"[OK] Calculated Cost:       ${res.cost.calculated_cost} {res.cost.currency}")


async def scenario_context_window_rejection() -> None:
    print_header("3. Preflight Context Window Check (Rejection Before Network Call)")

    # Artificially small context window for demonstration
    estimator = TokenEstimator(context_window_overrides={"gpt-4": 30})
    client = GuardedLLMClient(tokenizer=estimator)

    long_prompt = "This is a long user request that exceeds thirty tokens framing limit. " * 3
    action = Action(
        id="act-manual-03",
        kind=ActionKind.LLM,
        name="gpt-4",
        payload={
            "model": "gpt-4",
            "messages": [{"role": "user", "content": long_prompt}],
            "max_tokens": 50,
        },
        run_id="run-manual-03",
        thread_id="th-manual-03",
    )

    try:
        await client.invoke(action)
        print("[FAIL] Rejection did not trigger!")
    except ContextWindowExceededError as exc:
        print(f"[PASS] Preflight Gate Intercepted: {exc}")
        print("       (No external API call was made)")


async def scenario_budget_limit_rejection() -> None:
    print_header("4. Budget Enforcement (Per-Request and Run Budget Gates)")

    client = GuardedLLMClient()
    action = Action(
        id="act-manual-04",
        kind=ActionKind.LLM,
        name="gpt-4o",
        payload={
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Run large expensive analysis."}],
            "max_tokens": 10000,
        },
        run_id="run-manual-04",
        thread_id="th-manual-04",
    )

    # Budget config with $0.0001 limit
    tiny_budget = BudgetConfig(max_spend_per_request=Decimal("0.0001"))

    try:
        await client.invoke(action, budget_config=tiny_budget)
        print("[FAIL] Budget check did not trigger!")
    except BudgetExceededError as exc:
        print(f"[PASS] Preflight Budget Gate Intercepted: {exc}")
        print("       (Zero spend incurred)")


async def scenario_rate_limiting_and_retries() -> None:
    print_header("5. Rate Limiting Throttling & 429 Exponential Backoff Retries")

    attempts = 0

    async def flaky_rate_limited_provider(req: LLMRequest) -> dict[str, Any]:
        nonlocal attempts
        attempts += 1
        print(f"     -> Attempt #{attempts}: ", end="")
        if attempts < 3:
            print("HTTP 429 Rate Limit encountered. Requesting retry in 0.05s...")
            raise RetryableProviderError("Rate limit exceeded", retry_after_s=0.05, status_code=429)
        print("HTTP 200 Success! Response received.")
        return {
            "choices": [{"message": {"content": "Successfully recovered after backoff."}}],
            "usage": {"prompt_tokens": 50, "completion_tokens": 20, "total_tokens": 70},
        }

    client = GuardedLLMClient(
        provider_caller=flaky_rate_limited_provider,
        rate_limiter=RateLimitConfig(max_retries=3, initial_backoff_s=0.05),
    )
    action = Action(
        id="act-manual-05",
        kind=ActionKind.LLM,
        name="gpt-4o",
        payload={"model": "gpt-4o", "messages": [{"role": "user", "content": "hello"}]},
        run_id="run-manual-05",
        thread_id="th-manual-05",
    )

    res = await client.invoke(action)
    print(f"[PASS] Total Retries Required: {res.retry_count}")
    print(f"[PASS] Final Outcome:          {res.result}")


async def main() -> None:
    print("\n" + "=" * 70)
    print("   WARDEN GUARDED LLM CLIENT — MANUAL TEST HARNESS")
    print("=" * 70)
    await scenario_openai_cached_and_reasoning()
    await scenario_anthropic_cache_read()
    await scenario_context_window_rejection()
    await scenario_budget_limit_rejection()
    await scenario_rate_limiting_and_retries()
    print("\n" + "=" * 70)
    print("   ALL MANUAL TEST SCENARIOS COMPLETED SUCCESSFULLY")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    asyncio.run(main())
