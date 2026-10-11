"""Guarded LLM Client for Warden.

Enforces preflight context checks, token estimation, budget reservations,
sliding-window rate limiting, bounded retries, provider usage extraction,
and precision-safe cost calculation within Warden's security perimeter.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Awaitable, Callable

from warden.llm.budget import BudgetManager
from warden.llm.extraction import UsageExtractor
from warden.llm.pricing import PricingRegistry
from warden.llm.rate_limiter import RateLimitingExecutor
from warden.llm.tokenizer import TokenEstimator
from warden.llm.types import (
    BudgetConfig,
    CostRecord,
    LLMClientError,
    LLMRequest,
    LLMResponse,
    LLMUsageTelemetry,
    NormalizedUsage,
    RateLimitConfig,
    TokenUsageSource,
)
from warden.models import Action, ActionKind


# Regex pattern to redact sensitive credentials from error messages and logs
SECRET_PATTERN = re.compile(
    r"(?:bearer\s+[a-zA-Z0-9_\-\.]{15,}|sk-[a-zA-Z0-9_\-]{20,}|key=[a-zA-Z0-9_\-]{15,})",
    re.IGNORECASE,
)


def redact_secrets(text: str) -> str:
    """Redact sensitive API keys or authorization tokens."""
    return SECRET_PATTERN.sub("[REDACTED_SECRET]", text)


@dataclass(frozen=True)
class LLMExecutionResult:
    """Result of an LLM call through GuardedLLMClient."""

    action_id: str
    run_id: str
    thread_id: str
    outcome_kind: str
    result: Any
    usage: NormalizedUsage
    cost: CostRecord | None
    latency_ms: int
    retry_count: int
    model: str
    provider: str
    provider_request_id: str | None = None
    error_code: str | None = None
    error_detail: str | None = None

    @property
    def is_success(self) -> bool:
        return self.outcome_kind == "allowed"


class GuardedLLMClient:
    """The central guarded seam for executing LLM operations."""

    def __init__(
        self,
        provider_caller: Callable[[LLMRequest], Awaitable[Any]] | None = None,
        tokenizer: TokenEstimator | None = None,
        pricing: PricingRegistry | None = None,
        budget_manager: BudgetManager | None = None,
        rate_limiter: RateLimitingExecutor | None = None,
        telemetry_sink: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
    ) -> None:
        self.provider_caller = provider_caller
        self.tokenizer = tokenizer or TokenEstimator()
        self.pricing = pricing or PricingRegistry()
        self.budget_manager = budget_manager or BudgetManager()
        self.rate_limiter = rate_limiter or RateLimitingExecutor()
        self.telemetry_sink = telemetry_sink

    async def invoke(
        self,
        action: Action,
        budget_config: BudgetConfig | None = None,
        rate_limit_config: RateLimitConfig | None = None,
    ) -> LLMExecutionResult:
        """Invoke an LLM action through all preflight and postflight guards."""
        start_time = time.monotonic()
        run_id = action.run_id
        action_id = action.id
        thread_id = action.thread_id
        model = str(action.payload.get("model") or action.name or "gpt-4o")
        provider = str(action.payload.get("provider", "openai"))
        messages = action.payload.get("messages", [])
        max_tokens = action.payload.get("max_tokens")

        request = LLMRequest(
            model=model,
            messages=messages,
            provider=provider,
            max_tokens=max_tokens,
            temperature=action.payload.get("temperature"),
            timeout_s=action.payload.get("timeout_s", 30.0),
            extra_params=action.payload.get("extra_params", {}),
        )

        reserved_cost = Decimal("0")
        estimated_tokens = 0
        retry_count = 0

        try:
            # 1. Preflight token estimation & context window check
            est_result = self.tokenizer.validate_preflight_context(
                model=model,
                messages=messages,
                max_output_tokens=max_tokens,
            )
            estimated_tokens = est_result.estimated_tokens or 0

            # 2. Preflight request token limits
            self.budget_manager.validate_request_tokens(
                estimated_input_tokens=estimated_tokens,
                requested_output_tokens=max_tokens,
                config=budget_config,
            )

            # 3. Preflight cost estimation
            est_usage = NormalizedUsage(
                prompt_tokens=estimated_tokens,
                completion_tokens=max_tokens or 0,
                total_tokens=estimated_tokens + (max_tokens or 0),
                input_uncached_tokens=estimated_tokens,
                input_cached_tokens=0,
                output_standard_tokens=max_tokens or 0,
                output_reasoning_tokens=0,
                source=TokenUsageSource.ESTIMATED,
            )
            est_cost_record = self.pricing.calculate_cost(
                usage=est_usage,
                provider=provider,
                model=model,
                is_estimate=True,
            )
            estimated_cost = est_cost_record.estimated_cost if est_cost_record else None

            # 4. Preflight request spend limit
            self.budget_manager.validate_request_cost(
                estimated_cost=estimated_cost,
                config=budget_config,
            )

            # 5. Preflight atomic run budget reservation
            reserved_cost = await self.budget_manager.reserve_budget(
                run_id=run_id,
                estimated_cost=estimated_cost,
                config=budget_config,
            )

            # 6. Execute under rate limiter, concurrency semaphore, and retry policy
            async def _call_provider() -> Any:
                if self.provider_caller is None:
                    raise RuntimeError("No provider caller configured on GuardedLLMClient")
                return await self.provider_caller(request)

            raw_response, retry_count = await self.rate_limiter.execute_with_retries(
                _call_provider,
                estimated_tokens=estimated_tokens,
            )

            # 7. Postflight usage extraction & normalization
            normalized_usage = UsageExtractor.extract_usage(raw_response, provider=provider)
            request_id = UsageExtractor.extract_request_id(raw_response)

            # 8. Postflight precision-safe cost calculation
            actual_cost = self.pricing.calculate_cost(
                usage=normalized_usage,
                provider=provider,
                model=model,
                is_estimate=False,
            )

            # 9. Settle actual budget
            await self.budget_manager.settle_budget(
                run_id=run_id,
                reserved_cost=reserved_cost,
                actual_cost=actual_cost.calculated_cost if actual_cost else None,
                actual_tokens=normalized_usage.total_tokens,
                config=budget_config,
            )

            latency_ms = int((time.monotonic() - start_time) * 1000)

            # Extract content from response
            result_content = self._extract_content(raw_response)

            exec_result = LLMExecutionResult(
                action_id=action_id,
                run_id=run_id,
                thread_id=thread_id,
                outcome_kind="allowed",
                result=result_content,
                usage=normalized_usage,
                cost=actual_cost,
                latency_ms=latency_ms,
                retry_count=retry_count,
                model=model,
                provider=provider,
                provider_request_id=request_id,
            )

            await self._emit_telemetry(exec_result)
            return exec_result

        except Exception as exc:
            # Release any active budget reservation on failure
            if reserved_cost > Decimal("0"):
                await self.budget_manager.release_reservation(
                    run_id=run_id,
                    reserved_cost=reserved_cost,
                    config=budget_config,
                )

            latency_ms = int((time.monotonic() - start_time) * 1000)
            clean_error = redact_secrets(str(exc))
            error_code = exc.__class__.__name__

            fallback_usage = NormalizedUsage(
                prompt_tokens=estimated_tokens,
                completion_tokens=0,
                total_tokens=estimated_tokens,
                input_uncached_tokens=estimated_tokens,
                input_cached_tokens=0,
                output_standard_tokens=0,
                output_reasoning_tokens=0,
                source=TokenUsageSource.ESTIMATED if estimated_tokens > 0 else TokenUsageSource.UNAVAILABLE,
            )

            exec_result = LLMExecutionResult(
                action_id=action_id,
                run_id=run_id,
                thread_id=thread_id,
                outcome_kind="error",
                result=None,
                usage=fallback_usage,
                cost=None,
                latency_ms=latency_ms,
                retry_count=retry_count,
                model=model,
                provider=provider,
                error_code=error_code,
                error_detail=clean_error,
            )

            await self._emit_telemetry(exec_result)
            raise

    def _extract_content(self, response: Any) -> Any:
        """Safely extract completion content from various provider response types."""
        if isinstance(response, str):
            return response
        if isinstance(response, dict):
            # Check OpenAI chat format
            choices = response.get("choices")
            if choices and isinstance(choices, list) and len(choices) > 0:
                choice = choices[0]
                if isinstance(choice, dict):
                    message = choice.get("message")
                    if isinstance(message, dict) and "content" in message:
                        return message["content"]
            if "content" in response:
                return response["content"]
        if hasattr(response, "choices") and response.choices:
            first_choice = response.choices[0]
            if hasattr(first_choice, "message") and hasattr(first_choice.message, "content"):
                return first_choice.message.content
        if hasattr(response, "content"):
            return response.content
        return response

    async def _emit_telemetry(self, res: LLMExecutionResult) -> None:
        """Emit telemetry event to configured sink, catching exceptions to avoid masking outcomes."""
        if self.telemetry_sink is None:
            return

        telemetry = LLMUsageTelemetry(
            action_id=res.action_id,
            run_id=res.run_id,
            thread_id=res.thread_id,
            provider=res.provider,
            model=res.model,
            usage=res.usage,
            cost=res.cost,
            latency_ms=res.latency_ms,
            retry_count=res.retry_count,
            outcome_kind=res.outcome_kind,
            provider_request_id=res.provider_request_id,
            error_code=res.error_code,
            error_detail=res.error_detail,
        )

        try:
            await self.telemetry_sink(telemetry.to_journal_payload())
        except Exception:
            # Telemetry delivery errors must not crash or bypass the primary execution outcome
            pass
