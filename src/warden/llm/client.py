"""Guarded LLM Client for Aegis.

Enforces preflight context checks, token estimation, budget reservations,
sliding-window rate limiting, bounded retries, provider usage extraction,
and precision-safe cost calculation within Aegis's security perimeter.
"""

from __future__ import annotations

import re
import logging
import time
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Awaitable, Callable

from warden.llm.budget import BudgetManager
from warden.llm.extraction import UsageExtractor
from warden.llm.pricing import PricingRegistry
from warden.llm.providers import (
    PROVIDER_ADAPTERS,
    ProviderAdapter,
    ProviderAuthenticationError,
    ProviderPermanentError,
    ProviderRateLimitError,
    ProviderTransientError,
    ProviderError,
)
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
    UnsupportedModelError,
    UnknownModelPricingError,
)
from warden.models import Action, ActionKind


# Regex pattern to redact sensitive credentials from error messages and logs
SECRET_PATTERN = re.compile(
    r"(?:bearer\s+[a-zA-Z0-9_\-\.]{15,}|sk-[a-zA-Z0-9_\-]{20,}|key=[a-zA-Z0-9_\-]{15,})",
    re.IGNORECASE,
)

logger = logging.getLogger("warden.llm.client")


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
    correlation_id: str | None = None

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
        rate_limiter: RateLimitingExecutor | RateLimitConfig | None = None,
        telemetry_sink: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
        provider_overrides: dict[str, ProviderAdapter] | None = None,
        default_provider: str = "openai",
    ) -> None:
        self.provider_caller = provider_caller
        self.tokenizer = tokenizer or TokenEstimator()
        self.pricing = pricing or PricingRegistry()
        self.budget_manager = budget_manager or BudgetManager()
        if isinstance(rate_limiter, RateLimitConfig):
            self.rate_limiter = RateLimitingExecutor(rate_limiter)
        else:
            self.rate_limiter = rate_limiter or RateLimitingExecutor()
        self.telemetry_sink = telemetry_sink
        # Injectable override map so additional providers can be registered at
        # construction time without changing the public signature.  Built-ins
        # (OpenAI/Groq) remain the default while the legacy callable path stays
        # in place for zero-change compatibility with tests and the API.
        self.provider_overrides = dict(provider_overrides or {})
        self.default_provider = default_provider

    # ---------------------------------------------------------------------------
    # Provider dispatch
    # ---------------------------------------------------------------------------

    async def _invoke_through_adapter(self, request: LLMRequest) -> Any:
        """Route *request* through the configured provider adapter.

        Resolution order:
        1. Explicit adapter registered under the request's provider name in
           ``provider_overrides``.  This is the seam a real deployment uses to
           bind a concrete provider (e.g. ``OpenAIProviderAdapter``).
        2. Injected ``provider_caller`` callable (the injection seam; tests
           and the API rely on it to substitute a real or mock LLM).
        3. If neither is configured, raise ``RuntimeError`` (fail closed).

        A ``provider_caller`` of ``None`` with no registered override means
        "no provider is configured".  This matches the backend ``/invoke``
        handler, which returns a preflight-only result when
        ``_client.provider_caller is None``.  We deliberately do NOT
        auto-construct a built-in adapter from ``PROVIDER_ADAPTERS`` here:
        doing so would invoke a real provider even though the caller
        configured none, bypassing the governance the guard exists to enforce.
        A built-in adapter is only used when explicitly registered via
        ``provider_overrides``.

        Credentials are never read or logged here.  They are resolved inside
        each adapter (see ``OpenAIProviderAdapter.from_settings``), so a
        missing API key fails closed with a ``ProviderAuthenticationError``
        instead of silently bypassing the provider.
        """
        provider = str(getattr(request, "provider", self.default_provider)).lower()

        # 1. Explicitly registered adapter for this provider wins.
        adapter: ProviderAdapter | None = self.provider_overrides.get(provider)

        # 2. Injected ``provider_caller`` (the injection seam) is used when no
        #    adapter was registered, so tests and the API can substitute a
        #    real or mock LLM without touching provider resolution.
        if adapter is None and self.provider_caller is not None:
            return await self.provider_caller(request)

        if adapter is not None:
            try:
                return await adapter.invoke(request)
            except ProviderAuthenticationError as exc:
                # Re-raise as the client-level error but with secrets redacted.
                raise ProviderError(redact_secrets(str(exc))) from exc
            except ProviderRateLimitError as exc:
                # Bounded retries are the responsibility of the rate limiter.
                raise ProviderRateLimitError(
                    redact_secrets(str(exc)),
                    retry_after_s=exc.retry_after_s,
                    status_code=exc.status_code,
                ) from exc
            except ProviderTransientError as exc:
                raise ProviderTransientError(redact_secrets(str(exc))) from exc
            except ProviderPermanentError as exc:
                raise ProviderPermanentError(redact_secrets(str(exc))) from exc
            except ProviderError:
                raise
            except Exception as exc:
                # Defensive: never leak credential-looking text from a previously
                # uncategorized provider exception.
                raise ProviderTransientError(redact_secrets(str(exc))) from exc

        if self.provider_caller is None:
            raise RuntimeError(
                "No provider caller configured on GuardedLLMClient "
                f"(provider={provider}, provider_caller=None)"
            )
        return await self.provider_caller(request)

    # -----------------------------------------------------------------------
    # Provider / credential management (single, extensible seam)
    # -----------------------------------------------------------------------

    def _bind_adapter(self, provider: str, adapter: ProviderAdapter) -> None:
        """Register an adapter instance under a provider name at runtime."""
        self.provider_overrides[provider] = adapter

    def _make_provider_caller(self, provider: str = "openai") -> Callable[[LLMRequest], Awaitable[Any]]:
        """Construct the legacy ``provider_caller`` for the given provider.

        This is a thin shim: the real work happens inside the adapter, which
        resolves credentials from the environment.  Tests and the API can call
        this when they need the callable form instead of the adapter form.
        """
        return lambda req: self._dispatch_legacy(req, provider)

    async def _dispatch_legacy(self, req: LLMRequest, provider: str) -> Any:
        """Legacy provider-callable shim.

        Dispatches to the adapter for *provider* when one is registered;
        otherwise delegates to the top-level ``provider_caller``.  This keeps
        the legacy callable useful while the adapter replaces it as the
        primary path.
        """
        if provider in PROVIDER_ADAPTERS:
            try:
                adapter = PROVIDER_ADAPTERS[provider]()
            except ProviderAuthenticationError:
                raise
            try:
                return await adapter.invoke(req)
            except ProviderAuthenticationError as exc:
                raise ProviderError(redact_secrets(str(exc))) from exc
            except ProviderRateLimitError as exc:
                raise ProviderRateLimitError(
                    redact_secrets(str(exc)),
                    retry_after_s=exc.retry_after_s,
                    status_code=exc.status_code,
                ) from exc
            except ProviderTransientError as exc:
                raise ProviderTransientError(redact_secrets(str(exc))) from exc
            except ProviderPermanentError as exc:
                raise ProviderPermanentError(redact_secrets(str(exc))) from exc
            except ProviderError:
                raise
            except Exception as exc:
                raise ProviderTransientError(redact_secrets(str(exc))) from exc
        if self.provider_caller is not None:
            return await self.provider_caller(req)
        raise RuntimeError(
                "No provider caller configured on GuardedLLMClient "
                f"(provider={provider})"
            )

    # Shared GuardedLLMClient wired with provider_caller (None), tokenizer, and
    # telemetry sink.  The provider caller is deliberately left unset: the
    # adapter is constructed lazily on the first request, so a missing
    # OPENAI_API_KEY fails closed at first use instead of import time.
    # ``default_provider`` records which provider supplies the runner so the
    # executor boundary can resolve (model, provider, cost) consistently.

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
        requested_max_tokens = action.payload.get("max_tokens")
        max_tokens = 512 if requested_max_tokens is None else requested_max_tokens

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
        estimated_tokens: int | None = None
        retry_count = 0

        try:
            if isinstance(max_tokens, bool) or not isinstance(max_tokens, int) or max_tokens < 1:
                raise ValueError("max_tokens must be a positive integer")

            # 1. Preflight token estimation & context window check
            est_result = self.tokenizer.validate_preflight_context(
                model=model,
                messages=messages,
                max_output_tokens=max_tokens,
            )
            estimated_tokens = est_result.estimated_tokens
            if not est_result.is_supported or estimated_tokens is None:
                raise UnsupportedModelError(
                    est_result.reason
                    or f"Token estimation is unavailable for model '{model}'"
                )

            # 2. Preflight request token limits
            self.budget_manager.validate_request_tokens(
                estimated_input_tokens=estimated_tokens,
                requested_output_tokens=max_tokens,
                config=budget_config,
            )

            # 3. Preflight cost estimation
            est_usage = NormalizedUsage(
                prompt_tokens=estimated_tokens,
                completion_tokens=max_tokens,
                total_tokens=estimated_tokens + max_tokens,
                input_uncached_tokens=estimated_tokens,
                input_cached_tokens=0,
                output_standard_tokens=max_tokens,
                output_reasoning_tokens=0,
                source=TokenUsageSource.ESTIMATED,
            )
            est_cost_record = self.pricing.calculate_cost(
                usage=est_usage,
                provider=provider,
                model=model,
                is_estimate=True,
            )
            if est_cost_record is None or est_cost_record.estimated_cost is None:
                raise UnknownModelPricingError(
                    f"No pricing configured for provider '{provider}', model '{model}'"
                )
            estimated_cost = est_cost_record.estimated_cost

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
                return await self._invoke_through_adapter(request)

            raw_response, retry_count = await self.rate_limiter.execute_with_retries(
                _call_provider,
                estimated_tokens=estimated_tokens,
            )

            # 7. Postflight usage extraction & normalization
            normalized_usage = UsageExtractor.extract_usage(raw_response, provider=provider)
            request_id = UsageExtractor.extract_request_id(raw_response)

            # 8. Postflight precision-safe cost calculation
            actual_cost: CostRecord | None
            if normalized_usage.source == TokenUsageSource.UNAVAILABLE:
                # Keep the reservation conservative when a provider omits
                # usage; do not settle an apparently free call.
                normalized_usage = est_usage
                actual_cost = est_cost_record
            else:
                actual_cost = self.pricing.calculate_cost(
                    usage=normalized_usage,
                    provider=provider,
                    model=model,
                    is_estimate=False,
                )
            if actual_cost is None:
                raise UnknownModelPricingError(
                    f"No pricing configured for provider '{provider}', model '{model}'"
                )

            # 9. Settle actual budget
            await self.budget_manager.settle_budget(
                run_id=run_id,
                reserved_cost=reserved_cost,
                actual_cost=(
                    actual_cost.calculated_cost
                    if actual_cost.calculated_cost is not None
                    else actual_cost.estimated_cost
                ),
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
                correlation_id=self._get_correlation_id(action),
            )

            await self._emit_telemetry(exec_result)
            return exec_result

        except Exception as exc:
            retry_count = int(getattr(exc, "retry_count", retry_count))
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

            est_tokens_fallback = estimated_tokens if estimated_tokens is not None else 0
            fallback_usage = NormalizedUsage(
                prompt_tokens=est_tokens_fallback,
                completion_tokens=0,
                total_tokens=est_tokens_fallback,
                input_uncached_tokens=est_tokens_fallback,
                input_cached_tokens=0,
                output_standard_tokens=0,
                output_reasoning_tokens=0,
                source=TokenUsageSource.ESTIMATED if est_tokens_fallback > 0 else TokenUsageSource.UNAVAILABLE,
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
                correlation_id=self._get_correlation_id(action),
            )

            await self._emit_telemetry(exec_result)
            raise

    @staticmethod
    def _get_correlation_id(action: Action) -> str | None:
        metadata = action.payload.get("_warden")
        if isinstance(metadata, dict):
            value = metadata.get("correlation_id") or metadata.get("trace_id")
            if isinstance(value, str):
                return value
        value = action.payload.get("correlation_id") or action.payload.get("trace_id")
        return value if isinstance(value, str) else None

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
            correlation_id=res.correlation_id,
        )

        try:
            await self.telemetry_sink(telemetry.to_journal_payload())
        except Exception:
            # Provider execution may already have succeeded. Surface journal
            # failure to operators without converting success into a retryable
            # provider failure or risking a duplicate billable call.
            logger.exception(
                "LLM telemetry journal delivery failed for action_id=%s run_id=%s",
                res.action_id,
                res.run_id,
            )
