"""Guarded LLM Client package for Aegis.

Provides token usage extraction, normalization, pricing, rate limiting,
budget enforcement, and telemetry.
"""

from warden.llm.budget import BudgetManager, RunBudgetTracker
from warden.llm.client import GuardedLLMClient, LLMExecutionResult, redact_secrets
from warden.llm.extraction import UsageExtractor
from warden.llm.pricing import DEFAULT_PRICING_CATALOG, PricingRegistry, PricingTier
from warden.llm.rate_limiter import RateLimitingExecutor, SlidingWindowRateLimiter
from warden.llm.tokenizer import (
    DEFAULT_CONTEXT_WINDOWS,
    DEFAULT_ENCODING_MAP,
    TokenEstimationResult,
    TokenEstimator,
)
from warden.llm.types import (
    BudgetConfig,
    BudgetExceededError,
    ContextWindowExceededError,
    CostRecord,
    LLMClientError,
    LLMRequest,
    LLMResponse,
    LLMUsageTelemetry,
    NonRetryableProviderError,
    NormalizedUsage,
    RateLimitConfig,
    RateLimitExceededError,
    RetryableProviderError,
    TokenLimitExceededError,
    TokenUsageSource,
    UnknownModelPricingError,
    UnsupportedModelError,
)

__all__ = [
    "BudgetConfig",
    "BudgetExceededError",
    "BudgetManager",
    "ContextWindowExceededError",
    "CostRecord",
    "DEFAULT_CONTEXT_WINDOWS",
    "DEFAULT_ENCODING_MAP",
    "DEFAULT_PRICING_CATALOG",
    "GuardedLLMClient",
    "LLMClientError",
    "LLMExecutionResult",
    "LLMRequest",
    "LLMResponse",
    "LLMUsageTelemetry",
    "NonRetryableProviderError",
    "NormalizedUsage",
    "PricingRegistry",
    "PricingTier",
    "RateLimitConfig",
    "RateLimitExceededError",
    "RateLimitingExecutor",
    "RetryableProviderError",
    "RunBudgetTracker",
    "SlidingWindowRateLimiter",
    "TokenEstimationResult",
    "TokenEstimator",
    "TokenLimitExceededError",
    "TokenUsageSource",
    "UnknownModelPricingError",
    "UnsupportedModelError",
    "UsageExtractor",
    "redact_secrets",
]
