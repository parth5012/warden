"""Model pricing registry and precision-safe cost calculator.

Inspired by Langfuse's default-model-prices and pricing-tier matcher:
- Maintains versioned, configurable pricing tiers per provider and model.
- Uses deterministic matching: exact (provider, model) match first, regex fallback second.
- Uses Decimal arithmetic with explicit 6-decimal rounding (micro-dollars).
- Completely prevents double charging for cached or reasoning tokens.
- Never fabricates prices or costs for unknown models.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from decimal import Decimal, ROUND_HALF_UP
from typing import Sequence

from warden.llm.types import CostRecord, NormalizedUsage

DECIMAL_ONE_MILLION = Decimal("1000000")
DECIMAL_QUANTIZE_CENTS = Decimal("0.000001")  # Micro-dollar precision


@dataclass(frozen=True)
class PricingTier:
    """Pricing configuration for a model tier."""

    provider: str
    model_pattern: str
    input_cost_per_million: Decimal
    output_cost_per_million: Decimal
    cache_read_cost_per_million: Decimal | None = None
    reasoning_cost_per_million: Decimal | None = None
    currency: str = "USD"
    pricing_version: str = "2024-10-01"
    is_pattern: bool = False


# Default pricing catalog covering standard frontier models
DEFAULT_PRICING_CATALOG: tuple[PricingTier, ...] = (
    # OpenAI GPT-4o
    PricingTier(
        provider="openai",
        model_pattern="gpt-4o",
        input_cost_per_million=Decimal("2.50"),
        output_cost_per_million=Decimal("10.00"),
        cache_read_cost_per_million=Decimal("1.25"),
        reasoning_cost_per_million=None,
    ),
    # OpenAI GPT-4o-mini
    PricingTier(
        provider="openai",
        model_pattern="gpt-4o-mini",
        input_cost_per_million=Decimal("0.15"),
        output_cost_per_million=Decimal("0.60"),
        cache_read_cost_per_million=Decimal("0.075"),
        reasoning_cost_per_million=None,
    ),
    # OpenAI o1
    PricingTier(
        provider="openai",
        model_pattern="o1",
        input_cost_per_million=Decimal("15.00"),
        output_cost_per_million=Decimal("60.00"),
        cache_read_cost_per_million=Decimal("7.50"),
        reasoning_cost_per_million=Decimal("60.00"),
    ),
    # OpenAI o3-mini
    PricingTier(
        provider="openai",
        model_pattern="o3-mini",
        input_cost_per_million=Decimal("1.10"),
        output_cost_per_million=Decimal("4.40"),
        cache_read_cost_per_million=Decimal("0.55"),
        reasoning_cost_per_million=Decimal("4.40"),
    ),
    # OpenAI GPT-4-turbo
    PricingTier(
        provider="openai",
        model_pattern="gpt-4-turbo",
        input_cost_per_million=Decimal("10.00"),
        output_cost_per_million=Decimal("30.00"),
        cache_read_cost_per_million=None,
    ),
    # OpenAI GPT-3.5-turbo
    PricingTier(
        provider="openai",
        model_pattern="gpt-3.5-turbo",
        input_cost_per_million=Decimal("0.50"),
        output_cost_per_million=Decimal("1.50"),
        cache_read_cost_per_million=None,
    ),
    # Anthropic Claude 3.5 Sonnet
    PricingTier(
        provider="anthropic",
        model_pattern="claude-3-5-sonnet",
        input_cost_per_million=Decimal("3.00"),
        output_cost_per_million=Decimal("15.00"),
        cache_read_cost_per_million=Decimal("0.30"),
    ),
    # Anthropic Claude 3.5 Haiku
    PricingTier(
        provider="anthropic",
        model_pattern="claude-3-5-haiku",
        input_cost_per_million=Decimal("0.80"),
        output_cost_per_million=Decimal("4.00"),
        cache_read_cost_per_million=Decimal("0.08"),
    ),
    # Google Gemini 1.5 Pro
    PricingTier(
        provider="google",
        model_pattern="gemini-1.5-pro",
        input_cost_per_million=Decimal("1.25"),
        output_cost_per_million=Decimal("5.00"),
        cache_read_cost_per_million=Decimal("0.3125"),
    ),
    # Google Gemini 1.5 Flash
    PricingTier(
        provider="google",
        model_pattern="gemini-1.5-flash",
        input_cost_per_million=Decimal("0.075"),
        output_cost_per_million=Decimal("0.30"),
        cache_read_cost_per_million=Decimal("0.01875"),
    ),
    # Fallback Pattern tiers (is_pattern=True)
    PricingTier(
        provider="openai",
        model_pattern=r"^gpt-4o(-\d{4}-\d{2}-\d{2})?$",
        input_cost_per_million=Decimal("2.50"),
        output_cost_per_million=Decimal("10.00"),
        cache_read_cost_per_million=Decimal("1.25"),
        is_pattern=True,
    ),
    PricingTier(
        provider="openai",
        model_pattern=r"^gpt-4o-mini(-\d{4}-\d{2}-\d{2})?$",
        input_cost_per_million=Decimal("0.15"),
        output_cost_per_million=Decimal("0.60"),
        cache_read_cost_per_million=Decimal("0.075"),
        is_pattern=True,
    ),
    PricingTier(
        provider="anthropic",
        model_pattern=r"^claude-3-5-sonnet(-\d{8})?$",
        input_cost_per_million=Decimal("3.00"),
        output_cost_per_million=Decimal("15.00"),
        cache_read_cost_per_million=Decimal("0.30"),
        is_pattern=True,
    ),
)


class PricingRegistry:
    """Manages versioned model pricing and deterministic tier resolution."""

    def __init__(self, catalog: Sequence[PricingTier] = DEFAULT_PRICING_CATALOG) -> None:
        self._exact_tiers: dict[tuple[str, str], PricingTier] = {}
        self._pattern_tiers: list[PricingTier] = []

        for tier in catalog:
            if tier.is_pattern:
                self._pattern_tiers.append(tier)
            else:
                self._exact_tiers[(tier.provider.lower(), tier.model_pattern.lower())] = tier

    def register_tier(self, tier: PricingTier) -> None:
        """Register or update a pricing tier."""
        if tier.is_pattern:
            self._pattern_tiers.insert(0, tier)
        else:
            self._exact_tiers[(tier.provider.lower(), tier.model_pattern.lower())] = tier

    def resolve_tier(self, provider: str, model: str) -> tuple[PricingTier | None, bool]:
        """Deterministic resolution: exact match first, pattern match second.

        Returns (tier, is_exact_match).
        """
        p_clean = provider.strip().lower()
        m_clean = model.strip().lower()

        # 1. Exact match
        exact_key = (p_clean, m_clean)
        if exact_key in self._exact_tiers:
            return self._exact_tiers[exact_key], True

        # 2. Pattern match
        for p_tier in self._pattern_tiers:
            if p_tier.provider.lower() == p_clean:
                try:
                    if re.match(p_tier.model_pattern, m_clean):
                        return p_tier, False
                except re.error:
                    continue

        return None, False

    def calculate_cost(
        self,
        usage: NormalizedUsage,
        provider: str,
        model: str,
        is_estimate: bool = False,
    ) -> CostRecord | None:
        """Calculate precision-safe cost from mutually-exclusive usage buckets.

        Returns None if model has no pricing entry (cost unknown, never fabricated).
        """
        tier, is_exact = self.resolve_tier(provider, model)
        if tier is None:
            return None

        # Resolve rates
        input_rate = tier.input_cost_per_million
        output_rate = tier.output_cost_per_million
        cache_rate = tier.cache_read_cost_per_million if tier.cache_read_cost_per_million is not None else input_rate
        reasoning_rate = tier.reasoning_cost_per_million if tier.reasoning_cost_per_million is not None else output_rate

        # Bucket amounts as Decimal
        uncached_in = Decimal(usage.input_uncached_tokens)
        cached_in = Decimal(usage.input_cached_tokens)
        standard_out = Decimal(usage.output_standard_tokens)
        reasoning_out = Decimal(usage.output_reasoning_tokens)

        # Precise computation per million
        cost_uncached = (uncached_in * input_rate) / DECIMAL_ONE_MILLION
        cost_cached = (cached_in * cache_rate) / DECIMAL_ONE_MILLION
        cost_standard = (standard_out * output_rate) / DECIMAL_ONE_MILLION
        cost_reasoning = (reasoning_out * reasoning_rate) / DECIMAL_ONE_MILLION

        total_cost = (cost_uncached + cost_cached + cost_standard + cost_reasoning).quantize(
            DECIMAL_QUANTIZE_CENTS, rounding=ROUND_HALF_UP
        )

        return CostRecord(
            calculated_cost=total_cost if not is_estimate else None,
            estimated_cost=total_cost if is_estimate else None,
            currency=tier.currency,
            pricing_version=tier.pricing_version,
            model=model,
            provider=provider,
            matched_pattern=tier.model_pattern,
            is_exact_match=is_exact,
        )
