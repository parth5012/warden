"""Budget enforcement layer for request-level and run-level limits.

Enforces:
- Per-request limits on estimated input tokens, max output tokens, and total tokens.
- Per-request spend limits.
- Run-level spend limits with race-safe atomic reservation and settlement.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

from warden.llm.types import (
    BudgetConfig,
    BudgetExceededError,
    TokenLimitExceededError,
)


@dataclass
class RunBudgetTracker:
    """Tracks cumulative spend and active reservations for an agent run."""

    max_spend: Decimal
    settled_spend: Decimal = Decimal("0.0")
    reserved_spend: Decimal = Decimal("0.0")
    total_tokens: int = 0
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    @property
    def total_committed(self) -> Decimal:
        return self.settled_spend + self.reserved_spend

    @property
    def remaining_budget(self) -> Decimal:
        return max(Decimal("0.0"), self.max_spend - self.total_committed)


class BudgetManager:
    """Thread-safe and async-safe budget manager."""

    def __init__(self, default_config: BudgetConfig | None = None) -> None:
        self.default_config = default_config or BudgetConfig()
        self._runs: dict[str, RunBudgetTracker] = {}
        self._global_lock = asyncio.Lock()

    async def get_or_create_run_tracker(
        self,
        run_id: str,
        config: BudgetConfig | None = None,
    ) -> RunBudgetTracker | None:
        """Retrieve or initialize the tracker for run_id if budget limit is configured."""
        effective_cfg = config or self.default_config
        if effective_cfg.max_spend_per_run is None:
            return None

        async with self._global_lock:
            if run_id not in self._runs:
                self._runs[run_id] = RunBudgetTracker(max_spend=effective_cfg.max_spend_per_run)
            return self._runs[run_id]

    def validate_request_tokens(
        self,
        estimated_input_tokens: int | None,
        requested_output_tokens: int | None,
        config: BudgetConfig | None = None,
    ) -> None:
        """Validate per-request token limits before calling provider."""
        cfg = config or self.default_config

        if cfg.max_input_tokens_per_request is not None and estimated_input_tokens is not None:
            if estimated_input_tokens > cfg.max_input_tokens_per_request:
                raise TokenLimitExceededError(
                    f"Estimated input tokens ({estimated_input_tokens}) exceeds per-request limit ({cfg.max_input_tokens_per_request})"
                )

        if cfg.max_output_tokens_per_request is not None and requested_output_tokens is not None:
            if requested_output_tokens > cfg.max_output_tokens_per_request:
                raise TokenLimitExceededError(
                    f"Requested output tokens ({requested_output_tokens}) exceeds per-request limit ({cfg.max_output_tokens_per_request})"
                )

        if cfg.max_total_tokens_per_request is not None:
            total_est = (estimated_input_tokens or 0) + (requested_output_tokens or 0)
            if total_est > cfg.max_total_tokens_per_request:
                raise TokenLimitExceededError(
                    f"Estimated total tokens ({total_est}) exceeds per-request limit ({cfg.max_total_tokens_per_request})"
                )

    def validate_request_cost(
        self,
        estimated_cost: Decimal | None,
        config: BudgetConfig | None = None,
    ) -> None:
        """Validate per-request spend limit."""
        cfg = config or self.default_config
        if cfg.max_spend_per_request is not None and estimated_cost is not None:
            if estimated_cost > cfg.max_spend_per_request:
                raise BudgetExceededError(
                    f"Estimated request cost (${estimated_cost}) exceeds per-request limit (${cfg.max_spend_per_request})",
                    required_spend=estimated_cost,
                    limit=cfg.max_spend_per_request,
                )

    async def reserve_budget(
        self,
        run_id: str,
        estimated_cost: Decimal | None,
        config: BudgetConfig | None = None,
    ) -> Decimal:
        """Atomically reserve estimated cost against the run budget before dispatching.

        Returns reserved amount.
        """
        if estimated_cost is None or estimated_cost <= Decimal("0"):
            return Decimal("0")

        tracker = await self.get_or_create_run_tracker(run_id, config)
        if tracker is None:
            return Decimal("0")

        async with tracker.lock:
            if tracker.total_committed + estimated_cost > tracker.max_spend:
                raise BudgetExceededError(
                    f"Run '{run_id}' budget exceeded: requires ${estimated_cost}, "
                    f"remaining budget is ${tracker.remaining_budget} of ${tracker.max_spend}",
                    required_spend=estimated_cost,
                    limit=tracker.max_spend,
                )
            tracker.reserved_spend += estimated_cost
            return estimated_cost

    async def settle_budget(
        self,
        run_id: str,
        reserved_cost: Decimal,
        actual_cost: Decimal | None,
        actual_tokens: int = 0,
        config: BudgetConfig | None = None,
    ) -> None:
        """Settle actual cost and release reservation upon completion."""
        tracker = await self.get_or_create_run_tracker(run_id, config)
        if tracker is None:
            return

        async with tracker.lock:
            # Release reservation
            tracker.reserved_spend = max(Decimal("0"), tracker.reserved_spend - reserved_cost)
            # Add actual cost
            if actual_cost is not None:
                tracker.settled_spend += actual_cost
            tracker.total_tokens += actual_tokens

    async def release_reservation(
        self,
        run_id: str,
        reserved_cost: Decimal,
        config: BudgetConfig | None = None,
    ) -> None:
        """Release reservation without settling spend (e.g. on error)."""
        if reserved_cost <= Decimal("0"):
            return

        tracker = await self.get_or_create_run_tracker(run_id, config)
        if tracker is None:
            return

        async with tracker.lock:
            tracker.reserved_spend = max(Decimal("0"), tracker.reserved_spend - reserved_cost)
