"""Rate limiting, concurrency throttling, and bounded retry policy.

Implements:
- Sliding-window request and token rate limiting per minute.
- In-flight concurrency bounding using asyncio.Semaphore.
- Bounded retries with exponential backoff, jitter, and Retry-After support.
- Clear retryable vs non-retryable error classification.
"""

from __future__ import annotations

import asyncio
import random
import time
from typing import Any, Awaitable, Callable, TypeVar

from warden.llm.types import (
    BudgetExceededError,
    ContextWindowExceededError,
    NonRetryableProviderError,
    RateLimitConfig,
    RateLimitExceededError,
    RetryableProviderError,
    TokenLimitExceededError,
)

T = TypeVar("T")


class SlidingWindowRateLimiter:
    """Sliding-window rate limiter for requests and tokens per minute."""

    def __init__(self, max_requests_per_minute: int = 60, max_tokens_per_minute: int = 100_000) -> None:
        self.max_rpm = max_requests_per_minute
        self.max_tpm = max_tokens_per_minute
        self._request_timestamps: list[float] = []
        self._token_entries: list[tuple[float, int]] = []
        self._lock = asyncio.Lock()

    async def acquire(self, estimated_tokens: int = 0) -> None:
        """Acquire rate limit capacity, or raise RateLimitExceededError if limit is reached."""
        async with self._lock:
            now = time.monotonic()
            window_start = now - 60.0

            # Prune entries older than 60 seconds
            self._request_timestamps = [ts for ts in self._request_timestamps if ts > window_start]
            self._token_entries = [entry for entry in self._token_entries if entry[0] > window_start]

            # Check RPM
            if len(self._request_timestamps) >= self.max_rpm:
                raise RateLimitExceededError(
                    f"Local rate limit reached: {len(self._request_timestamps)}/{self.max_rpm} requests per minute"
                )

            # Check TPM
            current_tokens = sum(count for _, count in self._token_entries)
            if current_tokens + estimated_tokens > self.max_tpm:
                raise RateLimitExceededError(
                    f"Local token rate limit reached: {current_tokens + estimated_tokens}/{self.max_tpm} tokens per minute"
                )

            # Record entry
            self._request_timestamps.append(now)
            self._token_entries.append((now, estimated_tokens))


class RateLimitingExecutor:
    """Combines concurrency limiting, sliding window throttling, and retry policies."""

    def __init__(self, config: RateLimitConfig | None = None) -> None:
        self.config = config or RateLimitConfig()
        self.limiter = SlidingWindowRateLimiter(
            max_requests_per_minute=self.config.max_requests_per_minute,
            max_tokens_per_minute=self.config.max_tokens_per_minute,
        )
        self.semaphore = asyncio.Semaphore(self.config.max_concurrent_requests)

    def is_retryable(self, exception: Exception) -> bool:
        """Determine whether an exception is safe and eligible for retry."""
        if isinstance(
            exception,
            (
                ContextWindowExceededError,
                TokenLimitExceededError,
                BudgetExceededError,
                NonRetryableProviderError,
            ),
        ):
            return False

        if isinstance(exception, (RetryableProviderError, asyncio.TimeoutError, ConnectionError)):
            return True

        # Check status codes on generic HTTP exceptions (e.g., openai.APIStatusError)
        status = getattr(exception, "status_code", None)
        if status in (429, 500, 502, 503, 504):
            return True
        if status in (400, 401, 403, 404):
            return False

        # Check error message strings
        msg = str(exception).lower()
        if "rate limit" in msg or "429" in msg or "overloaded" in msg or "timeout" in msg:
            return True

        return False

    def get_retry_delay(self, attempt: int, exception: Exception | None = None) -> float:
        """Compute delay using Retry-After header or exponential backoff with full jitter."""
        if isinstance(exception, RetryableProviderError) and exception.retry_after_s is not None:
            return min(self.config.max_backoff_s, max(0.1, exception.retry_after_s))

        # Check for retry_after on generic exception
        if exception is not None and hasattr(exception, "retry_after"):
            ra = getattr(exception, "retry_after")
            if isinstance(ra, (int, float)):
                return min(self.config.max_backoff_s, max(0.1, float(ra)))

        # Exponential backoff with jitter
        backoff = min(
            self.config.max_backoff_s,
            self.config.initial_backoff_s * (self.config.backoff_multiplier ** attempt),
        )
        # Full jitter between backoff/2 and backoff
        jitter = random.uniform(backoff * 0.5, backoff)
        return jitter

    async def execute_with_retries(
        self,
        coro_fn: Callable[[], Awaitable[T]],
        estimated_tokens: int = 0,
    ) -> tuple[T, int]:
        """Execute coro_fn under concurrency semaphore and rate limiter with bounded retries.

        Returns (result, retry_count).
        """
        retries = 0
        last_exception: Exception | None = None

        while retries <= self.config.max_retries:
            try:
                # 1. Rate limiter check
                await self.limiter.acquire(estimated_tokens=estimated_tokens)

                # 2. Concurrency bound + timeout
                async with self.semaphore:
                    result = await asyncio.wait_for(coro_fn(), timeout=self.config.timeout_s)
                    return result, retries

            except Exception as exc:
                last_exception = exc
                if not self.is_retryable(exc) or retries >= self.config.max_retries:
                    try:
                        setattr(exc, "retry_count", retries)
                    except Exception:
                        pass
                    raise

                delay = self.get_retry_delay(retries, exc)
                retries += 1
                await asyncio.sleep(delay)

        if last_exception:
            try:
                setattr(last_exception, "retry_count", retries)
            except Exception:
                pass
            raise last_exception
        raise RuntimeError("Retry loop exited without result or exception")
