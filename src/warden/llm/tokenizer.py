"""Local token estimation and context-window validation layer.

Uses tiktoken for OpenAI-compatible models with explicit message-overhead accounting
and strictly flags unsupported models rather than fabricating counts.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import tiktoken

from warden.llm.types import ContextWindowExceededError


@dataclass(frozen=True)
class TokenEstimationResult:
    """Outcome of preflight token estimation."""

    is_supported: bool
    estimated_tokens: int | None
    encoding_name: str | None = None
    reason: str | None = None


# Known context window token limits
DEFAULT_CONTEXT_WINDOWS: dict[str, int] = {
    # OpenAI
    "gpt-4o": 128_000,
    "gpt-4o-mini": 128_000,
    "chatgpt-4o-latest": 128_000,
    "o1": 200_000,
    "o1-preview": 128_000,
    "o1-mini": 128_000,
    "o3-mini": 200_000,
    "gpt-4-turbo": 128_000,
    "gpt-4-turbo-preview": 128_000,
    "gpt-4": 8_192,
    "gpt-4-32k": 32_768,
    "gpt-3.5-turbo": 16_385,
    "gpt-3.5-turbo-16k": 16_385,
    # Anthropic
    "claude-3-5-sonnet": 200_000,
    "claude-3-5-sonnet-20241022": 200_000,
    "claude-3-5-haiku": 200_000,
    "claude-3-5-haiku-20241022": 200_000,
    "claude-3-opus": 200_000,
    "claude-3-opus-20240229": 200_000,
    # Google
    "gemini-1.5-pro": 2_000_000,
    "gemini-1.5-flash": 1_000_000,
    "gemini-2.0-flash": 1_000_000,
    # Groq-hosted GPT-OSS models
    "openai/gpt-oss-20b": 131_072,
    "openai/gpt-oss-120b": 131_072,
}

# Known model to tiktoken encoding mappings
DEFAULT_ENCODING_MAP: dict[str, str] = {
    "gpt-4o": "o200k_base",
    "gpt-4o-mini": "o200k_base",
    "chatgpt-4o-latest": "o200k_base",
    "o1": "o200k_base",
    "o1-preview": "o200k_base",
    "o1-mini": "o200k_base",
    "o3-mini": "o200k_base",
    "gpt-4-turbo": "cl100k_base",
    "gpt-4-turbo-preview": "cl100k_base",
    "gpt-4": "cl100k_base",
    "gpt-4-32k": "cl100k_base",
    "gpt-3.5-turbo": "cl100k_base",
    "gpt-3.5-turbo-16k": "cl100k_base",
    "openai/gpt-oss-20b": "o200k_base",
    "openai/gpt-oss-120b": "o200k_base",
}


class TokenEstimator:
    """Preflight tokenizer and context-window gate."""

    def __init__(
        self,
        encoding_overrides: dict[str, str] | None = None,
        context_window_overrides: dict[str, int] | None = None,
    ) -> None:
        self._encoding_map = dict(DEFAULT_ENCODING_MAP)
        if encoding_overrides:
            self._encoding_map.update(encoding_overrides)

        self._context_windows = dict(DEFAULT_CONTEXT_WINDOWS)
        if context_window_overrides:
            self._context_windows.update(context_window_overrides)

        self._cached_encoders: dict[str, tiktoken.Encoding] = {}

    def get_encoding_for_model(self, model: str) -> tiktoken.Encoding | None:
        """Resolve tiktoken encoding for model, or None if unsupported."""
        clean_model = model.strip().lower()

        # Check explicit map
        encoding_name = self._encoding_map.get(clean_model)
        if not encoding_name:
            # Check prefixes
            for m_prefix, enc in self._encoding_map.items():
                if clean_model.startswith(m_prefix):
                    encoding_name = enc
                    break

        if not encoding_name:
            try:
                encoding = tiktoken.encoding_for_model(model)
                return encoding
            except KeyError:
                return None

        if encoding_name not in self._cached_encoders:
            try:
                self._cached_encoders[encoding_name] = tiktoken.get_encoding(encoding_name)
            except Exception:
                return None

        return self._cached_encoders[encoding_name]

    def get_context_window(self, model: str) -> int | None:
        """Resolve configured context window token limit for model."""
        clean_model = model.strip().lower()
        if clean_model in self._context_windows:
            return self._context_windows[clean_model]

        for m_prefix, limit in self._context_windows.items():
            if clean_model.startswith(m_prefix):
                return limit

        return None

    def count_tokens(self, model: str, text: str) -> int:
        """Count tokens in text for model, or return 0 when unavailable.

        Unlike the old implementation, an unsupported model never maps to a
        guessed count of zero: it is surfaced through the estimator result so
        budget and spend policy can treat it as an unknown (and refuse to
        proceed) instead of silently allowing the request.
        """
        res = self.estimate_text_tokens(text=text, model=model)
        return res.estimated_tokens or 0

    def estimate_tokens(self, text: str, model: str) -> TokenEstimationResult:
        """Explicit, safe token estimation for raw text.

        Returns an explicit ``TokenEstimationResult`` that distinguishes:
        - supported + counted tokens
        - unsupported (no compatible encoding) tokens -> estimated_tokens=None

        This matters because a zero is never a valid stand-in for an unknown
        token count: budget and spend limits must not be bypassed when the
        estimator cannot say how many tokens a prompt contains.
        """
        return self.estimate_text_tokens(text=text, model=model)

    def estimate_text_tokens(self, text: str, model: str) -> TokenEstimationResult:
        """Estimate token count for a raw string.

        Returns None for the token count when the model is unsupported.  A
        request that cannot be token-counted is never treated as zero.
        """
        encoder = self.get_encoding_for_model(model)
        if encoder is None:
            return TokenEstimationResult(
                is_supported=False,
                estimated_tokens=None,
                reason=f"No compatible tiktoken encoding found for model '{model}'",
            )

        token_count = len(encoder.encode(text, disallowed_special=()))
        return TokenEstimationResult(
            is_supported=True,
            estimated_tokens=token_count,
            encoding_name=encoder.name,
        )

    def estimate_messages_tokens(
        self,
        messages: list[dict[str, Any]],
        model: str,
    ) -> TokenEstimationResult:
        """Estimate chat messages token count including formatting framing overhead.

        Accurately models OpenAI chat formatting:
        - 3 tokens per message (<|im_start|>{role}\n{content}<|im_end|>)
        - 1 token if 'name' is provided
        - 3 tokens for primer reply prefix (<|im_start|>assistant<|im_sep|>)
        """
        encoder = self.get_encoding_for_model(model)
        if encoder is None:
            return TokenEstimationResult(
                is_supported=False,
                estimated_tokens=None,
                reason=f"No compatible tiktoken encoding found for model '{model}'",
            )

        tokens_per_message = 3
        tokens_per_name = 1

        num_tokens = 0
        for message in messages:
            num_tokens += tokens_per_message
            for key, value in message.items():
                if value is None:
                    continue

                if isinstance(value, str):
                    text = value
                elif isinstance(value, (dict, list)):
                    try:
                        text = json.dumps(value, ensure_ascii=False)
                    except Exception:
                        text = str(value)
                else:
                    text = str(value)

                num_tokens += len(encoder.encode(text, disallowed_special=()))
                if key == "name":
                    num_tokens += tokens_per_name

        num_tokens += 3  # Assistant reply priming overhead

        return TokenEstimationResult(
            is_supported=True,
            estimated_tokens=num_tokens,
            encoding_name=encoder.name,
        )

    def validate_preflight_context(
        self,
        model: str,
        messages: list[dict[str, Any]],
        max_output_tokens: int | None = None,
    ) -> TokenEstimationResult:
        """Validate that the request can fit inside the model's context window.

        Raises ContextWindowExceededError if limit is configured and exceeded.
        """
        estimation = self.estimate_messages_tokens(messages, model)
        context_limit = self.get_context_window(model)

        if estimation.is_supported and estimation.estimated_tokens is not None and context_limit is not None:
            requested_output = max_output_tokens or 0
            total_required = estimation.estimated_tokens + requested_output
            if total_required > context_limit:
                raise ContextWindowExceededError(
                    model=model,
                    required_tokens=total_required,
                    limit=context_limit,
                )

        return estimation
