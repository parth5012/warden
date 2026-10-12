"""Usage extraction and normalization layer for Guarded LLM Client.

Adapted from Langfuse's ingestion and usage extraction architecture:
- Extracts native provider usage metadata from OpenAI, Anthropic, Google Gemini,
  and generic API/LangChain response objects.
- Normalizes usage into strictly mutually-exclusive token buckets to eliminate
  double counting of cached and reasoning tokens.
- Preserves raw diagnostics without mutating or fabricating data.
"""

from __future__ import annotations

from typing import Any

from warden.llm.types import NormalizedUsage, TokenUsageSource


class UsageExtractor:
    """Extracts and normalizes token usage and request identifiers across providers."""

    @classmethod
    def extract_request_id(cls, response: Any) -> str | None:
        """Extract provider request identifier if available."""
        if response is None:
            return None

        # Check attribute (OpenAI response, Pydantic model)
        if hasattr(response, "id") and isinstance(response.id, str):
            return response.id

        # Check dict
        if isinstance(response, dict):
            if "id" in response and isinstance(response["id"], str):
                return response["id"]
            if "request_id" in response and isinstance(response["request_id"], str):
                return response["request_id"]
            if "headers" in response and isinstance(response["headers"], dict):
                headers = response["headers"]
                return (
                    headers.get("x-request-id")
                    or headers.get("request-id")
                    or headers.get("apim-request-id")
                )

        # Check response_metadata (LangChain)
        if hasattr(response, "response_metadata") and isinstance(response.response_metadata, dict):
            meta = response.response_metadata
            return meta.get("id") or meta.get("request_id")

        return None

    @classmethod
    def extract_usage(
        cls,
        response: Any,
        provider: str = "openai",
    ) -> NormalizedUsage:
        """Extract and normalize provider usage into mutually-exclusive buckets."""
        if response is None:
            return cls._empty_usage(TokenUsageSource.UNAVAILABLE)

        raw_usage = cls._get_raw_usage_dict(response)
        if not raw_usage:
            return cls._empty_usage(TokenUsageSource.UNAVAILABLE)

        provider_norm = provider.lower()
        if "anthropic" in provider_norm:
            return cls._normalize_anthropic(raw_usage)
        elif "google" in provider_norm or "gemini" in provider_norm:
            return cls._normalize_google(raw_usage)
        else:
            # Default to OpenAI / standard format
            return cls._normalize_openai(raw_usage)

    @classmethod
    def _get_raw_usage_dict(cls, response: Any) -> dict[str, Any]:
        """Convert various response formats into a raw usage dictionary."""
        # Case 1: Response itself is a usage dict
        if isinstance(response, dict) and ("prompt_tokens" in response or "input_tokens" in response):
            return response

        # Case 2: Dict with 'usage' or 'usage_metadata' key
        if isinstance(response, dict):
            if "usage" in response:
                usage = response["usage"]
                if isinstance(usage, dict):
                    return usage
                if hasattr(usage, "model_dump"):
                    return usage.model_dump()  # type: ignore[no-any-return]
                if hasattr(usage, "__dict__"):
                    return dict(usage.__dict__)
            if "usage_metadata" in response:
                meta = response["usage_metadata"]
                if isinstance(meta, dict):
                    return meta
                if hasattr(meta, "__dict__"):
                    return dict(meta.__dict__)

        # Case 3: Object with .usage attribute (OpenAI Completion / ChatCompletion)
        if hasattr(response, "usage") and response.usage is not None:
            usage = response.usage
            if isinstance(usage, dict):
                return usage
            if hasattr(usage, "model_dump"):
                return usage.model_dump()  # type: ignore[no-any-return]
            # Extract common attributes from object
            obj_dict: dict[str, Any] = {}
            for attr in (
                "prompt_tokens",
                "completion_tokens",
                "total_tokens",
                "prompt_tokens_details",
                "completion_tokens_details",
                "input_tokens",
                "output_tokens",
            ):
                if hasattr(usage, attr):
                    obj_dict[attr] = getattr(usage, attr)
            if obj_dict:
                return obj_dict
            if hasattr(usage, "__dict__"):
                return dict(usage.__dict__)

        # Case 4: LangChain AIMessage with usage_metadata
        if hasattr(response, "usage_metadata") and isinstance(response.usage_metadata, dict):
            return response.usage_metadata

        # Case 5: LangChain AIMessage with response_metadata["token_usage"] or response_metadata["usage"]
        if hasattr(response, "response_metadata") and isinstance(response.response_metadata, dict):
            meta = response.response_metadata
            if "token_usage" in meta and isinstance(meta["token_usage"], dict):
                return meta["token_usage"]
            if "usage" in meta and isinstance(meta["usage"], dict):
                return meta["usage"]

        # Case 6: Google Gemini usage_metadata
        if hasattr(response, "usage_metadata") and response.usage_metadata is not None:
            meta = response.usage_metadata
            if hasattr(meta, "__dict__"):
                return dict(meta.__dict__)
            if isinstance(meta, dict):
                return meta

        return {}

    @classmethod
    def _normalize_openai(cls, raw: dict[str, Any]) -> NormalizedUsage:
        """Normalize OpenAI-compatible usage dictionary.

        OpenAI returns:
        - prompt_tokens (includes cached_tokens)
        - completion_tokens (includes reasoning_tokens)
        - total_tokens
        - prompt_tokens_details: { cached_tokens: int }
        - completion_tokens_details: { reasoning_tokens: int }
        """
        prompt_tokens = int(raw.get("prompt_tokens") or raw.get("input_tokens") or 0)
        completion_tokens = int(raw.get("completion_tokens") or raw.get("output_tokens") or 0)
        reported_total = raw.get("total_tokens")

        # Cached tokens extraction
        prompt_details = raw.get("prompt_tokens_details") or {}
        if isinstance(prompt_details, dict):
            cached_val = prompt_details.get("cached_tokens", 0)
        elif hasattr(prompt_details, "cached_tokens"):
            cached_val = getattr(prompt_details, "cached_tokens", 0)
        else:
            cached_val = raw.get("cached_tokens", 0)
        cached_tokens = int(cached_val or 0)

        # Reasoning tokens extraction
        comp_details = raw.get("completion_tokens_details") or {}
        if isinstance(comp_details, dict):
            reasoning_val = comp_details.get("reasoning_tokens", 0)
        elif hasattr(comp_details, "reasoning_tokens"):
            reasoning_val = getattr(comp_details, "reasoning_tokens", 0)
        else:
            reasoning_val = raw.get("reasoning_tokens", 0)
        reasoning_tokens = int(reasoning_val or 0)

        # Ensure mutually exclusive accounting:
        # Prompt tokens from OpenAI includes cached tokens
        input_cached = max(0, cached_tokens)
        input_uncached = max(0, prompt_tokens - input_cached)

        # Completion tokens from OpenAI includes reasoning tokens
        output_reasoning = max(0, reasoning_tokens)
        output_standard = max(0, completion_tokens - output_reasoning)

        total_calculated = input_uncached + input_cached + output_standard + output_reasoning
        total_tokens = int(reported_total) if reported_total is not None else total_calculated

        return NormalizedUsage(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            input_uncached_tokens=input_uncached,
            input_cached_tokens=input_cached,
            output_standard_tokens=output_standard,
            output_reasoning_tokens=output_reasoning,
            source=TokenUsageSource.PROVIDER_REPORTED,
            raw_usage=raw,
        )

    @classmethod
    def _normalize_anthropic(cls, raw: dict[str, Any]) -> NormalizedUsage:
        """Normalize Anthropic usage dictionary.

        Anthropic returns:
        - input_tokens: int (non-cached)
        - output_tokens: int
        - cache_creation_input_tokens: int (optional)
        - cache_read_input_tokens: int (optional)
        """
        input_uncached = int(raw.get("input_tokens", 0))
        output_standard = int(raw.get("output_tokens", 0))
        cached_read = int(raw.get("cache_read_input_tokens", 0))
        # Note: cache_creation_input_tokens is also uncached input billed at higher rate
        cache_creation = int(raw.get("cache_creation_input_tokens", 0))

        total_input_uncached = input_uncached + cache_creation
        input_cached = cached_read
        prompt_tokens = total_input_uncached + input_cached
        completion_tokens = output_standard
        total_tokens = prompt_tokens + completion_tokens

        return NormalizedUsage(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            input_uncached_tokens=total_input_uncached,
            input_cached_tokens=input_cached,
            output_standard_tokens=output_standard,
            output_reasoning_tokens=0,
            source=TokenUsageSource.PROVIDER_REPORTED,
            raw_usage=raw,
        )

    @classmethod
    def _normalize_google(cls, raw: dict[str, Any]) -> NormalizedUsage:
        """Normalize Google Gemini usage metadata."""
        prompt_tokens = int(raw.get("prompt_token_count", 0))
        completion_tokens = int(raw.get("candidates_token_count", 0))
        cached_tokens = int(raw.get("cached_content_token_count", 0))

        input_cached = max(0, cached_tokens)
        input_uncached = max(0, prompt_tokens - input_cached)
        total_tokens = int(raw.get("total_token_count") or (prompt_tokens + completion_tokens))

        return NormalizedUsage(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            input_uncached_tokens=input_uncached,
            input_cached_tokens=input_cached,
            output_standard_tokens=completion_tokens,
            output_reasoning_tokens=0,
            source=TokenUsageSource.PROVIDER_REPORTED,
            raw_usage=raw,
        )

    @classmethod
    def _empty_usage(cls, source: TokenUsageSource) -> NormalizedUsage:
        return NormalizedUsage(
            prompt_tokens=0,
            completion_tokens=0,
            total_tokens=0,
            input_uncached_tokens=0,
            input_cached_tokens=0,
            output_standard_tokens=0,
            output_reasoning_tokens=0,
            source=source,
            raw_usage={},
        )
