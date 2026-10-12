"""Provider adapters for Aegis's Guarded LLM Client.

The `GuardedLLMClient` has a single injection seam for a real LLM: the
callable stored in ``provider_caller``.  To keep that seam replaceable (so
new providers can be added later without touching ``client.py``), we wrap a
small, versioned **ProviderAdapter** protocol underneath the existing
``provider_caller``.  The legacy ``provider_caller`` callable remains the
default path so existing tests and the backend API keep working without
changes.

Provider adapters are responsible for:

* mapping a WARDEN ``LLMRequest`` onto the provider SDK
* returning a response object in the shape the existing extraction/normalization
  code already understands (``.choices[].message.content`` and ``.usage``)
* classifying transient (retryable) vs permanent (non-retryable) errors
* injecting correlation/request IDs and (optionally) provider usage metadata

Security rules implemented here:

* No secrets are hard-coded; provider credentials come exclusively from the
  environment (see ``settings`` / ``os.environ``).
* API keys are redacted from every error message and telemetry record.
* No retry, other than the bounded exponential backoff already applied by
  ``RateLimitingExecutor``, is performed here.  Retries must never duplicate
  an unsafe operation, so this adapter performs **idempotent reads only**.
"""

from __future__ import annotations

import os
import re
import time
from abc import ABC, abstractmethod
from typing import Any, Awaitable, Callable

# Local, copy of the project-wide credential regex so provider adapters never
# import redaction logic from the client (which would create a cycle back into
# warden.llm.client -> providers).  Kept in sync with warden.llm.client.SECRET_PATTERN.
_SECRET_PATTERN = re.compile(
    r"(?:bearer\s+[a-zA-Z0-9_\-\.]{15,}|sk-[a-zA-Z0-9_\-]{20,}|gsk_[a-zA-Z0-9_\-]{20,}|key=[a-zA-Z0-9_\-]{15,})",
    re.IGNORECASE,
)


def _redact_secrets(text: str) -> str:
    """Redact sensitive API keys or authorization tokens."""
    return _SECRET_PATTERN.sub("[REDACTED_SECRET]", text)

from warden.llm.types import LLMRequest

# Provider identifiers used in the adapter registry.
PROVIDER_OPENAI = "openai"
PROVIDER_ANTHROPIC = "anthropic"
PROVIDER_GEMINI = "google"


class ProviderError(Exception):
    """Base exception for provider adapter failures."""


class ProviderAuthenticationError(ProviderError):
    """Credential missing or invalid (401/403 semantics)."""


class ProviderRateLimitError(ProviderError):
    """Transient overload / quota error (429 semantics)."""

    def __init__(self, message: str, retry_after_s: float | None = None, status_code: int | None = None) -> None:
        super().__init__(message)
        self.retry_after_s = retry_after_s
        self.status_code = status_code


class ProviderTransientError(ProviderError):
    """Transient failure (500/502/503/504 / connection errors)."""


class ProviderPermanentError(ProviderError):
    """Permanent, non-retryable failure (400/404 semantics)."""


class ProviderAdapter(ABC):
    """Abstract contract every provider adapter must implement."""

    name: str

    def __init__(self, request_timeout_s: float = 30.0) -> None:
        self.request_timeout_s = request_timeout_s

    @abstractmethod
    async def invoke(self, request: LLMRequest) -> Any:
        """Execute *request* against the provider and return the raw response.

        The caller (``GuardedLLMClient``) does *not* retry here.  It relies on
        the bounded retry policy in ``RateLimitingExecutor``.
        """
        ...

    @abstractmethod
    def is_retryable(self, exc: Exception) -> bool:
        """Classify an exception as retryable or not.

        Returns False for permanent authentication/authorization/404-type errors
        and for preflight-checkable failures (e.g. context windows).  Returns
        True for 429/502/503/504, connection errors, and other transient faults.
        """
        ...

    @abstractmethod
    def extract_request_id(self, response: Any) -> str | None:
        """Pull a provider request identifier out of a raw response."""
        ...

    @abstractmethod
    def extract_usage(self, response: Any) -> dict[str, Any]:
        """Extract raw usage metadata from a response.

        Returns a dict that the existing ``UsageExtractor`` can normalize.
        """
        ...


class _LegacyProviderCallerAdapter(ProviderAdapter):
    """Fallback adapter that delegates to the existing ``provider_caller``.

    Kept for backward compatibility and for tests that already pass a
    MagicMock-style callable.  It intentionally performs **no** error
    classification beyond what the caller's exception already conveys.
    """

    def __init__(self, provider_caller: Callable[[LLMRequest], Awaitable[Any]]) -> None:
        super().__init__()
        self._caller = provider_caller

    async def invoke(self, request: LLMRequest) -> Any:
        return await self._caller(request)

    def is_retryable(self, exc: Exception) -> bool:
        return True

    def extract_request_id(self, response: Any) -> str | None:
        response_id = getattr(response, "id", None)
        if isinstance(response_id, str):
            return response_id
        if isinstance(response, dict):
            for key in ("id", "request_id"):
                request_id = response.get(key)
                if isinstance(request_id, str):
                    return request_id
        return None

    def extract_usage(self, response: Any) -> dict[str, Any]:
        return {}


class _EnvironmentCredentialProvider:
    """Read-only wrapper around the platform environment.

    Returns secrets if they are set and non-empty; otherwise returns None
    so callers can fail closed with a clear error.
    """

    @staticmethod
    def _env_value(name: str) -> str | None:
        value = os.getenv(name)
        if value:
            return value
        return None

    @staticmethod
    def get_api_key(name: str) -> str | None:
        return _EnvironmentCredentialProvider._env_value(name)


class OpenAIProviderAdapter(ProviderAdapter):
    """OpenAI-compatible provider adapter (OpenAI, Groq, Together, etc.).

    The request model identifier is passed to the provider unchanged, except
    for OpenAI-qualified model IDs that need their prefix removed. Credentials
    and base URL are injected at call time so they never enter action payloads
    or logs.

    The adapter deliberately **does not** retry on its own.  Any retryable
    provider error it raises is classified as retryable so that the existing
    ``RateLimitingExecutor`` retry loop handles it with bounded exponential
    backoff.  This satisfies the "no unbounded / non-retryable retries"
    requirement.
    """

    name = PROVIDER_OPENAI

    # tiktoken encodings used by the preflight estimator for the models this
    # adapter supports.  Kept in sync with the OpenAI region defaults.
    _OPENAI_ENCODINGS = {
        "gpt-4o": "o200k_base",
        "gpt-4o-mini": "o200k_base",
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
    }

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        request_timeout_s: float = 30.0,
    ) -> None:
        super().__init__(request_timeout_s=request_timeout_s)
        self._api_key = api_key
        self._base_url = base_url

        # Lazy import so missing SDK dependency fails fast only when a call is
        # actually attempted (and so imports do not defeat circular import
        # checks in the client package).
        try:
            import openai  # noqa: F401
        except ImportError as exc:  # pragma: no cover - env only
            raise ProviderError(
                "openai SDK is not installed. Install it via `pip install openai` "
                "or add it to your project dependencies."
            ) from exc

    @classmethod
    def from_settings(cls, request_timeout_s: float = 30.0) -> "OpenAIProviderAdapter":
        """Build an adapter from environment variables (never hard-coded keys)."""
        api_key = _EnvironmentCredentialProvider.get_api_key("OPENAI_API_KEY")
        base_url = _EnvironmentCredentialProvider._env_value("OPENAI_BASE_URL")
        if not api_key:
            # Fail closed: an adapter with no credentials must not silently
            # fall back to "no provider caller configured" at call time.
            raise ProviderAuthenticationError(
                "OPENAI_API_KEY environment variable is not set"
            )
        return cls(api_key=api_key, base_url=base_url, request_timeout_s=request_timeout_s)

    @property
    def api_key(self) -> str | None:
        # Exposed for diagnostics only; never echoed into logs or responses.
        return self._api_key

    async def invoke(self, request: LLMRequest) -> Any:
        import openai

        # Normalize the model identifier to OpenAI's expected values.  The
        # request may carry provider-specific names (e.g. "openai/gpt-4o") but
        # the SDK only understands a bare model identifier.
        model = request.model.strip()
        if request.provider.lower() == PROVIDER_OPENAI and model.startswith("openai/"):
            model = model.rsplit("/", 1)[-1].strip()

        messages = [
            {"role": str(m.get("role") or "user"), "content": str(m.get("content") or "")}
            for m in request.messages
        ]

        kwargs: dict[str, Any] = {
            "model": model,
            "messages": messages,
        }
        if request.max_tokens is not None:
            kwargs["max_tokens"] = request.max_tokens
        if request.temperature is not None:
            kwargs["temperature"] = request.temperature
        if request.extra_params:
            kwargs.update(request.extra_params)

        try:
            async with openai.AsyncOpenAI(
                api_key=self._api_key,
                base_url=self._base_url,
                timeout=min(request.timeout_s, self.request_timeout_s),
                max_retries=0,
            ) as client:
                return await client.chat.completions.create(**kwargs)
        except (openai.AuthenticationError, openai.PermissionDeniedError) as exc:
            raise ProviderAuthenticationError(_redact_secrets(str(exc))) from exc
        except openai.RateLimitError as exc:
            headers = getattr(getattr(exc, "response", None), "headers", {})
            retry_after = headers.get("retry-after") if headers else None
            try:
                retry_after_s = float(retry_after) if retry_after is not None else None
            except (TypeError, ValueError):
                retry_after_s = None
            raise ProviderRateLimitError(
                _redact_secrets(str(exc)),
                retry_after_s=retry_after_s,
                status_code=429,
            ) from exc
        except (openai.APITimeoutError, openai.APIConnectionError) as exc:
            raise ProviderTransientError(_redact_secrets(str(exc))) from exc
        except openai.APIStatusError as exc:
            detail = _redact_secrets(str(exc))
            if exc.status_code >= 500:
                raise ProviderTransientError(detail) from exc
            raise ProviderPermanentError(detail) from exc
        except Exception as exc:
            raise ProviderPermanentError(_redact_secrets(str(exc))) from exc

    def is_retryable(self, exc: Exception) -> bool:
        return isinstance(exc, (ProviderRateLimitError, ProviderTransientError))

    def extract_request_id(self, response: Any) -> str | None:
        response_id = getattr(response, "id", None)
        if isinstance(response_id, str):
            return response_id
        if isinstance(response, dict):
            for key in ("id", "request_id"):
                request_id = response.get(key)
                if isinstance(request_id, str):
                    return request_id
        return None

    def extract_usage(self, response: Any) -> dict[str, Any]:
        # OpenAI's ChatCompletion response exposes `.usage` and `.id`.
        if hasattr(response, "usage") and response.usage is not None:
            usage = response.usage
            if isinstance(usage, dict):
                return usage
            # pydantic/dataclass-style usage objects
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
        if isinstance(response, dict):
            for key in ("usage", "usage_metadata"):
                usage = response.get(key)
                if isinstance(usage, dict):
                    return {str(name): value for name, value in usage.items()}
        return {}


PROVIDER_ADAPTERS: dict[str, type[ProviderAdapter]] = {
    PROVIDER_OPENAI: OpenAIProviderAdapter,
}
