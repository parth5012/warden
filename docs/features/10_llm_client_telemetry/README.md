# Feature 10 — Guarded LLM Client and Telemetry

**Status:** ✅ IMPLEMENTED  
**Workstream:** F (Infra)  
**Package:** `src/warden/llm/`  
**Test Suite:** `tests/test_llm_client.py`  

---

## 1. Overview & Purpose

The **Guarded LLM Client** acts as Warden's single protected execution seam for Large Language Model invocations (`action.kind == ActionKind.LLM`). Rather than permitting raw, unmonitored HTTP requests to LLM providers, Warden gates every request through preflight validation, token estimation, budget reservations, rate limits, concurrency semaphores, bounded retries, response usage extraction, precision-safe cost calculations, and audit telemetry.

Warden remains the sole governance authority. Token accounting and cost tracking operate strictly within Warden's security boundary.

---

## 2. Token Usage Model & Mutually-Exclusive Buckets

To prevent double counting across providers that report overlapping token categories (such as OpenAI including cached tokens within `prompt_tokens` and reasoning tokens within `completion_tokens`), Warden enforces mutually-exclusive accounting buckets:

$$\text{total\_tokens} = \text{input\_uncached} + \text{input\_cached} + \text{output\_standard} + \text{output\_reasoning}$$

### Bucket Definitions

| Bucket | Formula / Source | Notes |
|---|---|---|
| `input_cached_tokens` | Provider reported (e.g., `prompt_tokens_details.cached_tokens`, Anthropic `cache_read_input_tokens`, Gemini `cached_content_token_count`) | Tokens retrieved from provider KV cache at discounted pricing. |
| `input_uncached_tokens` | $\max(0, \text{prompt\_tokens} - \text{input\_cached\_tokens})$ | Freshly ingested prompt tokens billed at standard input rates. |
| `output_reasoning_tokens` | Provider reported (e.g., `completion_tokens_details.reasoning_tokens`) | Internal CoT / reasoning tokens billed at reasoning rates. |
| `output_standard_tokens` | $\max(0, \text{completion\_tokens} - \text{output\_reasoning\_tokens})$ | Final completion tokens returned to caller. |
| `total_tokens` | $\sum \text{buckets}$ | Exactly matches the physical billed token sum. |

### Usage Source Attribution

Every usage record carries an explicit `source` attribute:
- `provider_reported`: Extracted from provider response metadata.
- `estimated`: Calculated locally via preflight `tiktoken` analysis.
- `unavailable`: Provider response contained no usage metadata; values set to 0 without fabricating counts.

---

## 3. Supported Provider Integrations

1. **OpenAI (`openai`)**: Native extraction of `prompt_tokens`, `completion_tokens`, `total_tokens`, `prompt_tokens_details.cached_tokens`, and `completion_tokens_details.reasoning_tokens`. Request ID from `response.id`.
2. **Anthropic (`anthropic`)**: Native extraction of `input_tokens`, `output_tokens`, `cache_read_input_tokens`, and `cache_creation_input_tokens`.
3. **Google Gemini (`google`)**: Native extraction of `usage_metadata` (`prompt_token_count`, `candidates_token_count`, `cached_content_token_count`, `total_token_count`).
4. **Generic / LangChain**: Normalizes dicts, `AIMessage` objects, and Pydantic models containing `usage_metadata` or `response_metadata`.

---

## 4. Local Token Estimation & Preflight Context Checks

Local estimation is implemented in [`src/warden/llm/tokenizer.py`](../../../src/warden/llm/tokenizer.py) using `tiktoken`:

- **Encoding Resolution:**
  - `gpt-4o`, `gpt-4o-mini`, `o1`, `o3-mini`: mapped to `o200k_base`.
  - `gpt-4`, `gpt-4-turbo`, `gpt-3.5-turbo`: mapped to `cl100k_base`.
  - Configurable model-to-encoding overrides supported.
- **Message Framing Overhead:**
  - Accurately models OpenAI chat formatting:
    - 3 tokens per message for framing (`<|im_start|>{role}\n{content}<|im_end|>`).
    - 1 additional token if a `name` parameter is present.
    - 3 tokens priming the assistant reply (`<|im_start|>assistant<|im_sep|>`).
- **Context Window Verification:**
  - Compares $\text{estimated\_prompt\_tokens} + \text{requested\_output\_tokens}$ against the model's configured context window (e.g. 128,000 for `gpt-4o`, 200,000 for `o1` and `claude-3-5-sonnet`).
  - Raises `ContextWindowExceededError` **before** dispatching any external HTTP request.
- **Explicit Unsupported Model Handling:**
  - If a model's tokenizer is not supported by `tiktoken`, the estimator explicitly returns `TokenEstimationResult(is_supported=False, estimated_tokens=None)`.
  - Warden never guesses an arbitrary tokenizer or claims an estimate is accurate for an unknown model.

---

## 5. Model Pricing Registry & Precision Cost Calculations

Implemented in [`src/warden/llm/pricing.py`](../../../src/warden/llm/pricing.py):

- **Precision-Safe Arithmetic:** Uses Python `Decimal` with micro-dollar quantization ($0.000001) to eliminate IEEE-754 floating point inaccuracies.
- **Deterministic Resolution:**
  1. Exact match on `(provider, model)`.
  2. Configured regex pattern match (e.g. `^gpt-4o(-\d{4}-\d{2}-\d{2})?$`).
  3. If unmapped, returns `None` — cost is recorded as unknown (`None`), **never** fabricated.
- **Cost Formula:**
  $$\text{cost} = \frac{\text{uncached\_in} \times P_{\text{in}} + \text{cached\_in} \times P_{\text{cache}} + \text{standard\_out} \times P_{\text{out}} + \text{reasoning\_out} \times P_{\text{reasoning}}}{1{,}000{,}000}$$
- **Standard Preconfigured Pricing Tiers:**
  - `gpt-4o`: Input: $2.50/1M, Output: $10.00/1M, Cache: $1.25/1M
  - `gpt-4o-mini`: Input: $0.15/1M, Output: $0.60/1M, Cache: $0.075/1M
  - `o1`: Input: $15.00/1M, Output: $60.00/1M, Cache: $7.50/1M, Reasoning: $60.00/1M
  - `o3-mini`: Input: $1.10/1M, Output: $4.40/1M, Cache: $0.55/1M, Reasoning: $4.40/1M
  - `claude-3-5-sonnet`: Input: $3.00/1M, Output: $15.00/1M, Cache: $0.30/1M
  - `claude-3-5-haiku`: Input: $0.80/1M, Output: $4.00/1M, Cache: $0.08/1M
  - `gemini-1.5-pro`: Input: $1.25/1M, Output: $5.00/1M, Cache: $0.3125/1M
  - `gemini-1.5-flash`: Input: $0.075/1M, Output: $0.30/1M, Cache: $0.01875/1M

---

## 6. Budget Enforcement & Atomic Reservation

Implemented in [`src/warden/llm/budget.py`](../../../src/warden/llm/budget.py):

- **Request-Level Gates:**
  - `max_input_tokens_per_request`
  - `max_output_tokens_per_request`
  - `max_total_tokens_per_request`
  - `max_spend_per_request`
- **Run-Level Spend Gate with Race-Safe Reservation:**
  - Maintains `RunBudgetTracker` with an `asyncio.Lock` per `run_id`.
  - **Preflight:** Atomically calculates estimated spend and reserves it against `max_spend_per_run`. If $\text{settled} + \text{reserved} + \text{estimate} > \text{max}$, raises `BudgetExceededError` before network dispatch.
  - **Postflight:** Settles actual billed spend, credits or debits the variance, and releases the reservation.
  - **Failure:** On network or provider errors, cleanly releases the reservation so remaining budget is not trapped.

---

## 7. Rate Limiting, Concurrency & Bounded Retries

Implemented in [`src/warden/llm/rate_limiter.py`](../../../src/warden/llm/rate_limiter.py):

- **Sliding-Window Throttling:** Tracks request timestamps and token consumption over a 60-second window (`max_requests_per_minute`, `max_tokens_per_minute`).
- **Concurrency Bounding:** Uses `asyncio.Semaphore(max_concurrent_requests)` to limit concurrent in-flight connections.
- **Bounded Retries:**
  - Up to `max_retries` (default: 3) attempts.
  - Exponential backoff with full jitter ($0.5 \times \text{backoff}$ to $\text{backoff}$).
  - Parses and honors provider `Retry-After` headers.
  - Strict error classification:
    - *Retryable:* HTTP 429, 500, 502, 503, 504, `asyncio.TimeoutError`, `ConnectionError`.
    - *Non-Retryable:* HTTP 400, 401, 403, 404, `ContextWindowExceededError`, `BudgetExceededError`, `TokenLimitExceededError`.

---

## 8. Security & Audit Telemetry

Implemented in [`src/warden/llm/client.py`](../../../src/warden/llm/client.py):

- **Secret Redaction:** `redact_secrets()` sanitizes API keys (`sk-...`, Bearer tokens, credentials) from error details and diagnostic logs.
- **Zero Raw Body Retention:** Telemetry events (`llm_usage`) record model parameters, token bucket counts, latency, and costs, but never persist raw user prompts or full completions.
- **Non-Interfering Emission:** Failures in downstream telemetry sinks are safely trapped and will never convert a successful execution into an error, nor authorize a failed execution.

---

## 9. Langfuse Source Attribution & Implementation Analysis

Warden inspected and referenced the official Langfuse repository ([langfuse/langfuse](https://github.com/langfuse/langfuse)) as an architectural and algorithmic reference under the **MIT License**.

### Inspected Langfuse Paths
1. `worker/src/constants/default-model-prices.json` (pricing tiers, unit costs, regex aliases)
2. `packages/shared/src/server/pricing-tiers/matcher.ts` (deterministic tier resolution and priority matching)
3. `packages/shared/src/server/otel/OtelIngestionProcessor.ts` (token usage extraction and cache normalization)
4. `packages/shared/src/server/llm/types.ts` (tokenizer identifiers and model tier schemas)
5. `langfuse-python/langfuse/openai.py` and `CallbackHandler.py` (OpenAI usage extraction patterns)

### Classification of Code

| Component | Status | Details |
|---|---|---|
| **Bucket Accounting Math** | Adapted | Adapted Langfuse's cache and reasoning token separation pattern to guarantee zero double counting across OpenAI, Anthropic, and Gemini. |
| **Model Pricing Registry** | Adapted | Adapted Langfuse's default model prices catalog and tier matcher algorithm to native Python `Decimal` micro-dollar arithmetic. |
| **Provider Usage Extraction** | Adapted | Adapted OpenAI, Anthropic, and Gemini usage parsing to handle dictionaries, SDK objects, and LangChain metadata. |
| **Local Token Estimation** | Adapted | Adapted Langfuse's `tiktoken` selection logic; added message framing and context-window gate. |
| **Atomic Budget Reservation** | Independently Implemented | Built specifically for Warden's `run_id` lifecycle and concurrency requirements. |
| **Sliding Window & Retries** | Independently Implemented | Built in native asyncio to avoid external Redis dependencies. |
| **AuditJournal Telemetry** | Independently Implemented | Tailored to Warden's write-ahead audit event contracts. |

### Intentionally Not Reused
- Langfuse's Next.js web application, frontend UI, Prisma ORM models, ClickHouse storage, and OpenTelemetry collector pipeline were intentionally **not** imported to keep Warden lightweight, self-contained, and security-centric.

### License & Attribution Notice
Portions of the pricing catalog and usage extraction patterns are adapted from Langfuse:
```
Copyright (c) 2023-present Langfuse GmbH
Licensed under the MIT License.
```

---

## 10. Verification Commands

```bash
# Run all Guarded LLM Client unit and integration tests
uv run pytest tests/test_llm_client.py -v

# Run entire repository test suite (checkpoint, cli, llm)
uv run pytest -v

# Run strict static type checking
uv run mypy src tests
```
