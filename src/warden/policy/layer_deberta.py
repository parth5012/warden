"""L1 DeBERTa-v3 prompt-injection scorer.

Real model: protectai/deberta-v3-base-prompt-injection-v2 (184M, 512 tokens,
Apache-2.0). Optional deps — transformers/onnxruntime are imported lazily so
the gate works without them (caller treats missing scorer as uncertain).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol
import importlib


@dataclass(frozen=True)
class InjectionScore:
    score: float  # P(injection) in [0, 1]
    model: str


class InjectionScorer(Protocol):
    def score(self, text: str) -> InjectionScore:
        ...


class FakeInjectionScorer:
    """Deterministic stub for tests/demos. Maps keywords to scores."""

    def __init__(self, default: float = 0.05) -> None:
        self._default = default

    def score(self, text: str) -> InjectionScore:
        lowered = text.lower()
        if "ignore previous instructions" in lowered or "ignore all instructions" in lowered:
            return InjectionScore(score=0.97, model="fake-deberta")
        if "prompt injection" in lowered:
            return InjectionScore(score=0.90, model="fake-deberta")
        return InjectionScore(score=self._default, model="fake-deberta")


class OnnxInjectionScorer:
    """ONNXRuntime INT8 scorer (HikmaAI/hikmaai-deberta-injection, 233MB).

    Lazily imports optimum/onnxruntime/transformers on first use.
    Raises RuntimeError if the optional deps are missing.
    """

    def __init__(
        self,
        model_id: str = "protectai/deberta-v3-base-prompt-injection-v2",
        max_length: int = 512,
    ) -> None:
        self._model_id = model_id
        self._max_length = max_length
        self._pipe: Any = None

    def score(self, text: str) -> InjectionScore:
        pipe = self._load()
        # transformers pipeline call typed as Any to keep strict mypy happy
        # without hard dependency.
        result: Any = pipe(text[:4000], truncation=True, max_length=self._max_length)
        candidates: list[Any] = result if isinstance(result, list) else [result]
        dicts = [r for r in candidates if isinstance(r, dict)]
        if not dicts:
            return InjectionScore(score=0.0, model=self._model_id)
        top = dicts[0]
        label = str(top.get("label", ""))
        score_raw = top.get("score", 0.0)
        raw = float(score_raw) if isinstance(score_raw, (int, float, str)) else 0.0
        # v2 labels: LABEL_1 / INJECTION = injection; LABEL_0 / benign = clean.
        if label in ("LABEL_1", "INJECTION", "1"):
            prob = raw
        elif label in ("LABEL_0", "BENIGN", "0"):
            prob = 1.0 - raw
        else:
            prob = raw
        return InjectionScore(score=min(1.0, max(0.0, prob)), model=self._model_id)

    def _load(self) -> Any:
        if self._pipe is not None:
            return self._pipe
        try:
            transformers = importlib.import_module("transformers")
            torch = importlib.import_module("torch")
        except ImportError as exc:
            raise RuntimeError(
                "DeBERTa scorer needs transformers+torch (or use FakeInjectionScorer)"
            ) from exc
        device = 0
        try:
            if not torch.cuda.is_available():
                device = -1
        except Exception:
            device = -1
        tokenizer = transformers.AutoTokenizer.from_pretrained(self._model_id)
        model_pipe = transformers.pipeline(
            "text-classification",
            model=self._model_id,
            tokenizer=tokenizer,
            truncation=True,
            max_length=self._max_length,
            device=device,
        )
        self._pipe = model_pipe
        return model_pipe
