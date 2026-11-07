"""Pluggable text-classifier adapters.

Detectors depend only on the ``TextClassifier`` interface, so the underlying
model (Hugging Face, scikit-learn, remote service) can be swapped through
configuration without touching the firewall architecture.

Models are loaded exactly once (``ModelRegistry.load_all`` at startup) and
inference runs in worker threads behind a semaphore (bounded concurrency) and
a timeout.
"""

from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Labels treated as the "positive" (risky) class when a model does not declare one explicitly.
_POSITIVE_LABEL_HINTS = {"injection", "jailbreak", "malicious", "unsafe", "toxic", "attack", "label_1", "1", "harmful"}


@dataclass
class ClassifierOutput:
    positive_prob: float
    label: str
    probs: dict[str, float]
    chunks: int = 1
    truncated: bool = False
    latency_ms: float = 0.0


@dataclass
class ClassifierStatus:
    name: str
    model_id: str
    backend: str
    available: bool
    error: str | None = None
    load_seconds: float | None = None
    labels: list[str] = field(default_factory=list)
    positive_labels: list[str] = field(default_factory=list)


class ClassifierUnavailable(RuntimeError):
    pass


class TextClassifier(ABC):
    """Interface every classifier adapter implements."""

    name: str
    model_id: str
    backend: str

    @property
    @abstractmethod
    def available(self) -> bool: ...

    @abstractmethod
    def load(self) -> None: ...

    @abstractmethod
    async def predict(self, text: str) -> ClassifierOutput: ...

    @abstractmethod
    def status(self) -> ClassifierStatus: ...


class HFSequenceClassifier(TextClassifier):
    """Hugging Face ``AutoModelForSequenceClassification`` adapter.

    Long inputs are split into overlapping token windows; the positive
    probability of the input is the maximum over windows (an injection hidden
    at the end of a long document must not be diluted).
    """

    backend = "transformers"

    def __init__(
        self,
        name: str,
        model_id: str,
        *,
        multi_label: bool = False,
        positive_labels: list[str] | None = None,
        device: str = "cpu",
        max_tokens: int = 512,
        max_chunks: int = 16,
        semaphore: asyncio.Semaphore | None = None,
        timeout: float = 20.0,
    ) -> None:
        self.name = name
        self.model_id = model_id
        self.multi_label = multi_label
        self._positive_override = [p.lower() for p in positive_labels] if positive_labels else None
        self.device = device
        self.max_tokens = max_tokens
        self.max_chunks = max_chunks
        self.semaphore = semaphore or asyncio.Semaphore(2)
        self.timeout = timeout
        self._model: Any = None
        self._tokenizer: Any = None
        self._labels: list[str] = []
        self._positive_idx: list[int] = []
        self._error: str | None = None
        self._load_seconds: float | None = None

    @property
    def available(self) -> bool:
        return self._model is not None

    def load(self) -> None:
        start = time.perf_counter()
        try:
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer

            self._tokenizer = AutoTokenizer.from_pretrained(self.model_id)
            model = AutoModelForSequenceClassification.from_pretrained(self.model_id)
            model.eval()
            if self.device != "cpu" and torch.cuda.is_available():
                model.to(self.device)
            else:
                self.device = "cpu"
            self._model = model
            id2label = model.config.id2label
            self._labels = [str(id2label[i]) for i in range(len(id2label))]
            lower = [l.lower() for l in self._labels]
            if self._positive_override:
                self._positive_idx = [i for i, l in enumerate(lower) if l in self._positive_override]
            elif self.multi_label:
                self._positive_idx = list(range(len(lower)))
            else:
                self._positive_idx = [i for i, l in enumerate(lower) if l in _POSITIVE_LABEL_HINTS]
            if not self._positive_idx:
                raise ClassifierUnavailable(f"Could not determine positive label(s) from {self._labels}")
            self._load_seconds = round(time.perf_counter() - start, 2)
            logger.info("Loaded classifier %s (%s) in %.1fs labels=%s", self.name, self.model_id, self._load_seconds, self._labels)
        except Exception as exc:  # model missing, no network, incompatible weights...
            self._model = None
            self._error = f"{type(exc).__name__}: {str(exc)[:200]}"
            logger.warning("Classifier %s (%s) unavailable: %s", self.name, self.model_id, self._error)

    def _predict_sync(self, text: str) -> ClassifierOutput:
        import torch

        start = time.perf_counter()
        enc = self._tokenizer(
            text,
            truncation=True,
            max_length=self.max_tokens,
            stride=64,
            return_overflowing_tokens=True,
            padding=True,
            return_tensors="pt",
        )
        enc.pop("overflow_to_sample_mapping", None)
        n_chunks = int(enc["input_ids"].shape[0])
        truncated = n_chunks > self.max_chunks
        if truncated:
            # Keep the first and last windows; injections are often appended at the end.
            half = self.max_chunks // 2
            idx = list(range(half)) + list(range(n_chunks - half, n_chunks))
            enc = {k: v[idx] for k, v in enc.items()}
        enc = {k: v.to(self.device) for k, v in enc.items() if k in ("input_ids", "attention_mask", "token_type_ids")}
        with torch.inference_mode():
            logits = self._model(**enc).logits
            probs = torch.sigmoid(logits) if self.multi_label else torch.softmax(logits, dim=-1)
        probs = probs.float().cpu()
        # Max over chunks per label.
        per_label = probs.max(dim=0).values.tolist()
        prob_map = {self._labels[i]: round(float(p), 6) for i, p in enumerate(per_label)}
        positive = max(per_label[i] for i in self._positive_idx)
        if self.multi_label:
            top = max(self._positive_idx, key=lambda i: per_label[i])
            label = self._labels[top] if positive >= 0.5 else "none"
        else:
            label = self._labels[int(max(range(len(per_label)), key=lambda i: per_label[i]))]
        return ClassifierOutput(
            positive_prob=float(positive),
            label=label,
            probs=prob_map,
            chunks=min(n_chunks, self.max_chunks),
            truncated=truncated,
            latency_ms=round((time.perf_counter() - start) * 1000, 2),
        )

    async def predict(self, text: str) -> ClassifierOutput:
        if not self.available:
            raise ClassifierUnavailable(self._error or "model not loaded")
        async with self.semaphore:
            return await asyncio.wait_for(asyncio.to_thread(self._predict_sync, text), timeout=self.timeout)

    def status(self) -> ClassifierStatus:
        return ClassifierStatus(
            name=self.name,
            model_id=self.model_id,
            backend=self.backend,
            available=self.available,
            error=self._error,
            load_seconds=self._load_seconds,
            labels=self._labels,
            positive_labels=[self._labels[i] for i in self._positive_idx] if self._labels else [],
        )


class SklearnTextClassifier(TextClassifier):
    """Adapter for a scikit-learn text pipeline trained by ``experiments/train_baseline.py``.

    Only loads artifacts produced by this project from a local path (joblib
    deserialization executes code, so never point this at untrusted files).
    """

    backend = "sklearn"

    def __init__(self, name: str, path: str | Path):
        self.name = name
        self.model_id = str(path)
        self._path = Path(path)
        self._pipe: Any = None
        self._error: str | None = None

    @property
    def available(self) -> bool:
        return self._pipe is not None

    def load(self) -> None:
        try:
            import joblib

            self._pipe = joblib.load(self._path)
        except Exception as exc:
            self._error = f"{type(exc).__name__}: {str(exc)[:200]}"

    async def predict(self, text: str) -> ClassifierOutput:
        if not self.available:
            raise ClassifierUnavailable(self._error or "model not loaded")
        start = time.perf_counter()
        prob = float(self._pipe.predict_proba([text])[0][1])
        return ClassifierOutput(
            positive_prob=prob,
            label="positive" if prob >= 0.5 else "negative",
            probs={"negative": 1 - prob, "positive": prob},
            latency_ms=round((time.perf_counter() - start) * 1000, 2),
        )

    def status(self) -> ClassifierStatus:
        return ClassifierStatus(self.name, self.model_id, self.backend, self.available, self._error)


class ModelRegistry:
    """Holds every classifier instance; guarantees each model is loaded once."""

    def __init__(self) -> None:
        self._classifiers: dict[str, TextClassifier] = {}
        self._aliases: dict[str, str] = {}

    def register(self, clf: TextClassifier) -> None:
        if clf.name in self._classifiers:
            raise ValueError(f"classifier {clf.name} already registered")
        self._classifiers[clf.name] = clf

    def alias(self, name: str, target: str) -> None:
        """Expose an already-registered classifier under another role name (no second load)."""
        self._aliases[name] = target

    def resolve(self, name: str) -> str:
        return self._aliases.get(name, name)

    def get(self, name: str) -> TextClassifier | None:
        clf = self._classifiers.get(self.resolve(name))
        return clf if clf is not None and clf.available else None

    def load_all(self) -> None:
        for clf in self._classifiers.values():
            clf.load()

    def statuses(self) -> list[ClassifierStatus]:
        return [c.status() for c in self._classifiers.values()]


def build_registry(settings: Any) -> ModelRegistry:
    """Create (but do not load) the default classifiers from settings."""
    registry = ModelRegistry()
    if not settings.ml_enabled:
        return registry
    sem = asyncio.Semaphore(settings.max_concurrent_inferences)
    common = dict(device=settings.ml_device, max_tokens=settings.ml_max_tokens, semaphore=sem, timeout=settings.detector_timeout_seconds)
    if settings.injection_model:
        registry.register(HFSequenceClassifier("prompt_injection", settings.injection_model, **common))
    if settings.jailbreak_model and settings.jailbreak_model == settings.injection_model:
        registry.alias("jailbreak", "prompt_injection")  # same weights: load once, share
    elif settings.jailbreak_model:
        registry.register(HFSequenceClassifier("jailbreak", settings.jailbreak_model, **common))
    if settings.toxicity_model:
        registry.register(HFSequenceClassifier("toxicity", settings.toxicity_model, multi_label=True, **common))
    return registry
