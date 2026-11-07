"""Shared evaluation harness.

All configurations are evaluated on identical samples with the *production*
pipeline components (normalizer, detectors, risk scorer, policy engine,
context detector, verifier). Only the policy/mode knobs differ between
configurations. Classifier outputs are memoized per text inside the harness so
each model runs once per unique input across configurations (this cache exists
only in the evaluation process).
"""

from __future__ import annotations

import asyncio
import json
import os
import platform
import statistics
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
os.chdir(ROOT / "backend")

from sentinel.config import Settings, configure_hf_home  # noqa: E402

configure_hf_home()

from sentinel.detection.classifiers import HFSequenceClassifier  # noqa: E402
from sentinel.detection.context_detector import ContextChunk  # noqa: E402
from sentinel.detection.normalizer import normalize  # noqa: E402
from sentinel.engine.enforcement import enforce  # noqa: E402
from sentinel.engine.policy_engine import ProviderContext  # noqa: E402
from sentinel.engine.policy_schema import SentinelPolicy  # noqa: E402
from sentinel.engine.risk_scorer import score_risk  # noqa: E402
from sentinel.main import AppContext, build_context  # noqa: E402
from sentinel.schemas.common import Decision, most_restrictive  # noqa: E402

DATA = ROOT / "datasets" / "processed"
RESULTS = ROOT / "experiments" / "results"
ACTION_RANK = {"allow": 0, "redact": 1, "block": 2}


def load_split(split: str = "test") -> list[dict[str, Any]]:
    path = DATA / f"{split}.jsonl"
    if not path.exists():
        raise SystemExit(f"{path} missing - run experiments/build_dataset.py first")
    # split on "\n" only: str.splitlines() would also break on U+2028/U+2029 inside JSON strings.
    return [json.loads(line) for line in path.read_text(encoding="utf-8").split("\n") if line.strip()]


def dataset_info(rows: list[dict[str, Any]], split: str) -> dict[str, Any]:
    manifest = json.loads((DATA / "manifest.json").read_text(encoding="utf-8"))
    return {"name": manifest["name"], "split": split, "sha256": manifest["sha256"], "n_samples": len(rows),
            "n_attack": sum(r["label"] for r in rows), "n_benign": sum(1 for r in rows if r["label"] == 0)}


def enable_prediction_cache() -> None:
    """Memoize classifier outputs by (model, text) for the evaluation process only."""
    original = HFSequenceClassifier.predict
    cache: dict[tuple[str, str], Any] = {}

    async def cached(self: HFSequenceClassifier, text: str):  # type: ignore[no-untyped-def]
        key = (self.model_id, text)
        if key not in cache:
            cache[key] = await original(self, text)
        return cache[key]

    HFSequenceClassifier.predict = cached  # type: ignore[method-assign]


async def make_context(*, ml: bool = True, cache: bool = False) -> AppContext:
    """Build the production pipeline. ``cache=True`` memoizes classifier outputs (faster, but then
    latency numbers are not representative - only use it where latency is not reported)."""
    settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:", redis_optional=True, redis_url="redis://127.0.0.1:1/0",
        ml_enabled=ml, cloud_enabled=False, detector_timeout_seconds=120,
    )
    ctx = await build_context(settings, load_models=ml)
    if cache:
        enable_prediction_cache()
    return ctx


@dataclass
class Config:
    name: str
    mode: str | None  # None = no firewall
    verification: bool = False
    profile: str | None = None
    policy_patch: Callable[[SentinelPolicy], None] | None = None
    always_verify: bool = False


@dataclass
class Outcome:
    action: str  # allow | redact | block
    decision: str
    latency_ms: float
    verified: bool = False
    verifier_tokens: int = 0
    verifier_ms: float = 0.0
    sanitized: str | None = None
    scores: dict[str, float] = field(default_factory=dict)


def to_action(decision: Decision) -> str:
    if decision in (Decision.BLOCK, Decision.HUMAN_REVIEW, Decision.VERIFY):
        return "block"
    return "redact" if decision == Decision.REDACT else "allow"


class Evaluator:
    def __init__(self, ctx: AppContext) -> None:
        self.ctx = ctx
        self.base_policy = ctx.policy_store.current
        self._verify_cache: dict[str, Any] = {}

    def policy_for(self, cfg: Config) -> SentinelPolicy:
        p = self.base_policy.model_copy(deep=True)
        p.verification.enabled = cfg.verification or cfg.always_verify
        if cfg.mode:
            p.prompt_injection.mode = cfg.mode  # type: ignore[assignment]
            p.jailbreak.mode = cfg.mode  # type: ignore[assignment]
            p.context.mode = cfg.mode  # type: ignore[assignment]
        if cfg.policy_patch:
            cfg.policy_patch(p)
        return p

    async def _verify(self, text: str, sources: list[str], policy: SentinelPolicy):
        if text not in self._verify_cache:
            self._verify_cache[text] = await self.ctx.pipeline.verifier.verify(text, sources, policy.verification)
        return self._verify_cache[text]

    async def run_input(self, sample: dict[str, Any], cfg: Config, provider: ProviderContext | None) -> Outcome:
        start = time.perf_counter()
        if cfg.mode is None:
            return Outcome(action="allow", decision="ALLOW", latency_ms=0.0, sanitized=sample["text"])
        policy = self.policy_for(cfg)
        pipe = self.ctx.pipeline
        norm = normalize(sample["text"], max_chars=200_000)
        results = await pipe.run_input_detectors(norm, policy, profile=cfg.profile, mode_override=cfg.mode)
        risk = score_risk(results, policy, cfg.profile)
        decision = pipe.engine.evaluate(results, risk, policy, provider=provider, profile=cfg.profile)
        final = decision.decision
        verified, vtokens, vms = False, 0, 0.0
        if cfg.always_verify or final == Decision.VERIFY:
            base = decision.decision_without_verify()
            if base == Decision.ALLOW and decision.redact_categories:
                base = Decision.REDACT
            vr = await self._verify(norm.text, decision.verify_sources or ["always"], policy)
            verified, vtokens, vms = True, (vr.prompt_tokens or 0) + (vr.completion_tokens or 0), vr.latency_ms
            if vr.status != "ok":
                final = most_restrictive(base, policy.verification.on_unavailable)
            else:
                final = Decision.BLOCK if vr.escalate else base
        enf = enforce(norm.text, results, decision, final_decision=final)
        latency = (time.perf_counter() - start) * 1000
        return Outcome(action=to_action(enf.decision), decision=enf.decision.value, latency_ms=latency, verified=verified,
                       verifier_tokens=vtokens, verifier_ms=vms, sanitized=enf.sanitized_text,
                       scores={k: r.score for k, r in results.items()})

    async def run_context(self, sample: dict[str, Any], cfg: Config) -> Outcome:
        start = time.perf_counter()
        if cfg.mode is None:
            return Outcome(action="allow", decision="ALLOW", latency_ms=0.0)
        policy = self.policy_for(cfg)
        from sentinel.engine.policy_engine import effective_threshold

        ci = await self.ctx.pipeline.context.inspect([ContextChunk(id=sample["id"], text=sample["text"])], policy.context,
                                                     threshold=effective_threshold(policy, "context", cfg.profile))
        c = ci.chunks[0]
        latency = (time.perf_counter() - start) * 1000
        action = "block" if not c.included else ("redact" if (c.removed_lines or c.redactions) else "allow")
        return Outcome(action=action, decision=c.action, latency_ms=latency, scores={"context": c.risk})

    async def run(self, sample: dict[str, Any], cfg: Config, provider: ProviderContext | None = None) -> Outcome:
        if sample["stage"] == "context":
            return await self.run_context(sample, cfg)
        return await self.run_input(sample, cfg, provider)


def pct(values: list[float], q: float) -> float | None:
    if not values:
        return None
    s = sorted(values)
    k = (len(s) - 1) * q
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return round(s[lo] + (s[hi] - s[lo]) * (k - lo), 2)


def binary_metrics(labels: list[int], preds: list[int]) -> dict[str, Any]:
    tp = sum(1 for y, p in zip(labels, preds) if y == 1 and p == 1)
    fp = sum(1 for y, p in zip(labels, preds) if y == 0 and p == 1)
    fn = sum(1 for y, p in zip(labels, preds) if y == 1 and p == 0)
    tn = sum(1 for y, p in zip(labels, preds) if y == 0 and p == 0)
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * precision * recall / (precision + recall) if precision and recall else 0.0 if precision is not None and recall is not None else None
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 4) if precision is not None else None,
        "recall": round(recall, 4) if recall is not None else None,
        "f1": round(f1, 4) if f1 is not None else None,
        "fpr": round(fp / (fp + tn), 4) if fp + tn else None,
        "fnr": round(fn / (fn + tp), 4) if fn + tp else None,
        "accuracy": round((tp + tn) / len(labels), 4) if labels else None,
    }


def latency_stats(values: list[float]) -> dict[str, Any]:
    return {"mean_ms": round(statistics.fmean(values), 2) if values else None, "p50_ms": pct(values, 0.5),
            "p95_ms": pct(values, 0.95), "p99_ms": pct(values, 0.99)}


def environment() -> dict[str, Any]:
    import torch
    import transformers

    return {"python": platform.python_version(), "platform": platform.platform(), "processor": platform.processor(),
            "torch": torch.__version__, "transformers": transformers.__version__, "device": "cpu"}


def write_result(kind: str, payload: dict[str, Any]) -> Path:
    RESULTS.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = RESULTS / f"{kind}_{stamp}.json"
    body = {"kind": kind, "created_at": datetime.now(timezone.utc).isoformat(), "environment": environment(), **payload}
    path.write_text(json.dumps(body, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def progress(i: int, n: int, label: str) -> None:
    if i % 50 == 0 or i == n:
        print(f"  [{label}] {i}/{n}", flush=True)


def run(coro) -> Any:
    return asyncio.run(coro)
