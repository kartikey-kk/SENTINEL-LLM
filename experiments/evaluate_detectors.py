"""Per-detector evaluation on the held-out test split.

For each detector and mode (rules / ml / hybrid) the detector's own `detected` flag (score >= the
policy threshold) is compared with ground truth on the relevant positive/negative subsets:

  prompt_injection : prompt_injection samples  vs benign input samples
  jailbreak        : jailbreak samples         vs benign input samples
  any_attack       : injection or jailbreak    vs benign (either detector fires)
  context          : indirect_injection chunks vs benign_context chunks
  secret_detection : synthetic secrets         vs benign (incl. documentation placeholders)
  toxicity         : toxic samples             vs benign (incl. strongly negative but non-toxic text)
  pii              : value-level recall of ground-truth PII values; false entities on benign text
                     (Presidio vs the deterministic regex fallback)
  sklearn_tfidf_lr : trained baseline (if experiments/train_baseline.py was run)

Latency is not reported here (classifier outputs are memoized across modes); see benchmark_latency.py.

Usage: backend/.venv/Scripts/python experiments/evaluate_detectors.py
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from common import ROOT, binary_metrics, dataset_info, load_split, make_context, progress, write_result
from sentinel.detection.base import DetectionContext
from sentinel.detection.context_detector import ContextChunk
from sentinel.detection.normalizer import normalize
from sentinel.detection.pii_detector import PIIDetector, options_from_policy
from sentinel.engine.policy_engine import effective_threshold

MODES = ("rules", "ml", "hybrid")


async def main() -> None:
    rows = load_split("test")
    ctx = await make_context(cache=True)
    policy = ctx.policy_store.current
    pipe = ctx.pipeline
    inputs = [r for r in rows if r["stage"] == "input"]
    benign = [r for r in inputs if r["label"] == 0 and r["category"] == "benign"]
    out: list[dict[str, Any]] = []

    async def run_det(det, sample, mode: str, name: str):
        n = normalize(sample["text"], max_chars=200_000)
        opts = {"ml_weight": getattr(policy, name).ml_weight} if name in ("prompt_injection", "jailbreak") else {}
        return await det.run(n, DetectionContext(mode=mode, threshold=effective_threshold(policy, name, None), options=opts))

    for name, det, positives in (("prompt_injection", pipe.injection, "prompt_injection"), ("jailbreak", pipe.jailbreak, "jailbreak")):
        subset = [r for r in inputs if r["category"] == positives] + benign
        for mode in MODES:
            preds = []
            for i, r in enumerate(subset, 1):
                preds.append(1 if (await run_det(det, r, mode, name)).detected else 0)
                progress(i, len(subset), f"{name}/{mode}")
            out.append({"detector": name, "mode": mode, "n": len(subset),
                        "metrics": binary_metrics([1 if r["category"] == positives else 0 for r in subset], preds)})

    attack = [r for r in inputs if r["category"] in ("prompt_injection", "jailbreak")] + benign
    for mode in MODES:
        preds = []
        for r in attack:
            a = await run_det(pipe.injection, r, mode, "prompt_injection")
            b = await run_det(pipe.jailbreak, r, mode, "jailbreak")
            preds.append(1 if (a.detected or b.detected) else 0)
        out.append({"detector": "any_attack", "mode": mode, "n": len(attack),
                    "metrics": binary_metrics([r["label"] for r in attack], preds)})

    ctx_rows = [r for r in rows if r["stage"] == "context"]
    for mode in MODES:
        pol = policy.context.model_copy(update={"mode": mode})
        preds = []
        for i, r in enumerate(ctx_rows, 1):
            ci = await pipe.context.inspect([ContextChunk(id=r["id"], text=r["text"])], pol)
            preds.append(1 if ci.chunks[0].flagged else 0)
            progress(i, len(ctx_rows), f"context/{mode}")
        out.append({"detector": "context", "mode": mode, "n": len(ctx_rows),
                    "metrics": binary_metrics([r["label"] for r in ctx_rows], preds)})

    sec_subset = [r for r in inputs if r["category"] == "secret"] + benign
    preds = [1 if (await pipe.secret.run(normalize(r["text"], max_chars=200_000), DetectionContext())).detected else 0 for r in sec_subset]
    out.append({"detector": "secret_detection", "mode": "rules+entropy", "n": len(sec_subset),
                "metrics": binary_metrics([1 if r["category"] == "secret" else 0 for r in sec_subset], preds)})

    tox_subset = [r for r in inputs if r["category"] == "toxicity"] + benign
    thr = effective_threshold(policy, "toxicity", None)
    preds = [1 if (await pipe.toxicity.run(normalize(r["text"], max_chars=200_000), DetectionContext(threshold=thr))).detected else 0
             for r in tox_subset]
    out.append({"detector": "toxicity", "mode": "ml", "n": len(tox_subset),
                "metrics": binary_metrics([1 if r["category"] == "toxicity" else 0 for r in tox_subset], preds)})

    # PII: Presidio (loaded) vs regex fallback.
    pii_rows = [r for r in inputs if r["category"] == "pii"]
    opts = options_from_policy(policy.pii)
    for engine_name, det in (("presidio", pipe.pii), ("regex_fallback", PIIDetector())):
        found = total = 0
        per_type: dict[str, list[int]] = {}
        for r in pii_rows:
            spans = await det.find_spans(r["text"], opts)
            covered = [r["text"][s.start:s.end] for s in spans]
            for v, etype in zip(r["pii_values"], r.get("pii_types") or [None] * len(r["pii_values"])):
                total += 1
                hit = any(v in c or c in v and len(c) >= 0.6 * len(v) for c in covered)
                found += hit
                per_type.setdefault(etype or "unknown", [0, 0])
                per_type[etype or "unknown"][0] += hit
                per_type[etype or "unknown"][1] += 1
        fp_entities = 0
        for r in benign:
            fp_entities += len(await det.find_spans(r["text"], opts))
        out.append({"detector": "pii", "mode": engine_name, "n": len(pii_rows), "metrics": {
            "value_recall": round(found / total, 4) if total else None, "values": total,
            "false_entities_per_benign_sample": round(fp_entities / len(benign), 4), "recall": round(found / total, 4) if total else None,
            "recall_by_type": {k: round(h / n, 4) for k, (h, n) in sorted(per_type.items())}}})

    # Trained scikit-learn baseline.
    artifact = ROOT / "models_cache" / "sentinel_sklearn" / "tfidf_lr.joblib"
    if artifact.exists():
        import joblib

        clf = joblib.load(artifact)  # artifact produced by experiments/train_baseline.py in this repository
        subset = [r for r in rows if r["category"] in ("prompt_injection", "jailbreak", "indirect_injection") or r["label"] == 0]
        probs = clf.predict_proba([r["text"] for r in subset])[:, 1]
        labels = [1 if r["category"] in ("prompt_injection", "jailbreak", "indirect_injection") else 0 for r in subset]
        out.append({"detector": "sklearn_tfidf_lr", "mode": "trained", "n": len(subset),
                    "metrics": binary_metrics(labels, [1 if p >= 0.5 else 0 for p in probs])})

    for row in out:
        m = row["metrics"]
        print(f"{row['detector']:18} {row['mode']:15} n={row['n']:<4} P={m.get('precision')} R={m.get('recall')} "
              f"F1={m.get('f1')} FPR={m.get('fpr')}")
    path = write_result("detector_eval", {"dataset": dataset_info(rows, "test"), "rows": out,
                                          "thresholds": {k: effective_threshold(policy, k, None) for k in ("prompt_injection", "jailbreak", "toxicity", "context")},
                                          "summary": {f"{r['detector']}/{r['mode']}": r["metrics"].get("f1") for r in out}})
    print(f"wrote {path}")


if __name__ == "__main__":
    asyncio.run(main())
