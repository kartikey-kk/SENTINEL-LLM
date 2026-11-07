"""Latency benchmark (no memoization).

Measures, on a fixed stratified sample of test inputs:
  * each detector in isolation (normalizer, injection hybrid, jailbreak hybrid, PII/Presidio, secrets, toxicity)
  * the complete input-inspection pipeline (hybrid, verification off), in-process
  * optionally, end-to-end HTTP latency of POST /api/v1/inspect/input against a running gateway (--http URL)
and reports mean / P50 / P95 / P99, plus a breakdown by input length.

Usage: backend/.venv/Scripts/python experiments/benchmark_latency.py [--n 200] [--http http://127.0.0.1:8000]
"""

from __future__ import annotations

import argparse
import asyncio
import random
import time
from collections import defaultdict

from common import dataset_info, latency_stats, load_split, make_context, write_result
from sentinel.detection.base import DetectionContext
from sentinel.detection.normalizer import normalize
from sentinel.detection.pii_detector import options_from_policy
from sentinel.engine.policy_engine import effective_threshold


def length_bucket(n: int) -> str:
    return "short (<200 chars)" if n < 200 else "medium (200-1000)" if n < 1000 else "long (>1000)"


async def main(args: argparse.Namespace) -> None:
    rows = [r for r in load_split("test") if r["stage"] == "input"]
    rnd = random.Random(7)
    rnd.shuffle(rows)
    rows = rows[: args.n]
    ctx = await make_context(cache=False)
    pol = ctx.policy_store.current.model_copy(deep=True)
    pol.verification.enabled = False
    pipe = ctx.pipeline
    dets = {
        "prompt_injection": (pipe.injection, DetectionContext(mode="hybrid", threshold=effective_threshold(pol, "prompt_injection", None),
                                                              options={"ml_weight": pol.prompt_injection.ml_weight})),
        "jailbreak": (pipe.jailbreak, DetectionContext(mode="hybrid", threshold=effective_threshold(pol, "jailbreak", None),
                                                       options={"ml_weight": pol.jailbreak.ml_weight})),
        "pii": (pipe.pii, DetectionContext(options=options_from_policy(pol.pii))),
        "secret_detection": (pipe.secret, DetectionContext(options={"entropy": True})),
        "toxicity": (pipe.toxicity, DetectionContext(threshold=pol.toxicity.threshold)),
    }
    # Warm-up (first calls allocate buffers / JIT kernels).
    for r in rows[:5]:
        await pipe.inspect_input(r["text"], policy=pol, allow_verification=False)

    lat: dict[str, list[float]] = defaultdict(list)
    by_len: dict[str, list[float]] = defaultdict(list)
    for r in rows:
        t0 = time.perf_counter()
        norm = normalize(r["text"], max_chars=200_000)
        lat["normalizer"].append((time.perf_counter() - t0) * 1000)
        for name, (det, dctx) in dets.items():
            t1 = time.perf_counter()
            await det.run(norm, dctx)
            lat[name].append((time.perf_counter() - t1) * 1000)
        t2 = time.perf_counter()
        await pipe.inspect_input(r["text"], policy=pol, allow_verification=False)
        total = (time.perf_counter() - t2) * 1000
        lat["pipeline_inprocess"].append(total)
        by_len[length_bucket(len(r["text"]))].append(total)

    http = None
    if args.http:
        import httpx

        async with httpx.AsyncClient(base_url=args.http, timeout=120) as c:
            await c.get("/api/v1/health")
            times = []
            for r in rows:
                t = time.perf_counter()
                resp = await c.post("/api/v1/inspect/input", json={"text": r["text"], "verify": False})
                if resp.status_code == 200:
                    times.append((time.perf_counter() - t) * 1000)
            http = {"url_host": args.http.split("//")[-1], "requests": len(times), **latency_stats(times)}
            lat["http_end_to_end"] = times

    stats = {k: {"n": len(v), **latency_stats(v)} for k, v in lat.items()}
    for k, v in stats.items():
        print(f"{k:20} n={v['n']:<4} mean={v['mean_ms']}ms p50={v['p50_ms']} p95={v['p95_ms']} p99={v['p99_ms']}")
    path = write_result("latency_benchmark", {
        "dataset": dataset_info(rows, "test"), "samples": len(rows),
        "detectors_run": "sequentially per sample (the pipeline runs them concurrently with bounded inference concurrency)",
        "stats": stats, "pipeline_by_length": {k: {"n": len(v), **latency_stats(v)} for k, v in by_len.items()},
        "http": http, "summary": {k: v["p95_ms"] for k, v in stats.items()},
    })
    print(f"wrote {path}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=200)
    ap.add_argument("--http", default=None)
    asyncio.run(main(ap.parse_args()))
