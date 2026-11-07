"""PII detection evaluation per entity type (validation and test splits).

Value-level recall: a ground-truth PII value counts as found when a detected span covers it.
False entities: spans reported on benign prompts (over-redaction).

Usage: backend/.venv/Scripts/python experiments/evaluate_pii.py
"""

from __future__ import annotations

import asyncio

from common import load_split, make_context, write_result
from sentinel.detection.pii_detector import PIIDetector, options_from_policy


async def score(det: PIIDetector, rows, benign, opts) -> dict:
    found = total = 0
    per_type: dict[str, list[int]] = {}
    for r in rows:
        spans = await det.find_spans(r["text"], opts)
        covered = [r["text"][s.start:s.end] for s in spans]
        for v, t in zip(r["pii_values"], r["pii_types"]):
            hit = any(v in c or (c in v and len(c) >= 0.6 * len(v)) for c in covered)
            found += hit
            total += 1
            per_type.setdefault(t, [0, 0])
            per_type[t][0] += hit
            per_type[t][1] += 1
    false_entities = 0
    types: dict[str, int] = {}
    for r in benign:
        for s in await det.find_spans(r["text"], opts):
            false_entities += 1
            types[s.type] = types.get(s.type, 0) + 1
    return {"value_recall": round(found / total, 4), "values": total, "samples": len(rows),
            "recall_by_type": {k: f"{h}/{n}" for k, (h, n) in sorted(per_type.items())},
            "false_entities_per_benign_prompt": round(false_entities / len(benign), 4),
            "false_entity_types": dict(sorted(types.items(), key=lambda kv: -kv[1]))}


async def main() -> None:
    ctx = await make_context()
    opts = options_from_policy(ctx.policy_store.current.pii)
    out = {}
    for split in ("validation", "test"):
        rows = load_split(split)
        pii = [r for r in rows if r["category"] == "pii"]
        benign = [r for r in rows if r["category"] == "benign" and r["stage"] == "input"]
        for name, det in (("presidio+checksum", ctx.pii), ("regex_fallback", PIIDetector())):
            res = await score(det, pii, benign, opts)
            out[f"{split}/{name}"] = res
            print(split, name, res)
    path = write_result("detector_eval_pii", {"results": out, "engine": ctx.pii.status(),
                                              "summary": {k: v["value_recall"] for k, v in out.items()}})
    print("wrote", path)


if __name__ == "__main__":
    asyncio.run(main())
