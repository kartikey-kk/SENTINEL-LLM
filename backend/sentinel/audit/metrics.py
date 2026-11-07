"""Dashboard metrics computed from persisted audit data (no synthetic numbers)."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select

from sentinel.db.models import DetectionResultRow, RequestMetric, SecurityEvent
from sentinel.db.session import Database

THREAT_CATEGORIES = {"prompt_injection", "jailbreak", "secret", "toxicity", "indirect_injection", "tool_abuse"}


def percentile(values: list[float], q: float) -> float | None:
    if not values:
        return None
    s = sorted(values)
    k = (len(s) - 1) * q
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return round(s[lo] + (s[hi] - s[lo]) * (k - lo), 2)


def _aware(ts: datetime) -> datetime:
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


async def compute_metrics(db: Database, hours: int = 24) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=hours)
    async with db.sessionmaker() as s:
        events = (await s.execute(
            select(SecurityEvent.id, SecurityEvent.request_id, SecurityEvent.timestamp, SecurityEvent.event_type,
                   SecurityEvent.decision, SecurityEvent.output_decision, SecurityEvent.threat_category,
                   SecurityEvent.threat_categories, SecurityEvent.severity, SecurityEvent.risk_score,
                   SecurityEvent.provider, SecurityEvent.processing_latency, SecurityEvent.review_status,
                   SecurityEvent.input_preview)
            .where(SecurityEvent.timestamp >= since).order_by(SecurityEvent.timestamp.desc()).limit(50000)
        )).all()
        metrics = (await s.execute(
            select(RequestMetric.provider, RequestMetric.model, RequestMetric.llm_latency_ms, RequestMetric.error,
                   RequestMetric.prompt_tokens, RequestMetric.completion_tokens, RequestMetric.endpoint)
            .where(RequestMetric.timestamp >= since).limit(50000)
        )).all()
        det_rows = (await s.execute(
            select(DetectionResultRow.stage, DetectionResultRow.detector, DetectionResultRow.detected,
                   DetectionResultRow.status, DetectionResultRow.latency_ms)
            .join(SecurityEvent, SecurityEvent.id == DetectionResultRow.event_id)
            .where(SecurityEvent.timestamp >= since).limit(200000)
        )).all()

    total = len(events)
    blocked = sum(1 for e in events if e.decision == "BLOCK" or e.output_decision == "BLOCK")
    threats = sum(1 for e in events if set(e.threat_categories or []) & THREAT_CATEGORIES
                  or any(str(c).startswith("output_") for c in (e.threat_categories or [])))
    pii_redactions = sum(1 for e in events if "pii" in (e.threat_categories or []) and e.decision in ("REDACT", "ALLOW"))
    decisions = Counter(("BLOCK" if e.output_decision == "BLOCK" else e.decision) for e in events)
    severities = Counter(e.severity for e in events)
    categories: Counter[str] = Counter()
    for e in events:
        categories.update(set(e.threat_categories or []))
    event_types = Counter(e.event_type for e in events)
    latencies = [e.processing_latency for e in events if e.processing_latency is not None]

    bucket_minutes = 15 if hours <= 6 else 60 if hours <= 72 else 360
    buckets: dict[datetime, dict[str, int]] = defaultdict(lambda: {"total": 0, "threats": 0, "blocked": 0, "redacted": 0})
    for e in events:
        ts = _aware(e.timestamp)
        floored = ts.replace(second=0, microsecond=0, minute=(ts.minute // bucket_minutes) * bucket_minutes if bucket_minutes < 60 else 0)
        if bucket_minutes > 60:
            floored = floored.replace(hour=(floored.hour // (bucket_minutes // 60)) * (bucket_minutes // 60))
        b = buckets[floored]
        b["total"] += 1
        if set(e.threat_categories or []) & THREAT_CATEGORIES:
            b["threats"] += 1
        if e.decision == "BLOCK" or e.output_decision == "BLOCK":
            b["blocked"] += 1
        if e.decision == "REDACT":
            b["redacted"] += 1
    timeseries = [{"bucket": k.isoformat(), **v} for k, v in sorted(buckets.items())]

    providers: dict[str, dict[str, Any]] = {}
    grouped: dict[tuple[str, str], list[Any]] = defaultdict(list)
    for m in metrics:
        if m.provider:
            grouped[(m.provider, m.model or "")].append(m)
    for (prov, model), rows in grouped.items():
        lat = [r.llm_latency_ms for r in rows if r.llm_latency_ms is not None]
        providers[f"{prov}/{model}" if model else prov] = {
            "provider": prov, "model": model or None, "requests": len(rows),
            "llm_calls": len(lat), "avg_llm_latency_ms": round(sum(lat) / len(lat), 2) if lat else None,
            "p95_llm_latency_ms": percentile(lat, 0.95), "errors": sum(1 for r in rows if r.error),
            "prompt_tokens": sum(r.prompt_tokens or 0 for r in rows),
            "completion_tokens": sum(r.completion_tokens or 0 for r in rows),
        }

    det_stats: dict[str, dict[str, Any]] = {}
    for stage, det, detected, status, row_latency in det_rows:
        if stage == "context":
            det = "context"
        key = f"{stage}:{det}"
        d = det_stats.setdefault(key, {"stage": stage, "detector": det, "runs": 0, "detections": 0, "failures": 0, "_lat": []})
        d["runs"] += 1
        d["detections"] += int(bool(detected))
        d["failures"] += int(status in ("error", "timeout", "unavailable"))
        d["_lat"].append(row_latency or 0.0)
    for d in det_stats.values():
        samples: list[float] = d.pop("_lat")
        d["avg_latency_ms"] = round(sum(samples) / len(samples), 2) if samples else None
        d["p95_latency_ms"] = percentile(samples, 0.95)

    reviews = Counter(e.review_status for e in events if e.review_status)
    fp, tp = reviews.get("false_positive", 0), reviews.get("true_positive", 0)

    recent = [
        {"request_id": e.request_id, "timestamp": _aware(e.timestamp).isoformat(), "event_type": e.event_type,
         "decision": e.decision, "output_decision": e.output_decision, "threat_category": e.threat_category,
         "severity": e.severity, "risk_score": e.risk_score, "provider": e.provider, "latency_ms": e.processing_latency,
         "preview": e.input_preview}
        for e in events[:12]
    ]
    return {
        "window_hours": hours,
        "generated_at": now.isoformat(),
        "totals": {
            "requests": total, "threats_detected": threats, "blocked": blocked, "pii_redactions": pii_redactions,
            "human_review": decisions.get("HUMAN_REVIEW", 0),
            "avg_latency_ms": round(sum(latencies) / len(latencies), 2) if latencies else None,
            "p50_latency_ms": percentile(latencies, 0.5), "p95_latency_ms": percentile(latencies, 0.95),
            "p99_latency_ms": percentile(latencies, 0.99),
        },
        "decisions": dict(decisions),
        "severities": dict(severities),
        "categories": dict(categories.most_common()),
        "event_types": dict(event_types),
        "timeseries": timeseries,
        "bucket_minutes": bucket_minutes,
        "providers": list(providers.values()),
        "detectors": sorted(det_stats.values(), key=lambda d: d["detector"]),
        "reviews": {"counts": dict(reviews), "observed_false_positive_rate": round(fp / (fp + tp), 4) if fp + tp else None},
        "recent_events": recent,
    }
