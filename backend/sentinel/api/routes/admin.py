"""Administrative endpoints: events, metrics, policies, evaluations."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Request
from sqlalchemy import func, or_, select

from sentinel.api.deps import AdminDep, Caller, get_ctx
from sentinel.api.middleware import request_id_of
from sentinel.audit.metrics import compute_metrics
from sentinel.config import REPO_ROOT
from sentinel.db.models import AuditLog, SecurityEvent
from sentinel.engine.policy_schema import POLICY_SECTIONS
from sentinel.schemas import api

router = APIRouter(prefix="/api/v1", tags=["administration"])


def _aware(ts: datetime) -> datetime:
    # SQLite returns naive datetimes; everything is stored in UTC.
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def _event_out(e: SecurityEvent) -> api.EventOut:
    return api.EventOut(
        request_id=e.request_id, timestamp=_aware(e.timestamp), session_id=e.session_id, event_type=e.event_type,
        threat_category=e.threat_category, threat_categories=list(e.threat_categories or []), severity=e.severity,
        risk_score=e.risk_score, decision=e.decision, output_decision=e.output_decision, provider=e.provider,
        model=e.model, processing_latency=e.processing_latency, input_preview=e.input_preview,
        policy_version=e.policy_version, review_status=e.review_status,
    )


@router.get("/events", response_model=api.EventPage, summary="Search and filter security events")
async def list_events(
    request: Request,
    caller: Caller = AdminDep,
    decision: str | None = Query(default=None, max_length=16),
    severity: str | None = Query(default=None, max_length=16),
    category: str | None = Query(default=None, max_length=64),
    event_type: str | None = Query(default=None, max_length=32),
    provider: str | None = Query(default=None, max_length=64),
    review_status: str | None = Query(default=None, max_length=32),
    q: str | None = Query(default=None, max_length=200, description="Search request id, session id or redacted preview"),
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0, le=1_000_000),
) -> api.EventPage:
    ctx = get_ctx(request)
    conds = []
    if decision:
        conds.append(or_(SecurityEvent.decision == decision.upper(), SecurityEvent.output_decision == decision.upper()))
    if severity:
        conds.append(SecurityEvent.severity == severity.lower())
    if category:
        conds.append(SecurityEvent.threat_category == category)
    if event_type:
        conds.append(SecurityEvent.event_type == event_type)
    if provider:
        conds.append(SecurityEvent.provider == provider)
    if review_status:
        conds.append(SecurityEvent.review_status == review_status)
    if since:
        conds.append(SecurityEvent.timestamp >= since)
    if until:
        conds.append(SecurityEvent.timestamp <= until)
    if q:
        like = f"%{q}%"
        conds.append(or_(SecurityEvent.request_id.ilike(like), SecurityEvent.session_id.ilike(like),
                         SecurityEvent.input_preview.ilike(like)))
    async with ctx.db.sessionmaker() as s:
        total = (await s.execute(select(func.count(SecurityEvent.id)).where(*conds))).scalar_one()
        rows = (await s.execute(select(SecurityEvent).where(*conds).order_by(SecurityEvent.timestamp.desc())
                                .limit(limit).offset(offset))).scalars().all()
    return api.EventPage(items=[_event_out(e) for e in rows], total=total, limit=limit, offset=offset)


@router.get("/events/{request_id}", response_model=api.EventDetailOut, summary="Full sanitized record for one request")
async def get_event(request_id: str, request: Request, caller: Caller = AdminDep) -> api.EventDetailOut:
    ctx = get_ctx(request)
    async with ctx.db.sessionmaker() as s:
        e = (await s.execute(select(SecurityEvent).where(SecurityEvent.request_id == request_id))).scalar_one_or_none()
        if e is None:
            raise HTTPException(status_code=404, detail="Event not found")
        base = _event_out(e).model_dump()
        dets = [api.EventDetection(stage=d.stage, detector=d.detector, detected=d.detected, score=d.score,
                                   confidence=d.confidence, severity=d.severity, status=d.status, method=d.method,
                                   reason=d.reason, latency_ms=d.latency_ms, details=d.details or {})
                for d in e.detections]
    return api.EventDetailOut(**base, detector_metadata=e.detector_metadata or {}, detections=dets)


@router.post("/events/{request_id}/review", summary="Record a human review disposition")
async def review_event(request_id: str, body: api.ReviewRequest, request: Request, caller: Caller = AdminDep) -> dict:
    ctx = get_ctx(request)
    async with ctx.db.sessionmaker() as s:
        e = (await s.execute(select(SecurityEvent).where(SecurityEvent.request_id == request_id))).scalar_one_or_none()
        if e is None:
            raise HTTPException(status_code=404, detail="Event not found")
        previous = e.review_status
        e.review_status = body.status
        s.add(AuditLog(actor="admin", action="event.review", target=request_id, request_id=request_id_of(request),
                       details={"from": previous, "to": body.status, "note": body.note}))
        await s.commit()
    return {"request_id": request_id, "review_status": body.status}


@router.get("/metrics", summary="Aggregated security metrics")
async def metrics(request: Request, caller: Caller = AdminDep, hours: int = Query(default=24, ge=1, le=24 * 90)) -> dict:
    ctx = get_ctx(request)
    return await compute_metrics(ctx.db, hours)


@router.get("/policies", summary="Active policy, version and recent changes")
async def get_policies(request: Request, caller: Caller = AdminDep) -> dict:
    ctx = get_ctx(request)
    policy = ctx.policy_store.current
    async with ctx.db.sessionmaker() as s:
        changes = (await s.execute(select(AuditLog).where(AuditLog.action == "policy.update")
                                   .order_by(AuditLog.timestamp.desc()).limit(20))).scalars().all()
    return {
        "version": policy.version,
        "hash": ctx.policy_store.hash(),
        "sections": list(POLICY_SECTIONS),
        "policy": policy.model_dump(mode="json"),
        "providers_configured": sorted(ctx.router.providers.keys()),
        "recent_changes": [{"timestamp": _aware(c.timestamp).isoformat(), "actor": c.actor, "section": c.target,
                            "from_version": c.details.get("from_version"), "to_version": c.details.get("to_version"),
                            "comment": c.details.get("comment")} for c in changes],
    }


@router.get("/policies/{policy_id}", summary="One policy section")
async def get_policy(policy_id: str, request: Request, caller: Caller = AdminDep) -> dict:
    ctx = get_ctx(request)
    try:
        return {"policy_id": policy_id, "version": ctx.policy_store.current.version, "value": ctx.policy_store.section(policy_id)}
    except KeyError:
        raise HTTPException(status_code=404, detail="Unknown policy section") from None


@router.put("/policies/{policy_id}", summary="Replace one policy section (validated, versioned, audited)")
async def put_policy(policy_id: str, body: api.PolicyUpdateRequest, request: Request, caller: Caller = AdminDep) -> dict:
    ctx = get_ctx(request)
    if policy_id not in POLICY_SECTIONS:
        raise HTTPException(status_code=404, detail="Unknown policy section")
    async with ctx.db.sessionmaker() as s:
        updated = await ctx.policy_store.update_section(s, policy_id, body.value, actor="admin", comment=body.comment)
    return {"policy_id": policy_id, "version": updated.version, "hash": ctx.policy_store.hash(),
            "value": ctx.policy_store.section(policy_id)}


@router.get("/evaluations", summary="Stored evaluation and experiment results")
async def evaluations(request: Request, caller: Caller = AdminDep,
                      kind: Literal["all", "detectors", "firewall", "latency", "experiments"] = "all") -> dict:
    results_dir = REPO_ROOT / "experiments" / "results"
    items = []
    if results_dir.exists():
        for p in sorted(results_dir.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True)[:50]:
            try:
                data = json.loads(Path(p).read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            k = data.get("kind", "unknown")
            if kind != "all" and not str(k).startswith(kind.rstrip("s")):
                continue
            items.append({"file": p.name, "kind": k, "created_at": data.get("created_at"), "summary": data.get("summary"),
                          "data": data})
    return {"items": items}
