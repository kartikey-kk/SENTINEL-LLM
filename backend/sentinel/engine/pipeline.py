"""Request pipeline / service layer.

Flow for every input:
  normalize -> parallel detectors (bounded, timed) -> risk score -> policy decision
  -> (escalate-only verification) -> enforcement -> [provider] -> output validation
  -> output enforcement -> audit

Each stage is a separate component; this module only wires them together and
guarantees that every security decision is audited.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass

from sentinel.audit.service import AuditService
from sentinel.config import Settings
from sentinel.detection.base import DetectionContext, Detector
from sentinel.detection.context_detector import ContextInspection, ContextSecurityDetector, SecurePromptBundle
from sentinel.detection.injection_detector import PromptInjectionDetector
from sentinel.detection.jailbreak_detector import JailbreakDetector
from sentinel.detection.normalizer import InputValidationError, NormalizedInput, normalize
from sentinel.detection.output_validator import OutputValidation, OutputValidator
from sentinel.detection.pii_detector import PIIDetector, options_from_policy
from sentinel.detection.secret_detector import SecretDetector
from sentinel.detection.toxicity_detector import ToxicityDetector
from sentinel.detection.verifier import LLMVerifier, VerificationResult
from sentinel.engine.enforcement import EnforcementResult, Redactor, collect_spans, enforce, restore_placeholders
from sentinel.engine.policy_engine import PolicyDecision, PolicyEngine, PolicyStore, ProviderContext, effective_threshold
from sentinel.engine.policy_schema import SentinelPolicy
from sentinel.engine.risk_scorer import RiskAssessment, score_risk
from sentinel.providers.base import ChatMessage, LLMProvider, LLMResponse, ProviderError
from sentinel.providers.router import ProviderRouter
from sentinel.schemas import api
from sentinel.schemas.common import Decision, DetectionResult, DetectorStatus, most_restrictive
from sentinel.security.pii_vault import PIIVault
from sentinel.security.tool_guard import ToolGuard

logger = logging.getLogger(__name__)

DEFAULT_SYSTEM_PROMPT = "You are a helpful, accurate assistant."
OUTPUT_WITHHELD = "The model response was withheld by the SentinelLLM output policy."


@dataclass
class InputInspection:
    normalized: NormalizedInput
    results: dict[str, DetectionResult]
    risk: RiskAssessment
    policy_decision: PolicyDecision
    final_decision: Decision
    enforcement: EnforcementResult
    verification: VerificationResult | None
    latency_ms: float


class SentinelPipeline:
    def __init__(
        self,
        *,
        settings: Settings,
        injection: PromptInjectionDetector,
        jailbreak: JailbreakDetector,
        pii: PIIDetector,
        secret: SecretDetector,
        toxicity: ToxicityDetector,
        context: ContextSecurityDetector,
        output_validator: OutputValidator,
        verifier: LLMVerifier,
        router: ProviderRouter,
        policy_store: PolicyStore,
        tool_guard: ToolGuard,
        vault: PIIVault,
        audit: AuditService,
    ) -> None:
        self.settings = settings
        self.injection = injection
        self.jailbreak = jailbreak
        self.pii = pii
        self.secret = secret
        self.toxicity = toxicity
        self.context = context
        self.output_validator = output_validator
        self.verifier = verifier
        self.router = router
        self.policy_store = policy_store
        self.tool_guard = tool_guard
        self.vault = vault
        self.audit = audit
        self.engine = PolicyEngine()

    # ------------------------------------------------------------------ helpers
    async def _run(self, det: Detector, inp: NormalizedInput, ctx: DetectionContext) -> DetectionResult:
        try:
            return await asyncio.wait_for(det.run(inp, ctx), timeout=self.settings.detector_timeout_seconds)
        except asyncio.TimeoutError:
            return DetectionResult(detector=det.name, status=DetectorStatus.TIMEOUT, reason="Detector timed out",
                                   latency_ms=self.settings.detector_timeout_seconds * 1000)

    def _check_profile(self, policy: SentinelPolicy, profile: str | None) -> None:
        if profile is not None and profile not in policy.context_profiles:
            raise InputValidationError(f"Unknown context_profile '{profile}'", code="unknown_context_profile")

    def provider_context(self, name: str | None) -> tuple[LLMProvider | None, ProviderContext | None]:
        if name is None:
            return None, None
        provider = self.router.get(name)
        return provider, ProviderContext(name=provider.name, is_local=provider.is_local)

    async def run_input_detectors(
        self,
        norm: NormalizedInput,
        policy: SentinelPolicy,
        *,
        profile: str | None = None,
        history: list[dict[str, str]] | None = None,
        mode_override: str | None = None,
    ) -> dict[str, DetectionResult]:
        tasks: dict[str, asyncio.Future] = {}
        hist = history or []
        if policy.prompt_injection.enabled:
            ctx = DetectionContext(mode=mode_override or policy.prompt_injection.mode,  # type: ignore[arg-type]
                                   threshold=effective_threshold(policy, "prompt_injection", profile), history=hist,
                                   options={"ml_weight": policy.prompt_injection.ml_weight})
            tasks["prompt_injection"] = asyncio.ensure_future(self._run(self.injection, norm, ctx))
        if policy.jailbreak.enabled:
            ctx = DetectionContext(mode=mode_override or policy.jailbreak.mode,  # type: ignore[arg-type]
                                   threshold=effective_threshold(policy, "jailbreak", profile), history=hist,
                                   options={"ml_weight": policy.jailbreak.ml_weight})
            tasks["jailbreak"] = asyncio.ensure_future(self._run(self.jailbreak, norm, ctx))
        if policy.pii.enabled:
            tasks["pii"] = asyncio.ensure_future(self._run(self.pii, norm, DetectionContext(options=options_from_policy(policy.pii))))
        if policy.secret_detection.enabled:
            opts = {"entropy": policy.secret_detection.entropy, "min_weight": policy.secret_detection.min_weight}
            tasks["secret_detection"] = asyncio.ensure_future(self._run(self.secret, norm, DetectionContext(options=opts)))
        if policy.toxicity.enabled and mode_override != "rules":
            ctx = DetectionContext(threshold=effective_threshold(policy, "toxicity", profile))
            tasks["toxicity"] = asyncio.ensure_future(self._run(self.toxicity, norm, ctx))
        done = await asyncio.gather(*tasks.values())
        return dict(zip(tasks.keys(), done))

    async def _verify(self, text: str, decision: PolicyDecision, policy: SentinelPolicy, allow: bool) -> tuple[Decision, VerificationResult | None]:
        base = decision.decision_without_verify()
        if base == Decision.ALLOW and decision.redact_categories:
            base = Decision.REDACT
        if not allow:
            return most_restrictive(base, policy.verification.on_unavailable), VerificationResult(status="skipped")
        vr = await self.verifier.verify(text, decision.verify_sources, policy.verification)
        if vr.status != "ok":
            return most_restrictive(base, policy.verification.on_unavailable), vr
        return (Decision.BLOCK if vr.escalate else base), vr

    # ------------------------------------------------------------- input stage
    async def inspect_input(
        self,
        text: str,
        *,
        policy: SentinelPolicy,
        content_type: str = "text",
        profile: str | None = None,
        history: list[dict[str, str]] | None = None,
        provider_ctx: ProviderContext | None = None,
        mode_override: str | None = None,
        allow_verification: bool = True,
        redactor: Redactor | None = None,
    ) -> InputInspection:
        start = time.perf_counter()
        self._check_profile(policy, profile)
        norm = normalize(text, max_chars=self.settings.max_input_chars, content_type=content_type)
        results = await self.run_input_detectors(norm, policy, profile=profile, history=history, mode_override=mode_override)
        risk = score_risk(results, policy, profile)
        decision = self.engine.evaluate(results, risk, policy, provider=provider_ctx, profile=profile)
        final = decision.decision
        verification = None
        if final == Decision.VERIFY:
            final, verification = await self._verify(norm.text, decision, policy, allow_verification)
        enf = enforce(norm.text, results, decision, final_decision=final, redactor=redactor)
        return InputInspection(
            normalized=norm, results=results, risk=risk, policy_decision=decision, final_decision=enf.decision,
            enforcement=enf, verification=verification, latency_ms=round((time.perf_counter() - start) * 1000, 2),
        )

    def _input_metadata(self, ins: InputInspection) -> dict:
        return {
            "risk": {"score": ins.risk.score, "weighted": ins.risk.weighted_score, "explanation": ins.risk.explanation,
                     "components": {k: v.model_dump() for k, v in ins.risk.components.items()},
                     "critical_override": ins.risk.critical_override, "incomplete": ins.risk.incomplete,
                     "profile": ins.risk.profile},
            "policy_reasons": [r.model_dump(mode="json") for r in ins.policy_decision.reasons],
            "initial_decision": ins.policy_decision.decision.value,
            "normalization_signals": ins.normalized.signal_summary(),
            "redactions": [{"type": e.type, "placeholder": e.placeholder} for e in ins.enforcement.redactions],
            "verification": ins.verification.model_dump(exclude={"rationale"}) if ins.verification else None,
        }

    async def handle_inspect_input(self, req: api.InspectInputRequest, *, request_id: str, client_id: str | None,
                                   is_admin: bool) -> api.InspectInputResponse:
        policy = self.policy_store.current
        _, pctx = self.provider_context(req.provider)
        mode = req.detection_mode if is_admin else None
        ins = await self.inspect_input(
            req.text, policy=policy, content_type=req.content_type, profile=req.context_profile,
            history=[m.model_dump() for m in req.history], provider_ctx=pctx, mode_override=mode,
            allow_verification=req.verify,
        )
        await self.audit.record_event(
            request_id=request_id, event_type="input", decision=ins.final_decision.value,
            stages={"input": ins.results}, risk_score=ins.risk.score, severity=ins.risk.severity,
            session_id=req.session_id, provider=req.provider, latency_ms=ins.latency_ms, raw_input=req.text,
            sanitized_preview=ins.enforcement.sanitized_text, policy_version=policy.version, client_id=client_id,
            metadata=self._input_metadata(ins),
        )
        await self.audit.record_metric(request_id=request_id, endpoint="inspect_input", decision=ins.final_decision.value,
                                       total_latency_ms=ins.latency_ms, detection_latency_ms=ins.latency_ms)
        return api.InspectInputResponse(
            request_id=request_id, decision=ins.final_decision,
            forwardable=ins.enforcement.forward, risk=ins.risk, detections=list(ins.results.values()),
            policy=api.PolicyInfo(version=policy.version, reasons=ins.policy_decision.reasons,
                                  initial_decision=ins.policy_decision.decision),
            sanitized_text=ins.enforcement.sanitized_text, redactions=ins.enforcement.redactions,
            normalization=api.NormalizationInfo(signals=ins.normalized.signal_summary(),
                                                removed_chars=ins.normalized.removed_chars,
                                                decoded_views=[v.name for v in ins.normalized.decoded_views]),
            verification=ins.verification, message=ins.enforcement.message, latency_ms=ins.latency_ms,
        )

    # ------------------------------------------------------------ output stage
    async def handle_inspect_output(self, req: api.InspectOutputRequest, *, request_id: str,
                                    client_id: str | None) -> api.InspectOutputResponse:
        start = time.perf_counter()
        policy = self.policy_store.current
        ov = await self.output_validator.validate(
            req.text, policy, canary=req.canary, system_prompt=req.system_prompt, response_format=req.response_format,
            json_schema=req.json_schema, evidence=req.evidence, max_chars=self.settings.max_input_chars,
        )
        latency = round((time.perf_counter() - start) * 1000, 2)
        await self.audit.record_event(
            request_id=request_id, event_type="output", decision=ov.decision.value, output_decision=ov.decision.value,
            stages={"output": ov.results}, session_id=req.session_id, latency_ms=latency, raw_input=req.text,
            sanitized_preview=ov.sanitized_text if ov.decision != Decision.BLOCK else None,
            policy_version=policy.version, client_id=client_id,
            metadata={"output_checks": [c.model_dump(mode="json") for c in ov.checks],
                      "grounding": ov.grounding.model_dump() if ov.grounding else None},
            extra_categories=[f"output_{c.check}" for c in ov.failed_checks if c.action != Decision.ALLOW],
            risk_score=max((r.score for r in ov.results.values() if r.detected), default=0.0),
        )
        await self.audit.record_metric(request_id=request_id, endpoint="inspect_output", decision=ov.decision.value,
                                       total_latency_ms=latency, detection_latency_ms=latency)
        return api.InspectOutputResponse(
            request_id=request_id, decision=ov.decision, checks=ov.checks, detections=list(ov.results.values()),
            sanitized_text=None if ov.decision == Decision.BLOCK else ov.sanitized_text, redactions=ov.redactions,
            grounding=ov.grounding, latency_ms=latency,
        )

    # ----------------------------------------------------------- context stage
    def _context_redacts_pii(self, policy: SentinelPolicy, pctx: ProviderContext | None) -> bool:
        cloud = pctx is not None and pctx.is_local is False
        return policy.pii.action == Decision.REDACT or (cloud and policy.providers.cloud_requires_pii_redaction)

    async def handle_inspect_context(self, req: api.InspectContextRequest, *, request_id: str,
                                     client_id: str | None) -> api.InspectContextResponse:
        start = time.perf_counter()
        policy = self.policy_store.current
        self._check_profile(policy, req.context_profile)
        _, pctx = self.provider_context(req.provider)
        ci = await self.context.inspect(req.chunks, policy.context,
                                        threshold=effective_threshold(policy, "context", req.context_profile),
                                        redact_pii=self._context_redacts_pii(policy, pctx))
        latency = round((time.perf_counter() - start) * 1000, 2)
        await self._audit_context(request_id, ci, policy, req.session_id, client_id, latency, "context")
        return api.InspectContextResponse(**ci.model_dump(), request_id=request_id, latency_ms=latency)

    async def _audit_context(self, request_id: str, ci: ContextInspection, policy: SentinelPolicy, session_id: str | None,
                             client_id: str | None, latency: float, event_type: str) -> None:
        results = {
            c.id: DetectionResult(detector="context", detected=c.flagged, score=c.risk, confidence=c.ml_score,
                                  reason="; ".join(c.reasons)[:400] or "no indicators", method=policy.context.mode,
                                  metadata={"rule_categories": c.categories, "ml_available": c.ml_score is not None})
            for c in ci.chunks
        }
        await self.audit.record_event(
            request_id=request_id, event_type=event_type, decision=ci.decision.value, stages={"context": results},
            risk_score=ci.max_risk, session_id=session_id, latency_ms=latency, policy_version=policy.version,
            client_id=client_id,
            metadata={"chunks": [{"id": c.id, "source_type": c.source_type, "risk": c.risk, "action": c.action,
                                  "categories": c.categories, "included": c.included} for c in ci.chunks],
                      "threshold": ci.threshold},
            extra_categories=["indirect_injection"] if ci.flagged_count else None,
        )
        await self.audit.record_metric(request_id=request_id, endpoint=event_type, decision=ci.decision.value,
                                       total_latency_ms=latency, detection_latency_ms=latency)

    # --------------------------------------------------------------- tool stage
    async def handle_inspect_tool(self, req: api.InspectToolRequest, *, request_id: str,
                                  client_id: str | None) -> api.InspectToolResponse:
        start = time.perf_counter()
        policy = self.policy_store.current
        decision = await self.tool_guard.evaluate(req, policy.tools)
        output_ci = None
        if req.execute:
            decision = await self.tool_guard.execute(req, decision, policy.tools)
            if decision.executed and decision.result is not None:
                # Tool output is untrusted: inspect it before anyone feeds it to a model.
                import json as _json

                from sentinel.detection.context_detector import ContextChunk

                chunk = ContextChunk(id=f"tool:{req.tool_name}", source_type="tool_output", source=req.tool_name,
                                     text=_json.dumps(decision.result, ensure_ascii=False)[: policy.context.max_chunk_chars])
                output_ci = await self.context.inspect([chunk], policy.context, redact_pii=True)
        latency = round((time.perf_counter() - start) * 1000, 2)
        flagged = decision.decision != Decision.ALLOW
        tool_result = DetectionResult(
            detector="tool_guard", detected=flagged, score=1.0 if decision.decision == Decision.BLOCK else (0.5 if flagged else 0.0),
            reason="; ".join(decision.reasons)[:400], method="policy",
            metadata={"violations": [v.model_dump() for v in decision.violations]},
        )
        stages: dict[str, dict[str, DetectionResult]] = {"tool": {"tool_guard": tool_result}}
        await self.audit.record_event(
            request_id=request_id, event_type="tool", decision=decision.decision.value, stages=stages,
            risk_score=tool_result.score, session_id=req.session_id, latency_ms=latency, policy_version=policy.version,
            client_id=client_id,
            metadata={"tool": req.tool_name, "scope": req.scope, "permission": decision.permission,
                      "reasons": decision.reasons, "violations": [v.model_dump() for v in decision.violations],
                      "approved": decision.approved, "executed": decision.executed,
                      "argument_names": sorted(req.arguments.keys()),
                      "output_flagged": bool(output_ci and output_ci.flagged_count)},
            extra_categories=(["tool_abuse"] if decision.decision == Decision.BLOCK else [])
            + (["indirect_injection"] if output_ci and output_ci.flagged_count else []),
        )
        await self.audit.record_metric(request_id=request_id, endpoint="inspect_tool", decision=decision.decision.value,
                                       total_latency_ms=latency, detection_latency_ms=latency)
        return api.InspectToolResponse(**decision.model_dump(), request_id=request_id, output_inspection=output_ci,
                                       latency_ms=latency)

    # --------------------------------------------------------------- chat flow
    async def _sanitize_history(self, history: list[api.HistoryMessage], redactor: Redactor, redact_pii: bool,
                                policy: SentinelPolicy) -> list[ChatMessage]:
        out: list[ChatMessage] = []
        opts = options_from_policy(policy.pii)
        for m in history:
            text = m.content[: self.settings.max_input_chars]
            spans, _, _ = self.secret.find_spans(text)
            if redact_pii:
                spans = spans + await self.pii.find_spans(text, opts)
            if spans:
                fake = DetectionResult(detector="history")
                fake.set_spans(spans)
                text, _ = redactor.redact(text, collect_spans({"pii": fake}, {"pii", "secret"}))
            out.append(ChatMessage(role=m.role, content=text))
        return out

    async def handle_chat(self, req: api.ChatRequest, *, request_id: str, client_id: str | None) -> api.ChatResponse:
        start = time.perf_counter()
        policy = self.policy_store.current
        provider, pctx = self.provider_context(req.provider or self.router.default_name)
        assert provider is not None and pctx is not None
        self._check_profile(policy, req.context_profile)

        restoration = bool(req.restore_pii and policy.pii.allow_restoration and req.session_id)
        existing = await self.vault.load(req.session_id) if restoration and req.session_id else {}
        redactor = Redactor(existing)

        ins = await self.inspect_input(
            req.message, policy=policy, profile=req.context_profile,
            history=[m.model_dump() for m in req.history], provider_ctx=pctx, redactor=redactor,
        )
        input_stage = api.StageSummary(decision=ins.final_decision, risk=ins.risk.score,
                                       detections=list(ins.results.values()),
                                       reasons=ins.policy_decision.summary, redactions=ins.enforcement.redactions)
        stages: dict[str, dict[str, DetectionResult]] = {"input": ins.results}
        metadata = self._input_metadata(ins)
        security = api.ChatSecurity(decision=ins.final_decision, input=input_stage, risk=ins.risk,
                                    verification=ins.verification, sanitized_prompt=ins.enforcement.sanitized_text)

        async def finish(text: str, blocked: bool, *, resp: LLMResponse | None = None, out_decision: Decision | None = None,
                         status: int = 200, extra: list[str] | None = None) -> api.ChatResponse:
            latency = round((time.perf_counter() - start) * 1000, 2)
            await self.audit.record_event(
                request_id=request_id, event_type="chat", decision=security.decision.value,
                output_decision=out_decision.value if out_decision else None, stages=stages,
                risk_score=ins.risk.score, severity=ins.risk.severity, session_id=req.session_id,
                provider=provider.name, model=(resp.model if resp else req.model or provider.default_model),
                latency_ms=latency, raw_input=req.message, sanitized_preview=ins.enforcement.sanitized_text,
                policy_version=policy.version, client_id=client_id, metadata=metadata, extra_categories=extra,
            )
            await self.audit.record_metric(
                request_id=request_id, endpoint="chat", provider=provider.name,
                model=resp.model if resp else None, status_code=status, decision=security.decision.value,
                total_latency_ms=latency, detection_latency_ms=ins.latency_ms,
                llm_latency_ms=resp.latency_ms if resp else None,
                prompt_tokens=resp.prompt_tokens if resp else None,
                completion_tokens=resp.completion_tokens if resp else None, error=status >= 500,
            )
            return api.ChatResponse(
                request_id=request_id, text=text, blocked=blocked, provider=provider.name,
                model=resp.model if resp else None, security=security,
                usage=api.ChatUsage(prompt_tokens=resp.prompt_tokens if resp else None,
                                    completion_tokens=resp.completion_tokens if resp else None,
                                    llm_latency_ms=resp.latency_ms if resp else None),
                latency_ms=latency,
            )

        if not ins.enforcement.forward:
            return await finish(ins.enforcement.message or "Request blocked.", True)

        # --- untrusted context ------------------------------------------------
        included_chunks = []
        if req.context:
            ci = await self.context.inspect(req.context, policy.context,
                                            threshold=effective_threshold(policy, "context", req.context_profile),
                                            redact_pii=self._context_redacts_pii(policy, pctx), redactor=redactor)
            security.context = ci
            stages["context"] = {
                c.id: DetectionResult(detector="context", detected=c.flagged, score=c.risk, confidence=c.ml_score,
                                      reason="; ".join(c.reasons)[:400] or "no indicators", method=policy.context.mode)
                for c in ci.chunks
            }
            metadata["context_chunks"] = [{"id": c.id, "risk": c.risk, "action": c.action, "included": c.included}
                                          for c in ci.chunks]
            if ci.decision == Decision.BLOCK:
                security.decision = Decision.BLOCK
                return await finish("The request was blocked because retrieved context contained embedded instructions.",
                                    True, extra=["indirect_injection"])
            included_chunks = ci.included

        history = await self._sanitize_history(req.history, redactor, self._context_redacts_pii(policy, pctx), policy)
        bundle = SecurePromptBundle(system_policy=req.system_prompt or DEFAULT_SYSTEM_PROMPT,
                                    user_message=ins.enforcement.sanitized_text, untrusted_context=included_chunks,
                                    history=history)
        messages = bundle.render()
        max_tokens = min(req.max_tokens, policy.providers.max_output_tokens)

        # --- provider call (no silent fallback) --------------------------------
        resp: LLMResponse | None = None
        active = provider
        try:
            resp = await active.chat(messages, model=req.model, temperature=req.temperature, max_tokens=max_tokens,
                                     json_mode=req.response_format == "json")
        except ProviderError as exc:
            fb = self.router.fallback_for(active, policy.providers.allow_cloud_fallback)
            if fb is None:
                security.decision = ins.final_decision
                metadata["provider_error"] = exc.code
                await finish(f"LLM provider error: {exc.message}", False, status=exc.status)
                raise
            # Re-apply policy for the cloud provider before any data leaves the machine.
            fctx = ProviderContext(name=fb.name, is_local=fb.is_local)
            redecision = self.engine.evaluate(ins.results, ins.risk, policy, provider=fctx, profile=req.context_profile)
            re_enf = enforce(ins.normalized.text, ins.results, redecision, final_decision=redecision.decision_without_verify()
                             if redecision.decision == Decision.VERIFY else redecision.decision)
            metadata["fallback"] = {"from": active.name, "to": fb.name, "decision": re_enf.decision.value}
            security.fallback_used = True
            if not re_enf.forward:
                security.decision = re_enf.decision
                return await finish("Cloud fallback was blocked by policy.", True)
            bundle.user_message = re_enf.sanitized_text
            bundle.untrusted_context = []  # context was sanitized for the local provider; do not forward it to cloud
            bundle.history = await self._sanitize_history(req.history, Redactor(), True, policy)
            active = fb
            resp = await active.chat(bundle.render(), model=None, temperature=req.temperature, max_tokens=max_tokens,
                                     json_mode=req.response_format == "json")

        # --- output validation -------------------------------------------------
        evidence = req.evidence
        if evidence is None and policy.output.grounding_min_support > 0 and included_chunks:
            evidence = [c.sanitized_text or "" for c in included_chunks]
        ov: OutputValidation = await self.output_validator.validate(
            resp.text, policy, canary=bundle.canary, system_prompt=req.system_prompt,
            response_format=req.response_format, json_schema=req.json_schema, evidence=evidence,
        )
        stages["output"] = ov.results
        metadata["output_checks"] = [c.model_dump(mode="json") for c in ov.checks]
        security.output = api.StageSummary(decision=ov.decision, detections=list(ov.results.values()),
                                           reasons=[f"{c.check}: {c.action.value} ({c.detail})" for c in ov.failed_checks],
                                           redactions=ov.redactions)
        security.output_checks = ov.checks

        if ov.decision == Decision.BLOCK:
            security.decision = Decision.BLOCK
            return await finish(OUTPUT_WITHHELD, True, resp=resp, out_decision=ov.decision,
                                extra=[f"output_{c.check}" for c in ov.failed_checks if c.action == Decision.BLOCK])

        final_text = ov.sanitized_text
        if restoration:
            final_text, n = restore_placeholders(final_text, redactor.mapping())
            security.restored_placeholders = n
            if req.session_id:
                await self.vault.save(req.session_id, redactor.value_to_ph, policy.pii.restoration_ttl_seconds)

        redacted_any = bool(ins.enforcement.redactions or ov.redactions or ov.decision == Decision.REDACT
                            or (security.context and security.context.decision == Decision.REDACT))
        security.decision = Decision.REDACT if redacted_any else Decision.ALLOW
        return await finish(final_text, False, resp=resp, out_decision=ov.decision)
