# SentinelLLM architecture

SentinelLLM is a gateway that sits between applications, LLM providers, retrieved context and tools.
Every request flows through the same staged pipeline, and each stage is a separate component with a
narrow interface.

```
client ─▶ API gateway (auth, rate limit, size limit, request id)
            │
            ▼
       normalizer ──▶ detection views (NFKC, homoglyph fold, decoded base64/hex/url/tags…)
            │
            ▼
   ┌────────┴──────── parallel detectors (bounded concurrency, per-detector timeout) ───────┐
   │ prompt_injection   jailbreak (+multi-turn)   pii (Presidio)   secrets   toxicity       │
   └────────┬───────────────────────────────────────────────────────────────────────────────┘
            ▼
       risk scorer  R = Σ wᵢ·sᵢ  + critical overrides + context profile
            ▼
       policy engine ──▶ ALLOW / REDACT / VERIFY / HUMAN_REVIEW / BLOCK  (+ reasons)
            ▼
       escalate-only verifier (only for VERIFY; local LLM judge)
            ▼
       enforcement  (redaction with placeholders, forward / hold / block)
            ▼
       context security (untrusted RAG chunks → drop / sanitize / flag)  ─┐
            ▼                                                           │ SecurePromptBundle keeps
       provider router (Ollama | OpenAI-compatible; no silent fallback)  │ system policy, user text and
            ▼                                                           │ untrusted data separate
       output validator (PII, secrets, toxicity, canary leak, unsafe HTML, JSON schema, evidence overlap)
            ▼
       output enforcement ─▶ response        audit + metrics (sanitized) ◀── every stage
```

## Separation of responsibilities

| Concern | Module | May do | Must not do |
|---|---|---|---|
| Detection | `sentinel/detection/*` | Return `DetectionResult` (score, confidence, severity, evidence, spans) | Block, redact, call providers |
| Risk | `engine/risk_scorer.py` | Combine detector scores into a single explained risk | Decide actions |
| Policy | `engine/policy_engine.py` | Map results + risk + provider context to a decision with reasons | Transform text |
| Enforcement | `engine/enforcement.py` | Redact, decide forwarding, restore placeholders when authorized | Re-score |
| Audit | `audit/service.py` | Persist sanitized events, metrics, admin actions | Store raw prompts by default |
| Orchestration | `engine/pipeline.py` | Wire the stages, time them, guarantee an audit record | Contain detection logic |

## Detectors

| Detector | Method | Score semantics |
|---|---|---|
| Normalizer (Module A) | Unicode NFC/NFKC, control/bidi/tag-char removal, homoglyph and leet folding, bounded decoding of base64/hex/URL/unicode-escape/rot13, JSON string extraction with depth/size limits | Produces views and encoding signals; forwarding text keeps ZWJ/ZWNJ and meaning |
| Prompt injection (B) | 24 regex rules (override, extraction, delimiter, privilege, exfiltration, tool hijack, concealment) + `protectai/deberta-v3-base-prompt-injection-v2` | Rules give heuristic weights (noisy-OR), the classifier gives a probability; hybrid fusion below |
| Jailbreak (C) | 22 rules (DAN, developer mode, persona, restriction removal, dual response, known templates) + multi-turn indicators + `jackhhao/jailbreak-classifier` | Same fusion; role-play is only penalized when combined with restriction removal |
| PII (D) | Microsoft Presidio + spaCy `en_core_web_md`, custom entities from policy, regex fallback (Luhn, SSN, Aadhaar, PAN, IBAN, email, phone, IP) | Per-entity recognizer scores; risk = max(sensitivity × score) |
| Secrets (E) | 15 provider formats, credential assignments, natural-language passwords, entropy near credential keywords, placeholder suppression | Deterministic rule weights (never presented as probabilities) |
| Toxicity (F) | `unitary/toxic-bert` (Detoxify "original" weights), multi-label sigmoid | Probability; kept separate from injection |
| Context (K) | Injection + jailbreak + 7 indirect-injection rules (addressed-to-AI, conditional instructions, hidden HTML, policy tampering, config assignments) + injection classifier | Per-chunk risk; DROP / SANITIZE / FLAG |
| Output (J) | Presidio, secrets, toxicity, canary token + 8-gram shingle overlap, unsafe HTML/JS/exfil-image patterns, JSON/JSON-Schema, lexical evidence overlap | Check list → ALLOW / REDACT / BLOCK only |

### Hybrid fusion (and why)

`score = max(rule, p)` when a non-dampened rule (weight ≥ 0.5) corroborates the classifier, otherwise
`score = max(rule, p × ml_weight)`. The default `ml_weight` for injection is 0.79, which keeps an
uncorroborated classifier score just below the 0.80 threshold. Such findings fall into the
verification band and go to the escalate-only verifier instead of being blocked outright. This was
introduced after calibration showed the classifiers are over-confident on some benign inputs
(p = 0.998 on a plain PII sentence; 0.94 on "Write a SQL query…"). The effect is measured in
`docs/EVALUATION.md` (rules vs ML vs hybrid vs hybrid + verification).

`confidence` is only ever a model probability. Pure rule hits report `confidence: null` and a
`rule_weight` in metadata.

## Risk scoring (Module G)

```
R_weighted = (0.40·P + 0.25·J + 0.20·S + 0.15·T) / Σw        (weights from policy; profile overrides)
R          = max(R_weighted, sᵢ of every detected injection/jailbreak/secret finding,
                 critical_floor if any finding is CRITICAL)
```

PII and toxicity contribute only through the weighted sum because they have their own deterministic
REDACT and VERIFY rules. The result carries an explanation (each component's contribution and any
override reason) and is marked `incomplete` when a detector failed.

## Policy engine (Module H)

Decision precedence is BLOCK > HUMAN_REVIEW > VERIFY > REDACT > ALLOW. Policies are YAML
(`backend/policies/default.yaml`), validated by Pydantic models with invariants that cannot be
configured away:

* Secrets can only be BLOCKed or REDACTed. With a cloud provider and `cloud_block_secrets`, they are always BLOCKed.
* Injection, jailbreak, PII and secret checks fail closed (`on_error` ∈ {BLOCK, HUMAN_REVIEW}).
* VERIFY is not allowed as the action of a critical detector; the verifier is escalate-only.
* PII is forced to REDACT for non-local providers when `cloud_requires_pii_redaction` is set.
* Context-profile threshold multipliers are bounded to [0.8, 1.5].
* Tools are default-deny, and VERIFY is never a tool decision.

Updates go through `PUT /api/v1/policies/{section}`. The whole candidate policy is re-validated,
versioned, written to the `policies` table, audited in `audit_logs`, and swapped atomically. Requests
read an immutable snapshot. Stored overrides take precedence over the YAML file on restart
(`scripts/reset_policy_overrides.py` clears them).

## Verification

Requests whose final decision is VERIFY go to an LLM judge. That happens when a score falls in a
detector's `verify_band`, when aggregate risk is at or above `verify_threshold`, or when the toxicity
action is VERIFY. The judged text is wrapped as data, and the detector that flagged it is not
revealed, because that anchoring biased small judges. A "malicious" verdict at or above
`min_confidence_to_escalate` makes the decision BLOCK. A "benign" verdict leaves the deterministic
decision unchanged. If the verifier is unavailable, `on_unavailable` (default HUMAN_REVIEW) applies.
The verifier can never turn a BLOCK into an ALLOW.

## Context security (Module K)

Retrieved documents, web pages, tool outputs and API results enter as `ContextChunk` objects. The
context detector scores each chunk and returns verdicts. It has no reference to the policy store or
tool registry, so there is no code path by which retrieved text can change configuration. This is
enforced by tests in `tests/test_tools_context_output.py` and `tests/test_api.py`. Included chunks are
rendered by `SecurePromptBundle` inside `<untrusted_data>` delimiters, with breakout attempts
neutralized. A per-request canary token is placed in the system message so leakage can be detected
on output.

## Tool security (Module L)

`ToolGuard` checks the following, in order:

1. Allowlist: default deny.
2. Per-tool enable switch.
3. Caller scope.
4. Read/write permission.
5. Strict argument schema: unknown, missing, type, length, regex, enum and range.
6. Argument content: shell/SQL metacharacters, injection phrases, and credentials.
7. Per-session call counter in Redis.
8. Approval: an HMAC token bound to session, tool and exact canonical arguments, issued only through the admin endpoint.

Execution is limited to harmless simulated tools with timeouts, and the calculator uses a whitelisted
AST evaluator. Tool outputs are scanned as untrusted context.

## Providers (Module I)

`OllamaProvider` and `OpenAICompatibleProvider` implement one interface (`chat`, `list_models`, `health`)
with timeouts, bounded exponential-backoff retries for retryable errors, and safe error translation
(no upstream bodies or credentials in messages). The router never falls back from local to cloud
unless both `SENTINEL_ALLOW_CLOUD_FALLBACK=true` and the policy flag are set. Even then, the policy
engine is re-run with the cloud provider context, so PII redaction and secret blocking are
re-applied, and retrieved context is not forwarded to the cloud.

## Data and privacy

* `security_events` stores decisions, scores, categories, an HMAC fingerprint of the input, and an optional
  *redacted* preview truncated to 200 characters. Raw prompts are stored only if
  `SENTINEL_AUDIT_STORE_RAW_PROMPTS=true`; this is off by default.
* `detection_results` stores per-detector rows with sanitized evidence: rule ids, entity-type counts, and
  masked secret previews showing at most four characters.
* `model_providers.api_key_env` stores the *name* of an environment variable, never a key.
* Retention: rows older than `SENTINEL_AUDIT_RETENTION_DAYS` are purged every 6 hours.
* The PII restoration vault is Fernet-encrypted with a key derived from `SENTINEL_SECRET_KEY`, scoped
  per session, TTL-bound, and holds only PII (never secrets). Restoration happens only when the policy
  allows it and the caller asks for it, and only in the response returned to that caller.
* Audit writes are fail-closed by default: if the audit log is unavailable, the request is refused with 503.

## Startup

`create_app()` builds an `AppContext` once:

1. The database: `create_all` in development; `alembic upgrade head` in Docker.
2. The Redis store, falling back to an in-process store only when `SENTINEL_REDIS_OPTIONAL=true`.
3. The policy store: YAML plus database overrides.
4. All classifiers and Presidio, loaded exactly once and off the event loop.
5. Providers and the pipeline.

A missing model degrades only the detector that needs it, which reports `degraded` or `unavailable`.
It never fails open.
