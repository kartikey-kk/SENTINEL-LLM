# Development status

_Last updated: 2026-11-07_

## Completed modules

| Phase | Module | Status | Location |
|---|---|---|---|
| 1 | Repository structure, config, `.env.example` | done | `backend/sentinel/config.py`, `.env.example` |
| 2 | FastAPI app, Pydantic schemas, SQLAlchemy models, Alembic migration, provider abstraction, health | done | `backend/sentinel/{main,api,db,providers}`, `backend/alembic` |
| 3 | A Normalizer · B Prompt injection · C Jailbreak (multi-turn) · D PII (Presidio) · E Secrets · F Toxicity | done | `backend/sentinel/detection/` |
| 4 | G Risk scoring · H Policy engine + store (YAML, validation, versioning) · enforcement/redaction | done | `backend/sentinel/engine/` |
| 5 | I Provider router (Ollama, OpenAI-compatible) · secure chat proxy · J Output validator · K Context security · L Tool guard · escalate-only verifier · PII vault | done | `backend/sentinel/{providers,detection,security,engine/pipeline.py}` |
| 5 | Python SDK (sync + async), examples, tests | done | `sdk/` |
| 6 | React console: overview, inspector, analytics, event explorer, policies, models | done | `frontend/` |
| 7 | Unified dataset + leak-free splits, firewall/detector evaluation, latency benchmark, 3 experiments, sklearn baseline | done | `experiments/`, `datasets/processed/` |
| 8 | Dockerfiles, Compose (CPU/GPU), docs, acceptance script | done | `docker-compose*.yml`, `docs/`, `scripts/` |

## Test results

| Suite | Result | Command |
|---|---|---|
| Backend unit + API tests (fake providers, no ML) | 110 passed | `cd backend && .venv/Scripts/python -m pytest -m "not ml and not ollama"` |
| Backend ML tests (real classifiers + Presidio) | 12 passed | `pytest -m ml` |
| **Backend total** | **122 passed** | `pytest -m "not ollama"` |
| SDK tests | 5 passed, 1 skipped (live test needs `SENTINEL_SDK_LIVE_URL`) | `pytest sdk/tests` |
| Type checking | mypy: no issues in 48 files · `tsc --noEmit`: no errors | `mypy sentinel --ignore-missing-imports`, `npm run typecheck` |
| Alembic | upgrade + `alembic check` clean (SQLite); upgrade applied on PostgreSQL 16 in Docker | |
| Frontend build | Vite production build OK | `npm run build` |
| Dashboard | All 6 pages exercised in the browser against live data (dev server and Docker/nginx) | |

**Acceptance criteria (spec §16)**, run with `scripts/acceptance_test.py --expect-docker` against the Docker
Compose deployment (PostgreSQL + Redis + gateway + nginx console, Ollama on the host):

| # | Criterion | Result |
|---|---|---|
| 1 | Benign prompt passes and receives an LLM response | PASS |
| 2 | Direct prompt injection blocked (LLM not called) | PASS |
| 3 | Synthetic PII redacted before cloud transmission | PASS* |
| 4 | Synthetic API key detected, blocked, absent from the audit record | PASS |
| 5 | Sensitive model output redacted (PII) / blocked (credential) | PASS |
| 6 | Unauthorized simulated tool call rejected | PASS |
| 7 | Policy changed through the admin API (and an invalid change rejected) | PASS |
| 8 | Every security decision generates an audit event | PASS |
| 9 | Works with local Ollama (`qwen2.5:3b`) | PASS |
| 10 | Works with a configured cloud (OpenAI-compatible) API | PASS* |
| 11 | Evaluation scripts compute real metrics | PASS |
| 12 | Docker deployment starts successfully | PASS |

\* Tests 3 and 10 ran against the OpenAI-compatible provider pointed at Ollama's `/v1` endpoint and
registered as a non-local provider, because no real cloud API key was available. With the default
`.env` (cloud disabled) they report SKIP: 10 passed, 2 skipped. A run against a real cloud API is
still outstanding.

The evaluation results are in `docs/EVALUATION.md` and the generated tables in `docs/EVALUATION_RESULTS.md`.

## Known limitations

* **Classifier calibration.** The public classifiers are over-confident on some benign inputs. The default
  fusion (`ml_weight`) routes uncorroborated classifier hits to verification instead of blocking them.
  This raises latency for those requests and makes recall partly depend on the verifier model.
* **Jailbreak classifier quality.** `jackhhao/jailbreak-classifier` has a high false-positive rate on
  security questions, coding requests and config snippets. It is down-weighted (`ml_weight 0.6`); a better
  model can be swapped in through `SENTINEL_JAILBREAK_MODEL`, and pointing it at the injection model
  shares one instance.
* **Verifier.** The default judge (`qwen3:4b-instruct`) is a small local model, and the verifier only
  escalates. Prompt-injection attacks aimed at the judge itself can make it under-report, which is one
  reason a benign verdict can never authorize anything.
* **Rules author bias.** The rules and the synthetic attack families were written by the same author.
  External held-out sources (InjecAgent, AgentDojo, garak) are reported separately for that reason.
* **Contamination.** In-the-wild jailbreaks, DAN prompts and Dolly may overlap with the public
  classifiers' training data (`seen_risk`). Unseen-source metrics are reported alongside.
* **Evidence check is lexical.** The output "evidence overlap" is lexical support, not factual verification.
* **Cloud provider.** No real cloud API key was available during development. The OpenAI-compatible path
  was exercised against Ollama's `/v1` endpoint, registered as a non-local provider so cloud privacy rules
  apply. A real cloud run needs `SENTINEL_CLOUD_*` settings.
* **Multi-instance.** Policy updates are pushed to the instance that received them. Other replicas pick
  them up on restart (there is no pub/sub invalidation yet). Rate limits and tool counters are shared only when Redis is used.
* **Toxicity coverage.** Toxicity evaluation uses a small synthetic set (mild, slur-free harassment).
  It is not a substitute for a dedicated toxicity benchmark.
* **Tools are simulated.** No real side-effecting tools are executed by design.

## Next implementation steps

1. Fine-tune or replace the jailbreak classifier, and calibrate classifier probabilities (temperature
   scaling) on the validation split.
2. Policy-change notification across replicas (Redis pub/sub) and per-tenant policies.
3. Streaming chat responses with incremental output validation.
4. A larger, independently written benign set for false-positive measurement in specific domains.
5. Optional cloud verifier with cost budgets once a key is available (Experiment 2 support exists).
