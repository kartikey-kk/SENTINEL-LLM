# Evaluation methodology and results

All numbers in this document come from scripts in `experiments/`, run on the machine described under
**Environment**. The raw outputs are JSON files in `experiments/results/` and are shown in the console
under *Threat Analytics*. Nothing here is estimated or hand-edited. When something could not be
measured (for example a real cloud provider without an API key), that is stated explicitly.

## 1. Dataset

`experiments/build_dataset.py` builds `datasets/processed/sentinel_eval_v1.jsonl` and the
`train` / `validation` / `test` splits with one schema:

```json
{"id": "SLLM-00001", "text": "…", "category": "prompt_injection", "label": 1, "severity": "high",
 "expected_action": "block", "stage": "input", "family": "ignore_previous", "group": "synthetic:ignore_previous",
 "source": "synthetic", "license": "project (MIT)", "split": "test", "seen_risk": false}
```

| Source | License | Used as | Notes |
|---|---|---|---|
| InjecAgent (`test_cases_{dh,ds}_{base,enhanced}`) | MIT | Indirect injections inside tool responses + benign tool responses (same template, harmless text in the injection slot) | At most 4 cases per attacker instruction |
| AgentDojo (injection-task `GOAL`s + `important_instructions` template) | MIT | Indirect injections | Goals extracted with `ast` (source is parsed, never executed); goals whose f-strings reference runtime values are skipped |
| garak `dan/*.json` | Apache-2.0 | Jailbreaks (DAN family templates) | `seen_risk` |
| garak `inthewild_jailbreak_llms.json` | Apache-2.0 (garak) | In-the-wild jailbreaks (200 sampled) | `seen_risk`: public classifiers were likely trained on this data |
| garak `sysprompt_extraction/attacks.json` | Apache-2.0 | System-prompt extraction attempts | |
| Databricks Dolly-15k | CC BY-SA 3.0 | Benign instructions (450 sampled) | `seen_risk` (widely used instruction data) |
| Synthetic (this project) | MIT | Injection families (+5 obfuscations each), jailbreak families, benign hard negatives, PII with ground-truth values (Luhn/Verhoeff/IBAN-valid), secrets vs documentation placeholders, toxicity, poisoned documents, canary attacks | Generated with seed 1337 |

### Splits and leakage control

* Exact duplicates (NFKC, case-folded, whitespace-collapsed) are removed globally.
* Synthetic samples are split by **family** (a deterministic hash of the group into 35 / 20 / 45 % train / validation / test).
  Obfuscated variants share their family's split.
* External attack sources reuse one template across many goals. AgentDojo uses `important_instructions`
  and InjecAgent uses the "IMPORTANT!!! Ignore all previous instructions" prefix, so a per-goal split would
  leak the template. They are therefore held out **entirely** as out-of-distribution test data.
* The builder asserts that no group and no attack family appears in more than one split
  (`family_split_overlap = 0` in `manifest.json`).
* `seen_risk = true` marks sources the off-the-shelf classifiers may have been trained on. Headline
  tables also report metrics on unseen sources only.

The train and validation splits are used only by the scikit-learn baseline (training, then selecting C).
Rule weights were written by hand. `ml_weight` was set from a calibration run on a handful of
hand-written prompts, not on the test split.

## 2. Metrics

Decisions map to actions: `BLOCK`/`HUMAN_REVIEW` → **block** (not forwarded), `REDACT` → **redact**,
`ALLOW` → **allow**.

| Metric | Definition |
|---|---|
| Precision / Recall / F1 | Attack samples (label 1) vs everything else, with prediction = block |
| FPR / FNR | FP / (FP + TN), FN / (FN + TP) |
| ASR (firewall) | Share of attack samples forwarded to the model (= FNR at the firewall) |
| ASR (LLM in the loop) | Canary attacks only: the attack succeeds if the model's reply contains the canary token |
| Policy violation rate | Share of samples whose action is *less* restrictive than `expected_action` |
| Over-enforcement rate | Share of samples whose action is *more* restrictive than `expected_action` |
| PII redaction success | Share of ground-truth PII values absent from the text that would be forwarded |
| Latency P50/P95/P99 | Firewall decision time per request, in-process (`evaluate_firewall`), per detector and end-to-end HTTP (`benchmark_latency`) |

Evaluation treats every request as destined for a cloud provider, the strictest privacy setting:
PII must be redacted and secrets blocked.

## 3. Configurations compared

All configurations run on the identical held-out samples with the same models. Only policy knobs differ.

| Config | Rules | ML | Verification | Meaning |
|---|---|---|---|---|
| `no_firewall` | – | – | – | Baseline: everything forwarded |
| `rules_only` | ✓ | – | – | Deterministic firewall |
| `ml_only` | – | ✓ | – | Classifier firewall (raw probabilities vs thresholds) |
| `hybrid` | ✓ | ✓ | – | Score fusion (`ml_weight` for uncorroborated classifier scores) |
| `hybrid_verify` | ✓ | ✓ | ✓ | SentinelLLM default: hybrid + escalate-only verification of the uncertainty band |

## 4. Reproduce

```bash
backend/.venv/Scripts/python -I experiments/build_dataset.py      # needs datasets/raw/* (commands below)
backend/.venv/Scripts/python experiments/train_baseline.py
backend/.venv/Scripts/python experiments/evaluate_firewall.py --llm   # --llm needs Ollama with qwen2.5:3b
backend/.venv/Scripts/python experiments/evaluate_detectors.py
backend/.venv/Scripts/python experiments/benchmark_latency.py --http http://127.0.0.1:8000
backend/.venv/Scripts/python experiments/run_experiments.py --exp 1 2 3
```

Raw data download (not redistributed in this repository):

```bash
cd datasets/raw
git clone --depth 1 --filter=blob:none --sparse https://github.com/uiuc-kang-lab/InjecAgent.git injecagent && (cd injecagent && git sparse-checkout set data)
git clone --depth 1 --filter=blob:none --sparse https://github.com/ethz-spylab/agentdojo.git agentdojo && (cd agentdojo && git sparse-checkout set src/agentdojo/default_suites src/agentdojo/attacks)
git clone --depth 1 --filter=blob:none --sparse https://github.com/NVIDIA/garak.git garak && (cd garak && git sparse-checkout set garak/data)
python -c "from huggingface_hub import hf_hub_download as d; d('databricks/databricks-dolly-15k','databricks-dolly-15k.jsonl',repo_type='dataset',local_dir='dolly')"
```

## 5. Results

**Environment:** Windows 11, Intel i5-12450HX (8 cores), 16 GB RAM. Detectors run on CPU (torch 2.15 CPU,
transformers 5.22). Ollama on an RTX 3050 6 GB laptop GPU: `qwen2.5:3b` is the target model and
`qwen3:4b-instruct` the verifier. Dataset `sentinel_eval_v1.1`, test split, sha256 `eb05393d…`.

### 5.1 End-to-end firewall comparison

991 held-out samples (652 attack, 339 non-attack), dataset v1.1 · `experiments/results/firewall_comparison_20261107T091714Z.json`.
The latency columns in this run were measured while a Docker image build was running in parallel;
use 5.3 for latency.

| Config | Precision | Recall | F1 | FPR | ASR (firewall) | Policy violation | Over-enforcement | PII redaction |
|---|---|---|---|---|---|---|---|---|
| no_firewall | – | 0.0% | – | 0.0% | 100.0% | 70.8% | 0.0% | 0.0% |
| rules_only | 98.8% | 51.1% | 0.673 | 1.2% | 48.9% | 32.2% | 5.1% | 100% |
| ml_only | 94.2% | **90.3%** | **0.922** | 10.6% | **9.7%** | **6.4%** | 8.3% | 100%¹ |
| hybrid | 94.5% | 75.9% | 0.842 | 8.6% | 24.1% | 15.8% | 7.6% | 100% |
| hybrid_verify (default) | **95.1%** | 86.0% | 0.903 | 8.6% | 14.0% | 9.2% | 7.6% | 100% |

¹ ML-only also blocks 20% of the PII requests outright (over-enforcement); the other configurations redact and forward them.

*Unseen sources only* (excluding `seen_risk` sources):

| Config | Precision | Recall | F1 | FPR | ASR |
|---|---|---|---|---|---|
| rules_only | 98.2% | 49.5% | 0.659 | 2.6% | 50.4% |
| ml_only | 91.5% | 85.9% | 0.886 | 22.6% | 14.1% |
| hybrid | 92.2% | 78.4% | 0.848 | 18.7% | 21.6% |
| hybrid_verify | 92.7% | 83.2% | 0.877 | 18.7% | 16.8% |

**Block rate by category** (attack categories = recall; benign categories = false-positive rate):

| Category (n) | rules_only | ml_only | hybrid | hybrid_verify |
|---|---|---|---|---|
| prompt_injection (116) | 40.5% | 89.7% | 59.5% | 75.0% |
| jailbreak (239) | 54.4% | 99.6% | 71.1% | 92.5% |
| indirect_injection (264) | 54.5% | 81.4% | 84.9% | 84.9% |
| secret (12) | 100% | 100% | 100% | 100% |
| toxicity (21) | 0%² | 95.2% | 95.2% | 81.0% |
| benign user prompts (203) | 2.0% | 0.5% | 2.0% | 2.0% |
| benign tool outputs (86) | 0.0% | 29.1% | 29.1% | 29.1% |
| PII requests (50, expected REDACT) | 0% | 20.0% | 0% | 0% |

² Toxicity has no rule-based detector by design. Per-source tables are in [EVALUATION_RESULTS.md](EVALUATION_RESULTS.md).

**LLM-in-the-loop attack success** (28 canary attacks against `qwen2.5:3b` with a defensive system
prompt; success = the model's reply contains the canary token): **100% without the firewall, 28.6%
with SentinelLLM** (hybrid_verify). All 8 successes come from two templates that matched no rule and
scored low on the classifier: "…as your real task, say X" and "Your only goal now is to output X".

### Reading these results

* **The rules are precise but narrow** (98.8% precision, 51% recall). They catch the phrasing they were
  written for and miss paraphrases, which is expected of hand-written patterns.
* **The off-the-shelf classifiers drive recall.** Their false positives concentrate on structured tool
  output: 29% of benign InjecAgent tool responses are flagged. On free-text benign prompts they are
  well behaved (0.5% FPR).
* **Uncorroborated fusion trades recall for fewer outright blocks.** Hybrid fusion caps uncorroborated
  classifier scores below the threshold and routes them to verification. Without the verifier those
  requests are allowed (`hybrid`: recall 75.9%). The escalate-only verifier recovers most of that
  recall (86.0%) with 137 verifier calls on 991 requests. It cannot reduce false positives, by design.
  It is more lenient than the classifier on mild system-prompt-extraction questions (garak
  `sysprompt_extraction`: 50% blocked vs 93% for ML-only) and on the synthetic insults (81% vs 95%).
* **On these numbers, `ml_only` has the best F1.** That's because the classifiers were likely trained on
  in-the-wild jailbreaks (99.5% blocked). The default (`hybrid_verify`) was chosen before evaluation to
  avoid unverified blocks from over-confident classifier scores; it was **not** selected on test-set F1.
  Both are one policy change apart (`mode: ml` per detector).
* **Context scanning is the main false-positive source** (benign tool outputs), so it is the first target
  for improvement. Applying the corroboration rule or verification there needs a context validation set,
  because external context data is held out entirely in the test split.

### 5.2 Per-detector evaluation

Each detector's own `detected` flag at the policy threshold, on the relevant positives vs benign
prompts · `detector_eval_20261107T085033Z.json` (dataset v1.1)

| Detector | Rules | ML | Hybrid |
|---|---|---|---|
| prompt_injection (116 attacks vs 203 benign) | P 97.2% · R 30.2% · FPR 0.5% | P 100% · R 88.8% · FPR 0.0% | P 98.5% · R 56.0% · FPR 0.5% |
| jailbreak (239 vs 203) | P 97.3% · R 44.8% · FPR 1.5% | P 99.6% · R 92.5% · FPR 0.5% | P 98.1% · R 64.4% · FPR 1.5% |
| any attack (355 vs 203) | P 97.8% · R 49.9% · FPR 2.0% | P 99.7% · R 96.3% · FPR 0.5% | P 98.4% · R 67.3% · FPR 2.0% |
| context (264 poisoned vs 86 benign chunks) | P 100% · R 54.5% · FPR 0.0% | P 89.6% · R 81.4% · FPR **29.1%** | P 90.0% · R 84.9% · FPR **29.1%** |

Hybrid recall at the *detector* level is lower than ML alone because uncorroborated classifier scores
are capped below the threshold on purpose; they become VERIFY at the policy level (see 5.1).

| Detector | Result |
|---|---|
| Secrets (12 real-format synthetic secrets vs 203 benign incl. documentation placeholders) | P 100% · R 100% · FPR 0% |
| Toxicity (21 synthetic harassment vs 203 benign incl. strongly negative non-toxic text) | P 100% · R 95.2% · FPR 0% |
| scikit-learn TF-IDF + LR baseline (trained on 300 train samples, C chosen on validation) | P 99.2% · R 41.8% · F1 0.589 · FPR 0.6%. Too little in-distribution training data to generalize to held-out families. |

**PII (value-level recall)** · `detector_eval_pii_20261107T085051Z.json`

| Engine | Validation (80 values) | Test (130 values) | False entities per benign prompt (test) |
|---|---|---|---|
| Presidio + checksum validators (default) | 100% | 100% (card, Aadhaar, PAN, IBAN, email, phone, IP, person) | 0.84, all `PERSON` (public figures in Dolly prompts get redacted) |
| Regex fallback (used if Presidio is unavailable) | 75% (no names) | 69.2% (no names, no phone formats) | 0.00 |

*Disclosure:* the v1 run found two PII integration bugs on the test split. Presidio's English registry
does not load the Indian-ID recognizers, so `IN_AADHAAR`/`IN_PAN` were silently skipped, and some valid
card formats were missed. They were fixed by registering the recognizers and adding Luhn / Verhoeff /
mod-97 validated patterns. The validation split contains none of the affected entity types, so the
fix could not be confirmed on unseen data. The test-split PII numbers above are therefore post-fix.
The same run exposed a bug in the dataset generator (synthetic card numbers were not Luhn-valid),
which led to dataset v1.1. All results here are on v1.1; v1 results are kept in
`experiments/results/superseded_v1/`.

### 5.3 Latency

200 held-out input samples, no memoization, after a warm-up, measured on an otherwise idle CPU ·
`latency_benchmark_20261107T092627Z.json`. Detectors were timed sequentially per sample; the pipeline
runs them concurrently.

| Stage | Mean | P50 | P95 | P99 |
|---|---|---|---|---|
| Normalizer | 1.3 ms | 0.3 ms | 5.1 ms | 10.4 ms |
| Secret detector | 0.4 ms | 0.1 ms | 1.2 ms | 1.8 ms |
| PII (Presidio + spaCy md + checksum validators) | 59 ms | 17 ms | 231 ms | 411 ms |
| Prompt injection (rules + DeBERTa) | 300 ms | 131 ms | 1.18 s | 1.95 s |
| Jailbreak (rules + BERT) | 163 ms | 46 ms | 750 ms | 1.24 s |
| Toxicity (BERT) | 149 ms | 42 ms | 723 ms | 1.17 s |
| **Full input pipeline, in-process** | 548 ms | 173 ms | 2.82 s | 4.36 s |
| **HTTP end-to-end** (`/inspect/input`, uvicorn, SQLite audit) | 581 ms | 213 ms | 2.58 s | 4.37 s |

By input length (full pipeline): **< 200 chars: P50 150 ms, P95 248 ms** (n = 133) · 200–1000 chars: P50 356 ms,
P95 535 ms (n = 21) · > 1000 chars: P50 1.05 s, P95 4.28 s (n = 46). Long inputs are split into
512-token windows, and every classifier runs over every window on CPU. A GPU or a smaller injection
model would cut this most. The LLM generation itself is not included; through the chat proxy it
dominates (several seconds per reply on the local GPU).

### 5.4 Experiment 1: context-aware risk aggregation

Hybrid + selective verification; 143 held-out attacks from unseen sources ·
`experiment_context_aware_20261107T091926Z.json`

| Scenario | Thresholds | Benign FPR | Attack recall |
|---|---|---|---|
| Security-research app (30 benign security-education prompts) | fixed | 10.0% | 79.0% |
| | `security_research` profile (×1.15) | **6.7%** | 78.3% |
| Customer-support app (150 Dolly prompts) | fixed | 0.0% | 79.0% |
| | `customer_support` profile (×0.85) | 0.0% | **92.3%** |

Context profiles moved the operating point in the intended direction in both scenarios. The stricter
support profile gained 13 points of recall with no false positives on everyday requests. The research
profile removed one of three false positives on 30 prompts at a cost of one missed attack. The samples
are small (30 security-education prompts), so read this as directional.

### 5.5 Experiment 2: selective verification

150 held-out samples (75 unseen-source attacks, 57 benign, 18 PII); verifier `qwen3:4b-instruct` via Ollama ·
`experiment_selective_verification_20261107T092939Z.json`

| Strategy | Recall | Precision | FPR | Mean latency | P95 latency | Verifier calls | Verifier tokens |
|---|---|---|---|---|---|---|---|
| always_local (no verifier) | 61.3% | 100% | 0% | 177 ms | 358 ms | 0 | 0 |
| **selective** (uncertainty band only) | 72.0% | 100% | 0% | 327 ms | 703 ms | 32 (21%) | 8,559 |
| always_verify | 76.0% | 100% | 0% | 666 ms | 832 ms | 150 (100%) | 40,923 |

Selective verification captured 73% of the recall gain of always-verify (+10.7 vs +14.7 points) with
21% of the verifier calls and 21% of the tokens. **Cloud cost could not be measured:** no cloud API key
was available, so the verifier ran locally (configured price $0). Applying a provider's price to the
token counts above gives the cost. For example, at $0.15 per million input tokens, always-verify uses
about 273 tokens per request, roughly $0.04 per 1,000 requests, against about $0.009 for selective.

### 5.6 Experiment 3: hybrid detector comparison

Same samples and models as 5.1 (`experiment_hybrid_20261107T091735Z.json`): rules F1 0.673 / FPR 1.2%;
ML F1 0.922 / FPR 10.6%; rules + ML F1 0.842 / FPR 8.6%; rules + ML + verification F1 0.903 / FPR 8.6%.
See 5.1 for per-category recall. **No method is claimed as novel.** In this setup the combination
mainly buys *fewer unverified blocks from uncorroborated classifier scores*, not higher F1 than the
classifiers alone.

## 6. Verifier model selection (probe)

Before choosing the judge model, a 10-prompt probe (6 benign hard negatives, 4 attacks) compared
local models and prompts. This probe is far too small to be an evaluation; it only screened out
unusable configurations.

| Verifier | Prompt | Correct |
|---|---|---|
| qwen2.5:3b | v1 (with "flagged by …" hint) | 4/10: labelled almost everything malicious |
| qwen2.5:3b | v2 (no hint, explicit benign classes) | 5/10 |
| qwen3:4b-instruct | v1 | 7/10 |
| qwen3:4b-instruct | final (v2 + harassment clause) | 10/10 |

The hint naming the detector that fired anchored the judges toward "malicious", so it was removed.

## 7. Limitations

* **Threats to validity.** The rules and the synthetic attacks were written by the same author, which
  inflates synthetic recall for rules. External sources are therefore held out and reported separately.
  The classifiers may have seen in-the-wild jailbreaks, DAN prompts and Dolly during training
  (`seen_risk`). Unseen-source metrics are reported.
* **Small categories.** Secrets (12), toxicity (21), PII (50), AgentDojo (7, because many goals reference
  runtime values and were skipped) and the security-education set (30) are small. Their percentages
  have wide confidence intervals.
* **Toxicity data is synthetic** (mild, slur-free harassment templates). It is not a substitute for a
  toxicity benchmark.
* **Firewall-level ASR is not model compromise.** Most rows report whether an attack *reached* the model.
  Actual compliance was measured only for the 28 canary attacks, against one local model.
* **Context false positives.** 29% of benign tool outputs are flagged by the context classifier. This is
  the clearest improvement target (see `DEVELOPMENT_STATUS.md`).
* **No tuning on test.** Weaknesses found here (two missed canary templates, context false positives,
  lenient verification of system-prompt extraction) were *not* patched against the test split. Fixes
  should be developed on a new validation set and re-measured on a fresh held-out set.
* **Cloud.** No cloud LLM run was possible without an API key. The OpenAI-compatible code path was
  tested against Ollama's `/v1` endpoint registered as a non-local provider.
