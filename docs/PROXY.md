# Using SentinelLLM as drop-in middleware

SentinelLLM exposes an **OpenAI-compatible API** at `/v1`. Any app that talks to OpenAI, or to any
provider with an OpenAI-style API, can put SentinelLLM in the middle by changing one setting: the base URL.

```
Before:  your app ─────────────────────────────▶ OpenAI / Groq / Gemini / OpenRouter
After:   your app ──▶ SentinelLLM /v1 (checks) ─▶ OpenAI / Groq / Gemini / OpenRouter
                       base_url changes; api_key stays the app's own provider key
```

## Quick start

**Python (OpenAI SDK)**

```python
from openai import OpenAI

client = OpenAI(base_url="https://your-sentinel.example.com/v1",   # was https://api.openai.com/v1
                api_key="sk-...your own OpenAI key...")

resp = client.chat.completions.create(model="gpt-4o-mini",
                                      messages=[{"role": "user", "content": "Explain machine learning"}])
print(resp.choices[0].message.content)
```

**JavaScript / TypeScript**

```ts
import OpenAI from "openai";
const client = new OpenAI({ baseURL: "https://your-sentinel.example.com/v1", apiKey: process.env.OPENAI_API_KEY });
```

**No code change at all.** Many tools read the base URL from the environment:

```bash
OPENAI_BASE_URL=https://your-sentinel.example.com/v1
```

**curl**

```bash
curl https://your-sentinel.example.com/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" -H "Content-Type: application/json" \
  -d '{"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Hello"}]}'
```

A runnable example is in `sdk/examples/openai_dropin.py`. It works against local Ollama with no key.

## Choosing the provider

| Header / model | Goes to |
|---|---|
| (default) | The default upstream (`SENTINEL_PROXY_DEFAULT_UPSTREAM`, `openai` out of the box) |
| `X-Sentinel-Upstream: groq` | Groq (`https://api.groq.com/openai/v1`) |
| `X-Sentinel-Upstream: openrouter` | OpenRouter |
| `X-Sentinel-Upstream: gemini` | Google Gemini's OpenAI-compatible endpoint |
| `model: "ollama/qwen2.5:3b"` | The local Ollama server (no provider key needed) |

Upstreams are a **named allowlist** (`SENTINEL_PROXY_UPSTREAMS`). Callers can only pick a name, never a
URL, so the proxy can't be abused to reach other addresses.

## Keys

| Header | Meaning |
|---|---|
| `Authorization: Bearer <provider key>` | The caller's own provider key ("bring your own key"). It is forwarded to the provider and is never stored or logged; the audit log only keeps an HMAC-based client id. |
| `X-Sentinel-Key: <SentinelLLM key>` | Identifies the caller. Required when `SENTINEL_REQUIRE_CLIENT_AUTH=true`; issue one per customer in `SENTINEL_CLIENT_API_KEYS`. |
| `Authorization: Bearer <SentinelLLM key>` | No provider key: SentinelLLM uses **your** configured cloud key (`SENTINEL_CLOUD_*`). This works only with a valid SentinelLLM key, so nobody can spend your credits anonymously. |

## What happens to each request

1. **Latest user message:** the full input check (injection, jailbreak, PII, secrets, toxicity, risk, policy).
   If it's blocked, the provider is never called.
2. **Earlier user and assistant turns:** personal data and secrets are redacted.
3. **Tool-role messages** (tool and RAG results in agent loops) are treated as untrusted content. Ones with
   hidden instructions are replaced by `[SentinelLLM removed this tool output: …]`; the rest are redacted.
4. **System and developer messages** are your app's own instructions and are forwarded unchanged.
5. **The answer** is checked for leaked personal data (redacted), leaked keys, system-prompt leaks, unsafe
   HTML and invalid JSON (when `response_format` asks for JSON). Tool calls whose arguments contain a
   credential are withheld.
6. Every call becomes a `proxy` event in the audit log and the dashboard.

When the destination is a cloud provider, personal data is always redacted and secrets are always blocked
(`providers.cloud_requires_pii_redaction`, `providers.cloud_block_secrets`).

## Blocked requests

`SENTINEL_PROXY_BLOCK_MODE` controls what the app receives:

- `message` (default): a normal completion whose content says the request was blocked, with
  `finish_reason: "content_filter"`. Apps keep working.
- `error`: HTTP 400 in OpenAI's error format (`error.code = "sentinel_blocked"`), so SDKs raise an exception.

Every response carries a `sentinel` field (`decision`, `request_id`, reasons) and an `X-Sentinel-Decision`
header. OpenAI SDKs ignore the extra field; in Python it is available as `resp.model_extra["sentinel"]`.

## Limits

- **Text only.** Image and audio content parts are refused with a 400 error, because they can't be
  inspected; forwarding them unchecked would bypass the firewall.
- **Streaming is buffered.** With `stream: true` the answer is generated and validated completely, then
  streamed. The first token arrives later, but output checks are never skipped.
- **Only the chat completions API** (`/v1/chat/completions`, `/v1/models`) is supported. Embeddings,
  images, audio and the Responses API are not proxied.
- **`max_tokens` is capped** at `providers.max_output_tokens` from the policy.
- **Long inputs.** Each tool output is inspected up to `context.max_chunk_chars` (it's truncated beyond
  that), and the user message is limited to `SENTINEL_MAX_INPUT_CHARS`.
- **All callers share one policy** and one audit log. Per-customer policies and separate dashboards are not built yet.
