# sentinelllm (Python SDK)

Small client for the SentinelLLM gateway. Its only dependency is `httpx`.

```bash
pip install -e sdk/
```

```python
from sentinelllm import Sentinel

firewall = Sentinel(base_url="http://localhost:8000")          # api_key="..." if client auth is enabled
response = firewall.secure_chat(message="Explain machine learning", provider="ollama", model="qwen2.5:3b")
print(response.text)
print(response.security.decision)      # ALLOW | REDACT | HUMAN_REVIEW | BLOCK
```

| Method | Endpoint |
|---|---|
| `secure_chat(message, provider=None, model=None, **options)` | `POST /api/v1/chat` |
| `inspect_input(text, provider=, session_id=, context_profile=, history=, content_type=, verify=)` | `POST /api/v1/inspect/input` |
| `inspect_output(text, system_prompt=, canary=, response_format=, json_schema=, evidence=)` | `POST /api/v1/inspect/output` |
| `inspect_context(chunks, provider=, context_profile=)` (strings or dicts) | `POST /api/v1/inspect/context` |
| `inspect_tool(tool_name, arguments, session_id=, scope=, granted_permissions=, approval_token=, execute=)` | `POST /api/v1/inspect/tool` |
| `health()`, `models()` | `GET /api/v1/health`, `GET /api/v1/models` |

* Results are dicts with attribute access (`r.security.input.reasons`); `r.raw` gives the JSON.
* Non-2xx responses raise `SentinelError` with `status`, `code`, `message` and `request_id`.
* `Sentinel(..., raise_on_block=True)` makes `secure_chat` raise `BlockedError` instead of returning a blocked result.
* `AsyncSentinel` offers the same API with `await`.

Examples: `examples/quickstart.py`, `examples/rag_chat.py`.
Tests: `pytest sdk/tests` (set `SENTINEL_SDK_LIVE_URL=http://127.0.0.1:8000` to also run against a live gateway).
