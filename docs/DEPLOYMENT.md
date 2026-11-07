# Deployment

## Requirements

| Component | Minimum | Notes |
|---|---|---|
| CPU / RAM | 4 cores, 8 GB RAM (16 GB recommended) | The three classifiers plus Presidio use about 2.5 GB RAM on CPU |
| Disk | ~6 GB | About 2 GB of Hugging Face models, ~2 GB backend image, ~2-2.5 GB per Ollama model |
| Python | 3.11+ | Local (non-Docker) runs |
| Node | 20+ | Building the console |
| Docker | Docker Desktop / Engine with Compose v2 | Container deployment |
| Ollama | Any recent version | Local LLM; https://ollama.com |

GPU is **optional**. The detectors run on CPU by default. Ollama uses an NVIDIA GPU automatically when
it is available on the host.

## 1. Local development (no Docker)

```bash
python -m venv backend/.venv
backend/.venv/Scripts/python -m pip install torch --index-url https://download.pytorch.org/whl/cpu   # Linux/macOS: backend/.venv/bin/python
backend/.venv/Scripts/python -m pip install -r backend/requirements-dev.txt
backend/.venv/Scripts/python -m spacy download en_core_web_md
cp .env.example .env            # then set SENTINEL_ADMIN_API_KEY and SENTINEL_SECRET_KEY to random values
backend/.venv/Scripts/python scripts/download_models.py     # downloads + smoke-tests the classifiers (~2 GB)
```

Ollama:

```bash
ollama serve                    # if it is not already running as a service
ollama pull qwen2.5:3b          # chat model (default)
ollama pull qwen3:4b-instruct   # secondary verifier (see docs/EVALUATION.md for why)
```

Run:

```bash
cd backend && .venv/Scripts/python -m uvicorn sentinel.main:app --host 127.0.0.1 --port 8000
cd frontend && npm install && npm run dev        # console on http://127.0.0.1:5173 (proxies /api to :8000)
```

Development defaults use SQLite (`backend/data/sentinel.db`). If Redis is not reachable, an
in-process store is used for rate limits, tool counters and the PII vault. This is shown in
`/api/v1/health`, and it is single-instance only.

## 2. Docker Compose (one command)

```bash
cp .env.example .env     # set SENTINEL_ADMIN_API_KEY, SENTINEL_SECRET_KEY, POSTGRES_PASSWORD
backend/.venv/Scripts/python scripts/download_models.py   # optional: pre-populates ./models_cache (otherwise downloaded on first start)
docker compose up -d --build
```

| Service | URL | Notes |
|---|---|---|
| Console | http://127.0.0.1:8080 | nginx serves the built dashboard and proxies `/api` |
| API | http://127.0.0.1:8000 (`/docs`) | Runs `alembic upgrade head` on start |
| PostgreSQL | internal only | Volume `pgdata` |
| Redis | internal only | No persistence (rate limits, counters, vault TTLs) |

* Models are bind-mounted from `./models_cache`. After the first download, set `HF_HUB_OFFLINE=1` in
  `.env` so the gateway never contacts the Hugging Face Hub.
* Experiment results are mounted read-only from `./experiments/results` so the console can show them.
* Ollama on the host is reached at `http://host.docker.internal:11434`. This works on Docker Desktop;
  on Linux the compose file adds a `host-gateway` mapping, and Ollama must listen on an address the
  bridge can reach (`OLLAMA_HOST=0.0.0.0`).

### CPU configuration (default)

* Backend image: CPU PyTorch wheel (`TORCH_INDEX=https://download.pytorch.org/whl/cpu`), `SENTINEL_ML_DEVICE=cpu`.
* Ollama in a container, CPU only: `docker compose --profile ollama up -d`, then
  `docker compose exec ollama ollama pull qwen2.5:3b`, and set `SENTINEL_OLLAMA_URL_DOCKER=http://ollama:11434`.
  Expect several seconds per response for 3-4B models on CPU.

### GPU configuration

* **Ollama on the host GPU** is the simplest setup. Install Ollama natively; it uses CUDA/ROCm/Metal automatically.
* **Ollama in a container with an NVIDIA GPU.** This needs the NVIDIA Container Toolkit on Linux, or Docker Desktop with WSL2 GPU support on Windows:
  ```bash
  docker compose -f docker-compose.yml -f docker-compose.gpu.yml --profile ollama up -d
  ```
* **Classifiers on GPU (optional).** Build the backend with a CUDA wheel and enable GPU device access for the backend service:
  ```bash
  TORCH_INDEX=https://download.pytorch.org/whl/cu124 docker compose build backend
  ```
  Then set `SENTINEL_ML_DEVICE=cuda` in `.env` and add the same `deploy.resources.reservations.devices`
  block to the `backend` service. On a 6 GB laptop GPU, keep the classifiers on CPU and give the VRAM to Ollama.

### Slow networks inside Docker

Docker Desktop's VM network can be much slower than the host's. During development it ran at about 100 KB/s,
which made the ~250 MB dependency download time out. The backend Dockerfile accepts an optional
wheelhouse, so the wheels can be downloaded on the host instead:

```bash
cd backend
.venv/Scripts/python -m pip download -r requirements.txt -d wheelhouse --only-binary=:all: \
  --python-version 3.11 --implementation cp --platform manylinux_2_28_x86_64 --platform manylinux2014_x86_64 \
  --platform manylinux_2_17_x86_64 --platform manylinux_2_24_x86_64 --platform manylinux1_x86_64 --platform manylinux_2_5_x86_64 --platform any
.venv/Scripts/python -m pip download --no-deps -d wheelhouse \
  "en_core_web_md @ https://github.com/explosion/spacy-models/releases/download/en_core_web_md-3.8.0/en_core_web_md-3.8.0-py3-none-any.whl"
cd .. && docker compose build backend
```

The wheels are bind-mounted only during `pip install` and never become part of the image. A BuildKit pip
cache also keeps partially downloaded dependencies across retries.

## Cloud LLM provider

Any OpenAI-compatible chat completions API can be used (OpenAI, Azure gateways, OpenRouter, Together, Groq, vLLM…):

```ini
SENTINEL_CLOUD_ENABLED=true
SENTINEL_CLOUD_BASE_URL=https://api.openai.com/v1
SENTINEL_CLOUD_API_KEY=<your key>          # environment only; never stored in the database or shown in the UI
SENTINEL_CLOUD_DEFAULT_MODEL=gpt-4o-mini
SENTINEL_CLOUD_PRICE_INPUT_PER_MTOK=0.15   # optional, only for cost reporting in experiments
```

The provider is registered as `openai_compatible`. Cloud requests always receive PII-redacted text,
and secrets are always blocked when the policy flags `cloud_requires_pii_redaction` and
`cloud_block_secrets` are set (the default). There is no automatic local-to-cloud fallback unless
`SENTINEL_ALLOW_CLOUD_FALLBACK=true` **and** `providers.allow_cloud_fallback: true`.

## Production checklist

* Set `SENTINEL_ENV=production` (the compose file does this). A real `SENTINEL_SECRET_KEY` is then mandatory.
* Use long random admin and client keys, and set `SENTINEL_REQUIRE_CLIENT_AUTH=true` with `SENTINEL_CLIENT_API_KEYS`.
* Terminate TLS in front of the console and API.
* Keep `SENTINEL_AUDIT_STORE_RAW_PROMPTS=false` unless you have a legal basis to store prompts. Set `SENTINEL_AUDIT_RETENTION_DAYS`.
* Keep Redis required (`SENTINEL_REDIS_OPTIONAL=false`) when running more than one backend replica.
* Policy updates are persisted in the database and survive restarts. Use `scripts/reset_policy_overrides.py` to return to the YAML file.

## Verifying a deployment

```bash
backend/.venv/Scripts/python scripts/acceptance_test.py --url http://127.0.0.1:8000 --expect-docker
```
