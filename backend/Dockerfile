# syntax=docker/dockerfile:1
# SentinelLLM backend (FastAPI + detectors). CPU PyTorch by default; see docs/DEPLOYMENT.md for GPU.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_DEFAULT_TIMEOUT=120 \
    PIP_RETRIES=10 \
    HF_HOME=/models

WORKDIR /app

# Each dependency group is its own layer; the pip cache mount keeps downloaded wheels across
# (re)builds, so a dropped connection does not restart the download from scratch.
# PyTorch comes from the CPU wheel index unless overridden (e.g. --build-arg TORCH_INDEX=https://download.pytorch.org/whl/cu124)
ARG TORCH_INDEX=https://download.pytorch.org/whl/cpu
RUN --mount=type=cache,target=/root/.cache/pip pip install --index-url ${TORCH_INDEX} torch

COPY requirements.txt .
# Optional offline wheelhouse (see docs/DEPLOYMENT.md, "Slow networks"): wheels placed in backend/wheelhouse/
# are used first and anything missing is downloaded. The bind mount keeps them out of the image layers.
RUN --mount=type=cache,target=/root/.cache/pip --mount=type=bind,source=wheelhouse,target=/wheels \
    pip install --find-links /wheels -r requirements.txt
RUN --mount=type=cache,target=/root/.cache/pip --mount=type=bind,source=wheelhouse,target=/wheels \
    pip install --find-links /wheels en_core_web_md \
 || python -m spacy download en_core_web_md

COPY alembic.ini ./
COPY alembic ./alembic
COPY policies ./policies
COPY sentinel ./sentinel
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN sed -i 's/\r$//' /usr/local/bin/docker-entrypoint.sh \
 && chmod +x /usr/local/bin/docker-entrypoint.sh \
 && useradd --create-home --uid 10001 sentinel \
 && mkdir -p /app/data /models \
 && chown -R sentinel:sentinel /app /models

USER sentinel
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=120s --retries=3 \
  CMD python -c "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=4).status == 200 else 1)"

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["uvicorn", "sentinel.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
