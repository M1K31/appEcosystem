# syntax=docker/dockerfile:1
# Container image for the appEcosystem registry + event bus.
FROM python:3.12-slim AS base

# Avoid interactive prompts and keep Python output unbuffered for logs.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    ECOSYSTEM_ENV=production \
    ECOSYSTEM_REGISTRY_HOST=0.0.0.0 \
    ECOSYSTEM_LOG_FORMAT=json

WORKDIR /app

# Install dependencies first for better layer caching.
COPY pyproject.toml ./
COPY auth ./auth
COPY registry ./registry
COPY events ./events
COPY llm ./llm
COPY ecosystem_client ./ecosystem_client
COPY cli ./cli
COPY ecosystem.yaml ./

RUN pip install --upgrade pip && pip install -e .

# Run as a non-root user.
RUN useradd --create-home --uid 10001 ecosystem \
    && mkdir -p /app/data \
    && chown -R ecosystem:ecosystem /app
USER ecosystem

EXPOSE 8500

# Container healthcheck hits the registry's own health endpoint.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8500/health', timeout=3).status==200 else 1)"

# In containers the registry must bind 0.0.0.0; isolate it on a trusted network.
CMD ["python", "-m", "uvicorn", "registry.app:app", "--host", "0.0.0.0", "--port", "8500"]
