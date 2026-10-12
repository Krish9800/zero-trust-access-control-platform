# Build stage
FROM python:3.12-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src/ src/

RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --upgrade pip && \
    /opt/venv/bin/pip install .

# Final Rootless Runtime Stage
FROM python:3.12-slim AS runtime

# Security hardening: Non-root user with explicit UID/GID 10001
RUN groupadd -g 10001 ztac && \
    useradd -u 10001 -g ztac -m -s /bin/bash ztac

WORKDIR /app

COPY --from=builder --chown=ztac:ztac /opt/venv /opt/venv
COPY --chown=ztac:ztac src/ /app/src/

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ZTAC_DB_PATH="/app/data/zero_trust.db"

# Create persistence data directory with strict non-root ownership
RUN mkdir -p /app/data && chown -R ztac:ztac /app/data

USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')" || exit 1

ENTRYPOINT ["uvicorn", "zero_trust.api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
