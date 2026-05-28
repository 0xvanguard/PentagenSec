# syntax=docker/dockerfile:1.7
# =============================================================================
#  VANGUARD-X — Autonomous SecOps Multi-Agent Container
#  -----------------------------------------------------------------------------
#  Multi-stage build:
#    Stage 1 (builder)  -> compiles wheels, isolates build deps
#    Stage 2 (runtime)  -> minimal, non-root, async-Python ready
#
#  Hardening choices:
#    * Non-root UID/GID 1001 (rootless containers compatible)
#    * tini as PID 1 (proper signal forwarding + zombie reaping)
#    * No build-essential in the runtime layer
#    * PYTHONDONTWRITEBYTECODE / PYTHONUNBUFFERED for clean container logs
#    * Read-only-friendly layout (only /tmp and /home/secops/app/reports writable)
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1 — Builder
# -----------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore

WORKDIR /opt/build

# Build dependencies are kept in this stage only.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential \
        gcc \
        ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Upgrade pip toolchain first to leverage modern resolver.
RUN python -m pip install --upgrade pip setuptools wheel

# Install requirements into an isolated prefix that we will copy verbatim.
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/opt/venv -r requirements.txt


# -----------------------------------------------------------------------------
# Stage 2 — Runtime
# -----------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS runtime

LABEL org.opencontainers.image.title="vanguard-x-secops" \
      org.opencontainers.image.description="Autonomous multi-agent SecOps platform (AutoGen v0.4 + Ollama)" \
      org.opencontainers.image.authors="John Sebastian Camargo <@0xvanguard>" \
      org.opencontainers.image.source="https://github.com/0xvanguard/PentagenSec" \
      org.opencontainers.image.licenses="MIT" \
      project="VANGUARD-X" \
      component="secops-agents"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    PYTHONHASHSEED=random \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/opt/venv/lib/python3.12/site-packages \
    PATH=/opt/venv/bin:$PATH \
    OLLAMA_BASE_URL=http://ollama-service:11434/v1 \
    OLLAMA_MODEL=qwen2.5-coder:7b \
    OLLAMA_API_KEY=ollama-local-noop \
    LOG_LEVEL=INFO \
    MAX_AGENT_TURNS=20 \
    REQUEST_TIMEOUT_S=180

# Minimal runtime deps:
#   tini       -> PID 1 / signal forwarding
#   ca-certs   -> TLS for any outbound calls (CTI feeds, future enrichers)
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        tini \
        ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 1001 secops \
 && useradd  --system --uid 1001 --gid secops \
            --create-home --home-dir /home/secops \
            --shell /usr/sbin/nologin secops

# Copy the pre-built virtualenv from the builder stage.
COPY --from=builder /opt/venv /opt/venv

# Workdir owned by the non-root user; reports volume mounts here at runtime.
WORKDIR /home/secops/app
RUN mkdir -p /home/secops/app/reports \
 && chown -R secops:secops /home/secops

# Copy the only piece of application code (single-file orchestrator).
COPY --chown=secops:secops main.py /home/secops/app/main.py

USER secops:secops

# Lightweight liveness check — verifies the Python interpreter and AutoGen import path.
HEALTHCHECK --interval=60s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import autogen_agentchat, autogen_ext.models.openai" || exit 1

# tini handles SIGTERM correctly so asyncio cancellation propagates cleanly.
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "-u", "main.py"]
