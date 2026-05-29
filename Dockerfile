# syntax=docker/dockerfile:1.7
# =============================================================================
#  VANGUARD-X · Blue Team SecOps Container
#  -----------------------------------------------------------------------------
#  Strictly defensive: ingests SIEM/EDR data we already own, never reaches
#  out to third-party networks (only the internal ollama-service and, after
#  human approval, our own Telegram/Discord channels).
#
#  Multi-stage:
#    Stage 1 (builder)  -> compiles wheels, isolates build deps
#    Stage 2 (runtime)  -> minimal, non-root, async-Python ready
#
#  Hardening:
#    * Non-root UID/GID 1001
#    * tini as PID 1 (signal forwarding for clean asyncio shutdown)
#    * No build-essential in the runtime image
#    * PYTHONDONTWRITEBYTECODE / PYTHONUNBUFFERED -> clean container logs
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

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential \
        gcc \
        ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN python -m pip install --upgrade pip setuptools wheel

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/opt/venv -r requirements.txt


# -----------------------------------------------------------------------------
# Stage 2 — Runtime
# -----------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS runtime

LABEL org.opencontainers.image.title="vanguard-x-blueteam" \
      org.opencontainers.image.description="Blue Team multi-agent SecOps platform — AutoGen v0.4 + Ollama + mandatory human approval gate" \
      org.opencontainers.image.authors="John Sebastian Camargo <@0xvanguard>" \
      org.opencontainers.image.source="https://github.com/0xvanguard/PentagenSec" \
      org.opencontainers.image.licenses="MIT" \
      project="VANGUARD-X" \
      component="blueteam-agents" \
      policy.scope="defensive-only" \
      policy.external-network="forbidden-without-written-authorization"

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
    MAX_AGENT_TURNS=18 \
    REQUEST_TIMEOUT_S=240 \
    HUMAN_APPROVAL_MODE=interactive \
    HUMAN_APPROVAL_TIMEOUT_S=600 \
    SIEM_EVENTS_PATH=/home/secops/app/sample_data/siem_events.json \
    REPORTS_DIR=/home/secops/app/reports

# Minimal runtime deps:
#   tini       -> PID 1 / signal forwarding
#   ca-certs   -> TLS for Telegram / Discord webhooks (post-approval only)
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        tini \
        ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 1001 secops \
 && useradd  --system --uid 1001 --gid secops \
            --create-home --home-dir /home/secops \
            --shell /usr/sbin/nologin secops

# Copy the prebuilt virtualenv from the builder stage.
COPY --from=builder /opt/venv /opt/venv

# Workdir owned by the non-root user; reports volume mounts here at runtime.
WORKDIR /home/secops/app
RUN mkdir -p /home/secops/app/reports /home/secops/app/sample_data \
 && chown -R secops:secops /home/secops

# Copy application code only (no secrets, no env files).
COPY --chown=secops:secops main.py            /home/secops/app/main.py
COPY --chown=secops:secops notifications.py   /home/secops/app/notifications.py
COPY --chown=secops:secops sample_data        /home/secops/app/sample_data

USER 1001:1001

# Defence-in-depth: the build itself fails immediately if a future edit
# accidentally puts the runtime back on root. The assertion runs as the
# user that will execute the ENTRYPOINT, so a positive result is proof
# that the running process is non-privileged.
RUN test "$(id -u)" = "1001" && test "$(id -g)" = "1001" \
 || (echo "FATAL: container would run as $(id) — expected uid=1001 gid=1001" \
     && exit 1)

# Liveness check — verifies the Python interpreter and AutoGen import path.
HEALTHCHECK --interval=60s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import autogen_agentchat, autogen_ext.models.openai" || exit 1

# tini forwards SIGTERM correctly so asyncio cancellation propagates cleanly.
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "-u", "main.py"]
