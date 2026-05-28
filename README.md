# VANGUARD-X · Autonomous Multi-Agent SecOps Platform

> **Single-command, fully self-hosted, agentic security operations platform**
> built on **Microsoft AutoGen v0.4** (asynchronous, event-driven) and
> **Qwen2.5-Coder:7b** running locally on **Ollama**.
> Zero cloud dependencies. Zero API bills. Production-grade scaffolding.

---

## Table of Contents

1. [What it is](#1-what-it-is)
2. [Architecture](#2-architecture)
3. [Tech Stack](#3-tech-stack)
4. [Quick Start (one command)](#4-quick-start-one-command)
5. [Configuration](#5-configuration)
6. [Running a custom scenario](#6-running-a-custom-scenario)
7. [Project layout](#7-project-layout)
8. [Operational notes](#8-operational-notes)
9. [Troubleshooting](#9-troubleshooting)
10. [Hardening checklist](#10-hardening-checklist)
11. [Ethics & scope](#11-ethics--scope)

---

## 1. What it is

VANGUARD-X simulates a **5-person senior SecOps team** as autonomous agents
that reason about a target, generate structured intelligence, correlate it
into prioritised alerts, and emit an audit-grade report aligned to
**OWASP Top 10 2021** and **ISO/IEC 27001:2022**.

Every agent is implemented as an `AssistantAgent` from `autogen-agentchat`
(v0.4) wired into a deterministic `RoundRobinGroupChat`. Each agent is
constrained to emit JSON with a stable schema so that the next agent
ingests a clean, parseable payload — never raw tool dumps. The final agent
breaks the JSON discipline on purpose and emits a polished Markdown report
that gets persisted to disk.

---

## 2. Architecture

```
                +---------------------------------------------------+
                |                    USER  TASK                     |
                |   "Audit dev.company.local API leaking traces"   |
                +------------------------+--------------------------+
                                         |
                                         v
+---------------------------------------------------------------------------+
|                       RoundRobinGroupChat (AutoGen v0.4)                  |
|                                                                           |
|   1. ReconAgent       -> attack_surface JSON (subdomains, tech, vectors)  |
|   2. ScannerAgent     -> findings JSON      (CWE, CVSS, OWASP)            |
|   3. ThreatIntelAgent -> enrichments JSON   (CVE, MITRE ATT&CK)           |
|   4. SocAgent         -> alerts JSON        (priority, composite risk)    |
|   5. AuditorAgent     -> final Markdown     (OWASP + ISO 27001 + roadmap) |
|                                                                           |
|   Termination:  MaxMessageTermination(20)  |  TextMentionTermination("TERMINATE")  |
+----------------------------------+----------------------------------------+
                                   |
              OpenAIChatCompletionClient (autogen-ext[openai])
                                   |
                          base_url = /v1
                                   |
                                   v
                      +-------------------------+
                      |   ollama-service        |
                      |   qwen2.5-coder:7b      |
                      |   (local, in-network)   |
                      +-------------------------+
```

Two Docker Compose services on an isolated bridge network:

| Service          | Image                | Role                                                                |
| ---------------- | -------------------- | ------------------------------------------------------------------- |
| `ollama-service` | `ollama/ollama:latest` | Hosts the LLM, auto-pulls `qwen2.5-coder:7b` on first boot, exposes the OpenAI-compatible API at `/v1`. |
| `secops-agents`  | built from `Dockerfile` | Runs the 5-agent AutoGen v0.4 pipeline once Ollama reports healthy. |

`secops-agents` `depends_on.ollama-service.condition: service_healthy` —
the agents will not start until Ollama has actually pulled the model.

---

## 3. Tech Stack

| Layer            | Choice                                        | Why                                                         |
| ---------------- | --------------------------------------------- | ----------------------------------------------------------- |
| Language         | Python 3.12 (async, type hints)               | First-class `asyncio`, performance, modern typing           |
| Agent framework  | `autogen-agentchat` 0.4 (`autogen-ext[openai]`) | Async event-driven multi-agent runtime                      |
| LLM              | `qwen2.5-coder:7b` via Ollama                 | Strong code/JSON discipline, 100% local, no telemetry       |
| LLM client       | `OpenAIChatCompletionClient` -> Ollama `/v1`  | One canonical client; trivially swap to GPT/Anthropic later |
| Orchestration    | `RoundRobinGroupChat`                         | Deterministic kill-chain pipeline                           |
| Termination      | `MaxMessageTermination | TextMentionTermination` | Bounded runs + clean auditor stop                           |
| Containers       | Docker + Docker Compose v2                    | Single-command deploy, isolated network                     |
| Hardening        | non-root UID 1001, `cap_drop: ALL`, `no-new-privileges`, `tini` PID 1 | Least-privilege defaults                                    |

---

## 4. Quick Start (one command)

### Prerequisites

* Docker Engine 24+ and Docker Compose v2 (`docker compose` subcommand).
* ~10 GB free disk (the qwen2.5-coder:7b model is ~4.7 GB).
* ~8 GB free RAM during inference. A modern laptop CPU is sufficient;
  GPU is optional and Ollama will use it automatically when available.

### Run it

```bash
git clone https://github.com/0xvanguard/PentagenSec.git
cd PentagenSec
docker compose up --build
```

What happens, in order:

1. Compose builds the `secops-agents` image from the local `Dockerfile`.
2. `ollama-service` starts and pulls `qwen2.5-coder:7b` on first boot
   (this can take **several minutes** — only on first run; the model is
   cached in the named volume `vanguard-ollama-models`).
3. The healthcheck flips to `healthy` once the model is loaded.
4. `secops-agents` starts and dispatches the default audit task to the
   5-agent pipeline. You will see each agent's reasoning streamed to
   stdout as Markdown / JSON blocks.
5. The `AuditorAgent` emits the final report and writes the literal token
   `TERMINATE` — Compose stops `secops-agents` with exit code 0.

The Markdown audit report is persisted under `./reports/` on the host:

```
reports/vanguard-x-report-<UTC-timestamp>.md
```

### Tear down

```bash
docker compose down            # stop containers, keep model cache
docker compose down -v         # also remove the model cache (forces re-pull)
```

---

## 5. Configuration

All knobs are environment variables. Copy `.env.example` to `.env` and edit
in place — Compose will auto-load it.

| Variable             | Default                                   | Purpose                                                                  |
| -------------------- | ----------------------------------------- | ------------------------------------------------------------------------ |
| `OLLAMA_BASE_URL`    | `http://ollama-service:11434/v1`          | OpenAI-compatible Ollama endpoint                                        |
| `OLLAMA_MODEL`       | `qwen2.5-coder:7b`                        | Any Ollama tag works — try `qwen2.5-coder:14b` for stronger reasoning    |
| `OLLAMA_API_KEY`     | `ollama-local-noop`                       | Required by the OpenAI SDK contract; Ollama itself ignores it            |
| `MAX_AGENT_TURNS`    | `20`                                      | Hard ceiling on conversation length                                      |
| `REQUEST_TIMEOUT_S`  | `240`                                     | Per-LLM-call timeout (raise on slow CPUs)                                |
| `LOG_LEVEL`          | `INFO`                                    | One of DEBUG / INFO / WARNING / ERROR                                    |
| `SECOPS_TASK`        | _(unset — uses bundled default scenario)_ | Override the audit scenario without rebuilding the image                 |
| `REPORTS_DIR`        | `/home/secops/app/reports`                | Where the AuditorAgent's Markdown lands inside the container             |

---

## 6. Running a custom scenario

You have **two options**:

### Option A — environment variable (no rebuild)

Edit `.env` (or pass `-e` on the CLI):

```bash
SECOPS_TASK="Audit api.staging.acme.io which exposes /debug and /metrics without authentication, runs Spring Boot 2.7.0, and accepts arbitrary file uploads on /upload."
```

Then:

```bash
docker compose up
```

### Option B — direct one-shot run

```bash
docker compose run --rm \
  -e SECOPS_TASK="Audit the public S3 bucket s3://acme-public-assets that returns directory listings." \
  secops-agents
```

---

## 7. Project layout

```
PentagenSec/
├── Dockerfile              # multi-stage, non-root, tini PID 1
├── docker-compose.yml      # ollama-service + secops-agents + healthcheck
├── requirements.txt        # AutoGen v0.4 + httpx + pydantic, all pinned
├── main.py                 # 5-agent pipeline + orchestrator + persistence
├── .dockerignore           # keeps the build context lean
├── .env.example            # documented template for local overrides
├── reports/                # auditor reports land here (created at runtime)
└── README.md               # this file
```

---

## 8. Operational notes

* **First boot is slow.** The model pull (~4.7 GB) happens once and is cached
  in the `vanguard-ollama-models` named volume. Subsequent runs are instant.
* **Streaming UX.** Every agent message is printed live to the terminal via
  `autogen_agentchat.ui.Console`, so you can watch the kill-chain unfold.
* **No tools, no network targeting.** Agents reason on the **textual brief**
  you provide — no scanners run, no targets are touched. This is by design:
  VANGUARD-X is a pre-engagement reasoning layer that prepares decisions
  before any tool is launched. Tool execution belongs in a separate,
  scope-validated layer that is intentionally not part of this scaffold.
* **Graceful shutdown.** `tini` forwards `SIGTERM` to the Python process;
  `main.py` cancels all asyncio tasks and closes the model client cleanly.

---

## 9. Troubleshooting

| Symptom                                                      | Likely cause / fix                                                                                                            |
| ------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------- |
| `secops-agents` hangs on `dependency failed to start: container vanguard-ollama is unhealthy` | First-time model pull is slow. The healthcheck has 60 retries x 15 s = 15 minutes of grace. Watch progress with `docker compose logs -f ollama-service`. |
| `ConnectError: All connection attempts failed`               | Ollama is not yet listening. Confirm `docker compose ps` shows `ollama-service` as `healthy`. Restart with `docker compose restart secops-agents`. |
| Agents emit malformed JSON                                   | qwen2.5-coder:7b is small; raise `REQUEST_TIMEOUT_S` and consider switching to `qwen2.5-coder:14b` or `qwen2.5:14b-instruct`. |
| `model 'qwen2.5-coder:7b' not found`                         | The pull was interrupted. Run `docker compose down -v && docker compose up --build` to force a clean re-pull.                 |
| OOM / process killed during inference                        | The 7b model needs ~6-8 GB RAM. Close other workloads or pick a smaller tag (`qwen2.5-coder:3b`).                              |

---

## 10. Hardening checklist

Already applied in this scaffold:

* Non-root user (UID 1001) inside the container.
* `cap_drop: ALL` and `no-new-privileges:true` on `secops-agents`.
* `tini` as PID 1 for proper signal forwarding.
* Multi-stage build — no compilers in the runtime image.
* Pinned dependency ranges across `autogen-*`, `openai`, `httpx`, `pydantic`.
* Healthcheck in both services; `depends_on.condition: service_healthy`.
* Reports written only inside an explicit volume mount.

Recommended next steps for a regulated deployment:

* Move secrets (Telegram tokens, Discord webhooks, real CTI keys) to Docker
  secrets / HashiCorp Vault / AWS SM. Never bake them into images.
* Enable read-only root filesystem on `secops-agents` (`read_only: true`)
  with a tmpfs for `/tmp` — already 90% there in the compose file.
* Pin both images to a digest (`@sha256:...`) once you have certified them.
* Run scans through a dedicated egress proxy with allow-listed targets.

---

## 11. Ethics & scope

VANGUARD-X is built for **defenders**. It is intended to:

* run against assets you **own** or are **explicitly authorised** to test;
* operate inside agreed pentest / bug-bounty scope statements;
* respect responsible-disclosure timelines.

It is **not** intended to:

* facilitate unauthorised access to third-party systems;
* generate weaponised exploits or evasion tooling;
* replace a human consent / scope-validation step prior to any active scan.

> If you are unsure whether you have authorisation, you do not. Stop and ask.

---

_Made with care by [@0xvanguard](https://github.com/0xvanguard) — Bogotá, Colombia._
