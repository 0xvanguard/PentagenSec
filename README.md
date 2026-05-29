# VANGUARD-X · Blue Team Multi-Agent SecOps Platform

> **Strictly defensive.** Multi-agent pipeline that ingests SIEM/EDR data
> **we already own**, correlates it, prioritises alerts, produces an
> ISO 27001 / NIST CSF / OWASP-aligned report, and **gates every external
> side-effect behind a mandatory human approval**.
>
> Built on **Microsoft AutoGen v0.4** (asynchronous, event-driven) with
> **Qwen2.5-Coder:7b** running locally on **Ollama**. Single-command deploy.

---

## Hard policy (codified in the platform, not bypassable)

1. **Zero active scanning.** No agent ever runs Nmap, Nuclei, SQLMap, or
   any active probe. Agents reason exclusively over data already collected
   by our SIEM/EDR.
2. **Zero unauthorised external network calls.** The container is
   permitted to talk to two destinations only:
   * the internal `ollama-service` (LLM inference, internal Docker net);
   * Telegram / Discord — **and only after a human operator types
     `approve` on the gate**.
3. **`HumanApprovalAgent` is a mandatory gate.** It is implemented as an
   AutoGen v0.4 `UserProxyAgent` with a fail-closed `input_func`. Timeouts,
   empty input, malformed responses, REJECT decisions — all of them halt
   the pipeline before any side-effect.
4. **No third-party network targeting without written authorisation.**
   This is the operator's policy contract; the platform refuses to ship
   a feature that violates it.

---

## Table of Contents

1. [Architecture](#1-architecture)
2. [Tech Stack](#2-tech-stack)
3. [Quick Start](#3-quick-start)
4. [The Human Approval Gate](#4-the-human-approval-gate)
5. [Notifications (post-approval only)](#5-notifications-post-approval-only)
6. [Configuration](#6-configuration)
7. [Custom SIEM batch](#7-custom-siem-batch)
8. [Project layout](#8-project-layout)
9. [Operational notes](#9-operational-notes)
10. [Troubleshooting](#10-troubleshooting)
11. [Hardening checklist](#11-hardening-checklist)

---

## 1. Architecture

```
                +-------------------------------------------------+
                |    SIEM / EDR batch (JSON, already in our       |
                |    possession — read-only volume mount)         |
                +-------------------------+-----------------------+
                                          |
                                          v
+--------------------------------------------------------------------------+
|                  RoundRobinGroupChat (AutoGen v0.4)                      |
|                                                                          |
|  1. LogIngestAgent      -> normalised events JSON                        |
|  2. EnrichmentAgent     -> + asset/identity context, MITRE techniques    |
|  3. CorrelationAgent    -> timeline + multi-event attack chains          |
|  4. SeverityAgent       -> composite risk + P0..P4 + fatigue triage      |
|  5. ComplianceAgent     -> Markdown report (ISO 27001 / NIST / OWASP)    |
|                                                                          |
|  6. HumanApprovalAgent  -> MANDATORY GATE  (UserProxyAgent, fail-closed) |
|                              |                                           |
|              +---------------+---------------+                           |
|              |                               |                           |
|       APPROVE token                   REJECT / timeout                   |
|              |                               |                           |
|              v                               v                           |
|       NotificationDispatcher          halt; report only persisted        |
|       (Telegram + Discord,            to ./reports/                      |
|        each chunked, retried)                                            |
+--------------------------------------------------------------------------+

Termination conditions (combined with v0.4's `|` operator):
  * MaxMessageTermination(18)                       — safety net
  * TextMentionTermination(__VANGUARD_APPROVE__)    — operator approved
  * TextMentionTermination(__VANGUARD_REJECT__)     — fail-closed exit
```

Two Docker Compose services on an isolated bridge network:

| Service             | Image                  | Role                                                              |
| ------------------- | ---------------------- | ----------------------------------------------------------------- |
| `ollama-service`    | `ollama/ollama:latest` | Auto-pulls `qwen2.5-coder:7b` once; healthcheck flips green only when the model is loaded. |
| `blueteam-agents`   | built from `Dockerfile`| Runs the 5 defensive agents + `HumanApprovalAgent`. `depends_on.condition: service_healthy`. |

---

## 2. Tech Stack

| Layer            | Choice                                      | Why                                                  |
| ---------------- | ------------------------------------------- | ---------------------------------------------------- |
| Language         | Python 3.12 (async, type hints)             | Modern asyncio, deterministic typing                 |
| Multi-agent      | `autogen-agentchat` 0.4 (`autogen-ext[openai]`) | Async event-driven HITL via `UserProxyAgent`         |
| LLM              | `qwen2.5-coder:7b` via Ollama               | Strong JSON discipline, 100% local, no telemetry     |
| LLM client       | `OpenAIChatCompletionClient` -> Ollama `/v1` | One canonical client; trivially swappable            |
| Orchestration    | `RoundRobinGroupChat`                       | Deterministic ingest → ... → gate sequence           |
| HITL             | `UserProxyAgent(input_func=async_func)`     | Canonical v0.4 human-in-the-loop pattern             |
| Notifications    | Custom async Telegram + Discord clients     | Minimal deps, chunking + retry + fail-closed         |
| Containers       | Docker + Docker Compose v2                  | Single-command deploy, isolated network              |
| Hardening        | non-root UID 1001, `cap_drop: ALL`, `no-new-privileges`, tini PID 1, read-only sample data | Least-privilege defaults |

---

## 3. Quick Start

### Prerequisites

* Docker Engine 24+ and Docker Compose v2 (`docker compose` subcommand).
* ~10 GB free disk (qwen2.5-coder:7b is ~4.7 GB).
* ~8 GB free RAM during inference. GPU optional — Ollama auto-detects.
* A **terminal** attached (the `HumanApprovalAgent` reads operator input
  from stdin in interactive mode).

### Run it

```bash
git clone https://github.com/0xvanguard/PentagenSec.git
cd PentagenSec
cp .env.example .env       # edit if you want notifications
docker compose up --build
```

What happens, in order:

1. Compose builds `blueteam-agents` from the local `Dockerfile`.
2. `ollama-service` starts and pulls `qwen2.5-coder:7b` on first boot
   (one-time, several minutes; cached in `vanguard-ollama-models`).
3. The healthcheck flips to `healthy` once the model is loaded.
4. `blueteam-agents` reads `sample_data/siem_events.json` (read-only mount)
   and dispatches the batch to the round-robin team.
5. Each agent's reasoning is streamed live to stdout.
6. `ComplianceAgent` emits the Markdown report and signs off with
   `AWAITING_HUMAN_APPROVAL`.
7. `HumanApprovalAgent` prints the report context and **waits for your
   decision on stdin**:

   ```
   ==============================================================================
   HUMAN APPROVAL REQUIRED — VANGUARD-X Blue Team
   ==============================================================================
   ...summary...
   ==============================================================================
   Reply with `approve <reason>` to dispatch notifications,
   or `reject <reason>` to halt. Empty / unknown / timeout -> REJECT.
   ==============================================================================
   ```
8. Type `approve looks good` (or `reject false-positive`) and press Enter.
9. On APPROVE, configured notifiers fire concurrently. On REJECT, the
   pipeline halts after persisting the report.

The Markdown report is **always** written to `./reports/` on the host:

```
reports/vanguard-x-blueteam-report-<UTC-timestamp>.md
```

### Tear down

```bash
docker compose down            # stop containers, keep model cache
docker compose down -v         # also remove the model cache
```

---

## 4. The Human Approval Gate

The gate is the most important component of this platform. It is enforced
in **three independent layers**:

| Layer | Mechanism | What it guarantees |
| ----- | --------- | ------------------ |
| **L1 — Topology** | `HumanApprovalAgent` is the **last participant** in `RoundRobinGroupChat`. The team cannot finish without it. | No analysis path exists that bypasses the gate. |
| **L2 — Termination** | The team only stops on `__VANGUARD_APPROVE_NOTIFICATION__` or `__VANGUARD_REJECT_NOTIFICATION__` (or `MaxMessageTermination` as a safety net). | The orchestrator has a parseable, unambiguous decision token. |
| **L3 — Dispatch policy** | `main.py` only invokes the `NotificationDispatcher` when `parse_outcome(...)` returns `decision == "approved"`. Any other outcome (rejected, unknown, parse error) is logged and the program exits. | The notifier code path is unreachable without a human APPROVE. |

### Modes

```bash
HUMAN_APPROVAL_MODE=interactive    # default — prompts on stdin
HUMAN_APPROVAL_MODE=auto_reject    # CI / smoke tests — always rejects
```

There is intentionally **no `auto_approve` mode**. If you need automation
you must extend the `input_func` deliberately (e.g. read from a file the
on-call analyst writes via a ticketing system) — that is a conscious
design decision, not a flag flip.

### Operator UX

Reply on stdin with one of:

* `approve <free-text justification>` → dispatches notifications.
* `reject <free-text justification>` → halts.
* anything else / empty / timeout → fail-closed REJECT.

The decision and justification are logged at INFO level for audit.

---

## 5. Notifications (post-approval only)

When and only when the operator approves, the report is fanned out
concurrently to every configured channel.

| Channel  | Configuration                                 | Format                               |
| -------- | --------------------------------------------- | ------------------------------------ |
| Telegram | `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`      | Markdown, chunked at 4 096 chars     |
| Discord  | `DISCORD_WEBHOOK_URL`                         | Markdown, chunked at 2 000 chars     |

If neither is configured the dispatch is skipped silently and the report
remains on disk.

The clients (`notifications.py`):

* Use `httpx.AsyncClient` with a 15 s timeout per request.
* Retry up to 3 times with exponential backoff (1.5 s, 3 s, 6 s) — except
  on hard 4xx (auth, bad request) which bail immediately.
* Never raise — they return a structured `DispatchResult` that the
  orchestrator logs and feeds into the exit code.

---

## 6. Configuration

All knobs are environment variables. Copy `.env.example` to `.env`.

| Variable                   | Default                                                      | Purpose                                                            |
| -------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------------ |
| `OLLAMA_BASE_URL`          | `http://ollama-service:11434/v1`                             | Internal Ollama endpoint                                           |
| `OLLAMA_MODEL`             | `qwen2.5-coder:7b`                                           | Any Ollama tag; e.g. `qwen2.5-coder:14b` for stronger reasoning    |
| `OLLAMA_API_KEY`           | `ollama-local-noop`                                          | Required by the OpenAI SDK contract; Ollama itself ignores it      |
| `MAX_AGENT_TURNS`          | `18`                                                         | Hard ceiling on conversation length                                |
| `REQUEST_TIMEOUT_S`        | `240`                                                        | Per-LLM-call timeout                                               |
| `LOG_LEVEL`                | `INFO`                                                       | DEBUG / INFO / WARNING / ERROR                                     |
| `SIEM_EVENTS_PATH`         | `/home/secops/app/sample_data/siem_events.json`              | The pre-collected SIEM/EDR batch                                   |
| `HUMAN_APPROVAL_MODE`      | `interactive`                                                | `interactive` or `auto_reject`. **No `auto_approve`.**             |
| `HUMAN_APPROVAL_TIMEOUT_S` | `600`                                                        | Operator response timeout (0 = wait forever)                       |
| `TELEGRAM_BOT_TOKEN`       | _empty_                                                      | Disables Telegram if empty                                         |
| `TELEGRAM_CHAT_ID`         | _empty_                                                      | Disables Telegram if empty                                         |
| `DISCORD_WEBHOOK_URL`      | _empty_                                                      | Disables Discord if empty                                          |
| `SECOPS_TASK`              | _empty_ (auto-built from batch)                              | Override the prompt without rebuilding                             |

---

## 7. Custom SIEM batch

To feed your own events:

1. Drop a JSON file under `./sample_data/` with the same shape as
   `sample_data/siem_events.json` — see below.
2. Either name it `siem_events.json` (it will be picked up automatically)
   or set `SIEM_EVENTS_PATH` to the new path.

Minimum schema:

```json
{
  "batch_id": "BATCH-...",
  "generated_at": "2026-05-29T08:14:32Z",
  "data_provenance": "owned-by-tenant; no third-party traffic captured",
  "events": [
    {
      "event_id": "EVT-0001",
      "timestamp": "2026-05-29T07:42:11Z",
      "source": "<wazuh|sysmon|suricata|crowdstrike|o365|...>",
      "severity": "high",
      "rule_description": "...",
      "host": {"hostname": "...", "ip": "..."},
      "user": {"upn": "..."},
      "data": {"...": "..."},
      "asset_context": {
        "asset_criticality": "low|medium|high|critical",
        "exposed_to_internet": false,
        "owner_team": "..."
      }
    }
  ]
}
```

The bundled sample contains 7 realistic Blue Team events spanning brute
force, encoded PowerShell, suspected C2 beaconing, impossible-travel
sign-in, living-off-the-land binaries, rootkit-fingerprint detection and
bulk file download — all signals from systems we own.

---

## 8. Project layout

```
PentagenSec/
├── Dockerfile                  # multi-stage, non-root, tini PID 1
├── docker-compose.yml          # ollama-service + blueteam-agents
├── requirements.txt            # AutoGen 0.4 + httpx + pydantic
├── main.py                     # 5 Blue Team agents + HumanApprovalAgent + dispatch
├── notifications.py            # async Telegram + Discord clients (post-approval)
├── sample_data/
│   └── siem_events.json        # realistic owned-data batch
├── reports/                    # ComplianceAgent reports (created at runtime)
├── .dockerignore
├── .env.example                # documented template
└── README.md                   # this file
```

---

## 9. Operational notes

* **First boot is slow.** The model pull (~4.7 GB) happens once and is
  cached in the `vanguard-ollama-models` named volume.
* **`tty: true` in compose is required.** Without an attached TTY the
  `HumanApprovalAgent` cannot read stdin, and the gate fail-closes.
  In CI/CD pipelines use `HUMAN_APPROVAL_MODE=auto_reject`.
* **Reports always persist.** Even on REJECT, the ComplianceAgent's
  Markdown is written to `./reports/`. Useful for post-mortem review.
* **The notifier dispatch is concurrent and independent.** A failed
  Telegram post does not block Discord, and vice versa.
* **Graceful shutdown.** SIGTERM / SIGINT cancel all asyncio tasks, the
  Ollama client closes its connection pool, and the process exits 130.

---

## 10. Troubleshooting

| Symptom                                                          | Likely cause / fix                                                                                                |
| ---------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `dependency failed to start: container vanguard-ollama is unhealthy` | First-time model pull is slow. The healthcheck has 60 retries × 15 s. `docker compose logs -f ollama-service`.   |
| Gate auto-rejects immediately                                    | `HUMAN_APPROVAL_MODE` is `auto_reject`, or no TTY is attached. Ensure `docker compose up` (not `up -d`).          |
| `ConnectError: All connection attempts failed`                   | Ollama not yet listening. Check `docker compose ps` for `service_healthy`.                                        |
| Empty / odd JSON from agents                                     | qwen2.5-coder:7b is small. Increase `REQUEST_TIMEOUT_S`, or switch to `qwen2.5-coder:14b` / `qwen2.5:14b-instruct`. |
| Telegram returns 401 / Discord returns 404                       | Token / webhook is wrong. Test with `curl` first; the dispatcher will not retry hard 4xx responses.                |
| Pipeline ends after only a few messages                          | A noisy term in an agent prose response collided with `__VANGUARD_*` tokens (extremely unlikely). Inspect logs.   |
| OOM / process killed                                             | 7b model needs ~6-8 GB RAM. Pick `qwen2.5-coder:3b` or close other workloads.                                     |

---

## 11. Hardening checklist

Already applied:

* Non-root user (UID 1001) inside the container.
* `cap_drop: ALL` and `no-new-privileges: true` on `blueteam-agents`.
* `tini` as PID 1 — proper SIGTERM forwarding.
* Multi-stage build — no compilers in the runtime image.
* SIEM batch volume mounted **read-only** (`:ro`).
* Pinned dependency ranges across `autogen-*`, `openai`, `httpx`, `pydantic`.
* Healthcheck in both services; `depends_on.condition: service_healthy`.
* No `auto_approve` mode anywhere in the codebase.

Recommended for regulated deployments:

* Move `TELEGRAM_BOT_TOKEN` / `DISCORD_WEBHOOK_URL` to Docker Secrets,
  HashiCorp Vault, or AWS Secrets Manager. Never bake them into images.
* Pin both images to a digest (`@sha256:...`).
* Run the container with `read_only: true` once `/tmp` and `/reports`
  remain the only writable mounts (already 90% there).
* Forward audit logs (operator decisions, dispatch outcomes) to your SIEM
  via syslog or a Filebeat sidecar.

---

## License

MIT — see `LICENSE`.

_Made with care by [@0xvanguard](https://github.com/0xvanguard) — Bogotá, Colombia._
