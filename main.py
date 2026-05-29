"""
================================================================================
 VANGUARD-X · Blue Team Multi-Agent SecOps Platform
--------------------------------------------------------------------------------
 Author      : John Sebastian Camargo (@0xvanguard)
 Framework   : Microsoft AutoGen v0.4   (asynchronous, event-driven)
 Local LLM   : qwen2.5-coder:7b via Ollama (OpenAI-compatible API at /v1)

 Pipeline (deterministic round-robin, single pass):
     LogIngestAgent          -> normalise & deduplicate the SIEM/EDR batch
     EnrichmentAgent         -> add asset/identity context, MITRE technique map
     CorrelationAgent        -> reconstruct timeline & multi-event attack chains
     SeverityAgent           -> composite risk score, P0..P4, fatigue triage
     ComplianceAgent         -> ISO 27001 + NIST CSF + OWASP-aligned report
     HumanApprovalAgent      -> MANDATORY gate (UserProxyAgent, fail-closed)

 Hard policy (codified in this file, NOT bypassable):
   1. ZERO active scanning. Agents reason only over data we already own.
   2. ZERO third-party network calls. Outbound traffic is restricted to:
        * the internal ollama-service (LLM inference)
        * Telegram / Discord — and only AFTER an explicit human APPROVE.
   3. The HumanApprovalAgent is fail-closed: any timeout, parse error,
      missing input, or REJECT decision halts the pipeline before any
      side effect.
   4. Notifications carry the auditor report only — never raw SIEM events,
      never PII beyond what the auditor has already redacted/contextualised.
================================================================================
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final

# --- AutoGen v0.4 -------------------------------------------------------------
from autogen_agentchat.agents import AssistantAgent, UserProxyAgent
from autogen_agentchat.base import TaskResult
from autogen_agentchat.conditions import (
    MaxMessageTermination,
    TextMentionTermination,
)
from autogen_agentchat.teams import RoundRobinGroupChat
from autogen_agentchat.ui import Console
from autogen_core import CancellationToken
from autogen_core.models import ModelFamily, ModelInfo
from autogen_ext.models.openai import OpenAIChatCompletionClient

from notifications import NotificationDispatcher

# Optional: pull .env in local dev. Silent no-op if dotenv missing.
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # pragma: no cover
    pass


# =============================================================================
# Logging
# =============================================================================
LOG_LEVEL: Final[str] = os.getenv("LOG_LEVEL", "INFO").upper()

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s | %(levelname)-8s | %(name)-25s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z",
    stream=sys.stdout,
)
for noisy in ("httpx", "httpcore", "openai._base_client"):
    logging.getLogger(noisy).setLevel(logging.WARNING)

logger: Final[logging.Logger] = logging.getLogger("vanguard.blueteam")


# =============================================================================
# Approval gate tokens
# Long, namespaced, low-collision strings so an analyst's prose can never
# accidentally trigger termination.
# =============================================================================
APPROVE_TOKEN: Final[str] = "__VANGUARD_APPROVE_NOTIFICATION__"
REJECT_TOKEN: Final[str] = "__VANGUARD_REJECT_NOTIFICATION__"


# =============================================================================
# Offensive-intent guard (L1 defence-in-depth)
# -----------------------------------------------------------------------------
# We refuse to feed any JSON batch that looks like a scan task to the agents,
# even if every individual event would be benign on its own. The presence of
# these keys at ANY nesting level in the input file is treated as a policy
# violation and aborts the pipeline before the first agent is invoked.
#
# The LogIngestAgent's system_message contains the same deny-list as L2
# defence — if a future edit ever weakens this Python check, the agent will
# still refuse the batch on first inspection.
# =============================================================================
FORBIDDEN_BATCH_KEYS: Final[frozenset[str]] = frozenset(
    {
        # Targeting
        "target_ip", "target_host", "target_url", "target_port", "targets",
        # Scanning intent
        "scan_type", "scan_target", "scan_options", "scan_profile",
        "nmap_args", "nmap_command", "nmap_options", "nmap_flags",
        # Exploitation tooling
        "exploit_target", "exploit_module", "exploit_options",
        "metasploit_module", "msf_module", "msf_options",
        "sqlmap_options", "nuclei_template", "nuclei_args",
        # Generic offensive verbs at batch level
        "attack_args", "attack_target", "attack_type",
        "payload_command", "payload_url", "shellcode",
    }
)

# A short, non-PII rejection sentence shared by L1 and L2 so audit logs are
# greppable across enforcement points.
OFFENSIVE_INTENT_REJECTION: Final[str] = (
    "Rejected: Input resembles scan task, not SIEM alert."
)


class OffensiveIntentDetected(RuntimeError):
    """Raised when the input batch contains keys that imply scanning intent."""

    def __init__(self, offending_keys: list[str]) -> None:
        self.offending_keys = offending_keys
        super().__init__(
            f"{OFFENSIVE_INTENT_REJECTION} Offending keys: {offending_keys}"
        )


def _walk_keys(node: object, acc: set[str]) -> None:
    """Depth-first walk that collects every dict key (lower-cased)."""
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(key, str):
                acc.add(key.lower())
            _walk_keys(value, acc)
    elif isinstance(node, list):
        for item in node:
            _walk_keys(item, acc)


def assert_no_offensive_intent(batch: object) -> None:
    """
    Raise :class:`OffensiveIntentDetected` if ``batch`` contains any key that
    suggests the input is a scan task instead of pre-collected SIEM/EDR
    telemetry. Pure inspection — never mutates the input, never logs PII.
    """
    keys: set[str] = set()
    _walk_keys(batch, keys)
    matches = sorted(keys & FORBIDDEN_BATCH_KEYS)
    if matches:
        raise OffensiveIntentDetected(matches)


# =============================================================================
# Runtime configuration
# =============================================================================
@dataclass(frozen=True, slots=True)
class Settings:
    """Immutable runtime configuration loaded from environment variables."""

    ollama_base_url: str
    ollama_model: str
    ollama_api_key: str
    max_agent_turns: int
    request_timeout_s: float
    siem_events_path: Path
    reports_dir: Path
    human_approval_mode: str
    human_approval_timeout_s: float

    @classmethod
    def from_env(cls) -> "Settings":
        mode = os.getenv("HUMAN_APPROVAL_MODE", "interactive").strip().lower()
        if mode not in {"interactive", "auto_reject"}:
            raise ValueError(
                f"HUMAN_APPROVAL_MODE must be 'interactive' or 'auto_reject', "
                f"got {mode!r}. There is intentionally no auto_approve mode."
            )
        return cls(
            ollama_base_url=os.getenv(
                "OLLAMA_BASE_URL", "http://ollama-service:11434/v1"
            ),
            ollama_model=os.getenv("OLLAMA_MODEL", "qwen2.5-coder:7b"),
            ollama_api_key=os.getenv("OLLAMA_API_KEY", "ollama-local-noop"),
            max_agent_turns=int(os.getenv("MAX_AGENT_TURNS", "18")),
            request_timeout_s=float(os.getenv("REQUEST_TIMEOUT_S", "240")),
            siem_events_path=Path(
                os.getenv(
                    "SIEM_EVENTS_PATH",
                    "/home/secops/app/sample_data/siem_events.json",
                )
            ),
            reports_dir=Path(
                os.getenv("REPORTS_DIR", "/home/secops/app/reports")
            ),
            human_approval_mode=mode,
            human_approval_timeout_s=float(
                os.getenv("HUMAN_APPROVAL_TIMEOUT_S", "600")
            ),
        )


SETTINGS: Final[Settings] = Settings.from_env()


# =============================================================================
# System messages — one Blue Team persona per agent
#   * Strictly defensive: no active probing, no offensive recommendations.
#   * Each agent emits structured JSON for the next agent (compliance ends
#     with prose Markdown).
#   * The HumanApprovalAgent's behaviour is governed by an input_func, not
#     an LLM system message — its only job is to record a human decision.
# =============================================================================
LOG_INGEST_SYSTEM_MESSAGE: Final[str] = """\
You are LOG-INGEST-AGENT, a Senior SOC log-pipeline engineer (20+ years
operating Splunk, Elastic SIEM, Wazuh, Sentinel, Chronicle).

ROLE
====
You are the FIRST agent in a Blue Team pipeline. You normalise, deduplicate
and cluster a batch of pre-collected SIEM / EDR events that are ALREADY in
our possession. You DO NOT run scanners. You DO NOT touch any external
network. You only reason over the events provided in the user message.

RESPONSIBILITIES
        "function_calling": False,
        "json_output": True,
        "family": ModelFamily.UNKNOWN,
        "structured_output": False,
    }

    logger.info(
        "Initialising Ollama model client | model=%s | endpoint=%s | timeout=%.0fs",
        SETTINGS.ollama_model,
        SETTINGS.ollama_base_url,
        SETTINGS.request_timeout_s,
    )
    return OpenAIChatCompletionClient(
        model=SETTINGS.ollama_model,
        base_url=SETTINGS.ollama_base_url,
        api_key=SETTINGS.ollama_api_key,
        model_info=model_info,
        timeout=SETTINGS.request_timeout_s,
        max_retries=3,
    )


# =============================================================================
# Agent factory  — 5 Blue Team analysts + 1 mandatory human gate
# =============================================================================
def build_agents(
    model_client: OpenAIChatCompletionClient,
) -> list[AssistantAgent | UserProxyAgent]:
    """
    Instantiate the agents in execution order:

        LogIngest -> Enrichment -> Correlation -> Severity
                  -> Compliance -> HumanApproval (gate)

    The ``HumanApprovalAgent`` is a :class:`UserProxyAgent` whose
    ``input_func`` enforces the fail-closed policy for the whole platform.
    """
    return [
        AssistantAgent(
            name="LogIngestAgent",
            description="Senior SOC log-pipeline engineer — normalises and "
            "deduplicates the SIEM/EDR batch.",
            model_client=model_client,
            system_message=LOG_INGEST_SYSTEM_MESSAGE,
        ),
        AssistantAgent(
            name="EnrichmentAgent",
            description="Senior SOC analyst — asset/identity context + "
            "MITRE ATT&CK technique attribution from observed signals.",
            model_client=model_client,
            system_message=ENRICHMENT_SYSTEM_MESSAGE,
        ),
        AssistantAgent(
            name="CorrelationAgent",
            description="Senior detection engineer — timeline reconstruction "
            "and multi-event attack chains.",
            model_client=model_client,
            system_message=CORRELATION_SYSTEM_MESSAGE,
        ),
        AssistantAgent(
            name="SeverityAgent",
            description="Tier-3 SOC lead — composite risk, prioritisation, "
            "alert-fatigue triage.",
            model_client=model_client,
            system_message=SEVERITY_SYSTEM_MESSAGE,
        ),
        AssistantAgent(
            name="ComplianceAgent",
            description="Senior compliance auditor — final ISO 27001 / NIST "
            "CSF 2.0 / OWASP-aligned report.",
            model_client=model_client,
            system_message=COMPLIANCE_SYSTEM_MESSAGE,
        ),
        UserProxyAgent(
            name="HumanApprovalAgent",
            description=HUMAN_APPROVAL_DESCRIPTION,
            input_func=_human_approval_input,
        ),
    ]


# =============================================================================
# Team factory — RoundRobinGroupChat with composite, fail-closed termination
# =============================================================================
def build_team(
    agents: list[AssistantAgent | UserProxyAgent],
) -> RoundRobinGroupChat:
    """
    Wire the agents into a strict round-robin and combine three termination
    conditions with the v0.4 ``|`` operator:

      * ``MaxMessageTermination`` — hard ceiling (safety net).
      * ``TextMentionTermination(APPROVE_TOKEN)`` — operator approved.
      * ``TextMentionTermination(REJECT_TOKEN)`` — operator rejected /
                                                     fail-closed path.
    """
    termination = (
        MaxMessageTermination(max_messages=SETTINGS.max_agent_turns)
        | TextMentionTermination(APPROVE_TOKEN)
        | TextMentionTermination(REJECT_TOKEN)
    )
    return RoundRobinGroupChat(
        participants=agents,  # type: ignore[arg-type]
        termination_condition=termination,
    )


# =============================================================================
# Task assembly — embeds the SIEM batch (no fetching, ever)
# =============================================================================
def load_siem_batch() -> dict[str, Any]:
    """Load the pre-collected SIEM/EDR batch from disk. Never network."""
    if not SETTINGS.siem_events_path.exists():
        raise FileNotFoundError(
            f"SIEM events file not found at {SETTINGS.siem_events_path}. "
            "Mount it via the docker-compose `sample_data` volume or set "
            "SIEM_EVENTS_PATH explicitly."
        )
    with SETTINGS.siem_events_path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def build_task_prompt(batch: dict[str, Any]) -> str:
    """
    Compose the task prompt that kicks off the team. The full SIEM batch is
    embedded inline so the agents never need filesystem or network access.
    """
    override = os.getenv("SECOPS_TASK", "").strip()
    intro = override or (
        "Process the following batch of SIEM/EDR events that we already "
        "own. Run the full Blue Team pipeline (ingest -> enrichment -> "
        "correlation -> severity -> compliance) and produce a final "
        "Markdown report aligned to ISO/IEC 27001:2022, NIST CSF 2.0, "
        "and OWASP Top 10 2021. Strictly defensive analysis: zero active "
        "scanning, zero third-party network calls."
    )
    serialised_batch = json.dumps(batch, indent=2, ensure_ascii=False)
    return (
        f"{intro}\n\n"
        f"BATCH METADATA: id={batch.get('batch_id', 'unknown')}, "
        f"events={len(batch.get('events', []))}, "
        f"provenance={batch.get('data_provenance', 'unspecified')}\n\n"
        "RAW BATCH (JSON):\n"
        f"```json\n{serialised_batch}\n```"
    )


# =============================================================================
# Result inspection
# =============================================================================
@dataclass(slots=True)
class GateOutcome:
    decision: str               # "approved" | "rejected" | "unknown"
    rationale: str
    compliance_report: str | None


def parse_outcome(result: TaskResult) -> GateOutcome:
    """
    Inspect the conversation tail to determine:
      * whether the human gate approved or rejected, and
      * the latest ComplianceAgent Markdown report (the dispatch payload).

    Walks the message list in REVERSE so the most recent decision wins.
    """
    decision = "unknown"
    rationale = "no rationale captured"
    compliance_report: str | None = None

    for message in reversed(result.messages):
        source = getattr(message, "source", None)
        content = getattr(message, "content", None)
        if not isinstance(content, str):
            continue
        if source == "HumanApprovalAgent" and decision == "unknown":
            if APPROVE_TOKEN in content:
                decision = "approved"
            elif REJECT_TOKEN in content:
                decision = "rejected"
            rationale = content.strip()
        elif source == "ComplianceAgent" and compliance_report is None:
            compliance_report = content

    return GateOutcome(
        decision=decision,
        rationale=rationale,
        compliance_report=compliance_report,
    )


def persist_report(report_md: str | None) -> Path | None:
    """Persist the ComplianceAgent Markdown report to disk."""
    if not report_md:
        logger.warning("No compliance report found — skipping persistence.")
        return None
    SETTINGS.reports_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = SETTINGS.reports_dir / f"vanguard-x-blueteam-report-{stamp}.md"
    out_path.write_text(report_md, encoding="utf-8")
    logger.info("Compliance report persisted to %s", out_path)
    return out_path


# =============================================================================
# Pipeline orchestration
# =============================================================================
async def run_pipeline(task: str) -> TaskResult:
    """Run the round-robin multi-agent pipeline once and return its result."""
    logger.info("Bootstrapping VANGUARD-X Blue Team pipeline.")
    model_client = build_model_client()
    try:
        agents = build_agents(model_client)
        team = build_team(agents)
        logger.info(
            "Team ready | agents=%d (5 analysts + 1 human gate) | "
            "max_turns=%d | termination=Max|APPROVE|REJECT",
            len(agents),
            SETTINGS.max_agent_turns,
        )
        result: TaskResult = await Console(team.run_stream(task=task))
        logger.info(
            "Pipeline finished | messages=%d | stop_reason=%s",
            len(result.messages),
            result.stop_reason,
        )
        return result
    finally:
        await model_client.close()


# =============================================================================
# Signal handling — graceful shutdown
# =============================================================================
def install_signal_handlers(loop: asyncio.AbstractEventLoop) -> None:
    def _cancel_all(sig: signal.Signals) -> None:
        logger.warning("Received %s — cancelling all in-flight tasks.", sig.name)
        for task in asyncio.all_tasks(loop):
            task.cancel()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _cancel_all, sig)
        except (NotImplementedError, RuntimeError):
            pass


# =============================================================================
# Entrypoint
# =============================================================================
async def main() -> int:
    """Async entrypoint. Returns POSIX-style exit code."""
    banner = "=" * 78
    logger.info(banner)
    logger.info("VANGUARD-X · Blue Team Multi-Agent SecOps Pipeline")
    logger.info("AutoGen v0.4 | Local LLM: %s", SETTINGS.ollama_model)
    logger.info("Approval mode: %s", SETTINGS.human_approval_mode)
    logger.info(banner)

    # 1) Load the SIEM batch we already own.
    try:
        batch = load_siem_batch()
    except FileNotFoundError as exc:
        logger.error(str(exc))
        return 2

    # 1a) Defence-in-depth: refuse any batch that looks like a scan task,
    # even before the LogIngestAgent has a chance to inspect it. This is the
    # L1 enforcement point; the agent's system_message replicates the same
    # deny-list as L2 in case a future edit weakens this check.
    try:
        assert_no_offensive_intent(batch)
    except OffensiveIntentDetected as exc:
        logger.critical(
            "OFFENSIVE-INTENT GUARD TRIGGERED — refusing batch from %s. "
            "Offending keys: %s. %s",
            SETTINGS.siem_events_path,
            exc.offending_keys,
            OFFENSIVE_INTENT_REJECTION,
        )
        # Persist a short audit trace so the rejection is reviewable later.
        try:
            SETTINGS.reports_dir.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            audit_path = (
                SETTINGS.reports_dir
                / f"vanguard-x-rejection-{stamp}.txt"
            )
            audit_path.write_text(
                f"{OFFENSIVE_INTENT_REJECTION}\n"
                f"source: {SETTINGS.siem_events_path}\n"
                f"offending_keys: {exc.offending_keys}\n"
                f"rejected_at_utc: {stamp}\n",
                encoding="utf-8",
            )
            logger.info("Rejection audit trace written to %s", audit_path)
        except Exception as audit_exc:  # noqa: BLE001
            logger.error("Could not persist rejection audit trace: %s", audit_exc)
        return 4

    task = build_task_prompt(batch)
    logger.info(
        "Loaded SIEM batch %s with %d events from %s",
        batch.get("batch_id", "?"),
        len(batch.get("events", [])),
        SETTINGS.siem_events_path,
    )

    # 2) Run the round-robin team (Blue Team + human gate).
    try:
        result = await run_pipeline(task)
    except asyncio.CancelledError:
        logger.warning("Pipeline cancelled by signal.")
        return 130
    except Exception as exc:  # noqa: BLE001 — top-level safety net
        logger.exception("Pipeline failed with unhandled error: %s", exc)
        return 1

    # 3) Inspect the outcome of the human gate.
    outcome = parse_outcome(result)
    logger.info(
        "Gate decision: %s | rationale: %s",
        outcome.decision.upper(),
        outcome.rationale,
    )

    # 4) Always persist the compliance report (if produced) — even on REJECT.
    persist_report(outcome.compliance_report)

    # 5) Notification dispatch — gated, fail-closed.
    if outcome.decision != "approved":
        logger.warning(
            "Notification dispatch SKIPPED (decision=%s). "
            "VANGUARD-X never sends external traffic without an explicit "
            "human APPROVE.",
            outcome.decision,
        )
        return 0

    if not outcome.compliance_report:
        logger.error(
            "Approved by operator but no compliance report present — "
            "refusing to send empty payload. Halting."
        )
        return 1

    dispatcher = NotificationDispatcher()
    if not dispatcher.has_any_channel:
        logger.warning(
            "Operator APPROVED but no notification channels are configured. "
            "Report saved to disk only."
        )
        return 0

    dispatch_result = await dispatcher.dispatch(outcome.compliance_report)
    logger.info("Dispatch result: %s", dispatch_result.to_dict())
    return 0 if dispatch_result.all_succeeded else 3


if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    install_signal_handlers(loop)
    try:
        exit_code = loop.run_until_complete(main())
    finally:
        try:
            loop.close()
        except Exception:  # noqa: BLE001
            pass
    sys.exit(exit_code)
