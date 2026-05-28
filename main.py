"""
================================================================================
 VANGUARD-X · Autonomous Multi-Agent SecOps Platform
--------------------------------------------------------------------------------
 Author      : John Sebastian Camargo  (@0xvanguard)
 Framework   : Microsoft AutoGen v0.4   (asynchronous, event-driven)
 Local LLM   : qwen2.5-coder:7b via Ollama (OpenAI-compatible API at /v1)
 Pipeline    : ReconAgent -> ScannerAgent -> ThreatIntelAgent
               -> SocAgent -> AuditorAgent

 Design principles (VANGUARD-X master steering):
   * Agency over Automation       — every agent reasons, none merely echoes
   * Confidence Scoring           — each agent emits a 0-100 confidence value
   * Context-window discipline    — each agent emits structured JSON, not raw
                                    tool dumps, so the next agent ingests
                                    a clean, schema-stable payload
   * Fail Safe                    — typed errors, signal handling, graceful
                                    cancellation, and report persistence
   * Production-grade from day 1  — full type hints, structured logging,
                                    retries, timeouts, no silent failures
================================================================================
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Final

# --- AutoGen v0.4 (async, event-driven) --------------------------------------
from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.base import TaskResult
from autogen_agentchat.conditions import (
    MaxMessageTermination,
    TextMentionTermination,
)
from autogen_agentchat.teams import RoundRobinGroupChat
from autogen_agentchat.ui import Console
from autogen_core.models import ModelFamily, ModelInfo
from autogen_ext.models.openai import OpenAIChatCompletionClient

# Optional: load .env in local dev — ignored silently if not installed.
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # pragma: no cover - dotenv is in requirements but be safe
    pass


# =============================================================================
# 1. Logging
# =============================================================================
LOG_LEVEL: Final[str] = os.getenv("LOG_LEVEL", "INFO").upper()

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s | %(levelname)-8s | %(name)-22s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z",
    stream=sys.stdout,
)
# Silence very chatty third-party libraries — keep our signal-to-noise high.
for noisy in ("httpx", "httpcore", "openai._base_client"):
    logging.getLogger(noisy).setLevel(logging.WARNING)

logger: Final[logging.Logger] = logging.getLogger("vanguard.secops")


# =============================================================================
# 2. Runtime configuration
# =============================================================================
@dataclass(frozen=True, slots=True)
class Settings:
    """Immutable runtime configuration loaded from environment variables."""

    ollama_base_url: str
    ollama_model: str
    ollama_api_key: str
    max_agent_turns: int
    request_timeout_s: float
    reports_dir: Path

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            ollama_base_url=os.getenv(
                "OLLAMA_BASE_URL", "http://ollama-service:11434/v1"
            ),
            ollama_model=os.getenv("OLLAMA_MODEL", "qwen2.5-coder:7b"),
            # Ollama ignores the key but the OpenAI SDK requires a non-empty one.
            ollama_api_key=os.getenv("OLLAMA_API_KEY", "ollama-local-noop"),
            max_agent_turns=int(os.getenv("MAX_AGENT_TURNS", "20")),
            request_timeout_s=float(os.getenv("REQUEST_TIMEOUT_S", "240")),
            reports_dir=Path(
                os.getenv("REPORTS_DIR", "/home/secops/app/reports")
            ),
        )


SETTINGS: Final[Settings] = Settings.from_env()


# =============================================================================
# 3. Senior-expert system messages (one per agent)
#    Each persona simulates 15-25 years of domain experience and is constrained
#    to emit deterministic JSON so the next agent in the pipeline can parse
#    it without context-window blow-up.
# =============================================================================
RECON_SYSTEM_MESSAGE: Final[str] = """\
You are RECON-AGENT, a Senior Reconnaissance Specialist with 25+ years of
offensive Red Team operations. You apply the PTES Intelligence Gathering
phase, OSSTMM, and OWASP WSTG.

ROLE
====
You are the FIRST agent in a SecOps kill-chain pipeline. You produce the
attack-surface intelligence the rest of the team will consume. You DO NOT
execute tools — you analyse and reason about the target description provided
by the user and emit structured findings.

RESPONSIBILITIES
================
1. Enumerate likely attack vectors and surface elements:
   - Subdomains, virtual hosts, dangling DNS, certificate transparency hints
   - Detected technology stack: web server, framework, language, CMS, auth
   - Authentication surfaces: login pages, OAuth flows, JWT, SSO, SAML
   - Cloud assets: S3, GCS, Azure Blob, R2 — when inferable from the brief
   - WAF / CDN / reverse-proxy fingerprints, TLS posture clues
   - Indicators of dev / staging / preprod exposure (very high signal)
2. Separate passive (OSINT) from active (probing) findings.
3. Score each vector by likely risk (low / medium / high / critical).
4. Produce a confidence_score (0-100) for the overall assessment.

OUTPUT FORMAT — STRICT
======================
You MUST respond with exactly ONE JSON block in ```json fences, followed by
a single short paragraph (<= 4 lines) summarising the findings for the team.

```json
{
  "agent": "ReconAgent",
  "target": "<asset under analysis>",
  "attack_surface": {
    "subdomains": [],
    "technologies": [],
    "auth_endpoints": [],
    "exposed_services": [],
    "waf_cdn": []
  },
  "attack_vectors": [
    {"vector": "<name>", "risk": "low|medium|high|critical", "rationale": "<why>"}
  ],
  "confidence_score": 0,
  "next_steps": ["<actionable handoff for ScannerAgent>"]
}
```

Do not request tool execution. Do not invent CVEs. Stay within the brief.
"""

SCANNER_SYSTEM_MESSAGE: Final[str] = """\
You are SCANNER-AGENT, a Senior Vulnerability Analyst with 22+ years parsing
output from Nmap, Nuclei, Nikto, Burp, SQLMap, Gobuster and custom fuzzers.
You think in CWE, CVSS v3.1 and OWASP Top 10 2021 categories.

ROLE
====
You are the SECOND agent. You consume the ReconAgent JSON above and translate
the surface into concrete, evidenced vulnerabilities and misconfigurations.

RESPONSIBILITIES
================
1. For each surface element, identify likely vulnerabilities:
   - Open / unnecessary ports, exposed admin panels, default credentials
   - Outdated software versions and end-of-life components
   - Verbose errors, debug pages, stack traces, source-map / .git / .env leaks
   - Injection vectors: SQLi, NoSQLi, SSRF, XXE, CMDi, template injection
   - Broken access control / IDOR / authentication bypass / JWT none-alg
   - Missing security headers (CSP, HSTS, X-Frame, COOP/COEP), insecure cookies
   - Weak / deprecated TLS, mixed content, certificate misissuance
2. Cross-correlate findings to suppress likely false positives (mark
   false_positive_likelihood explicitly).
3. Map every finding to its CWE-ID and OWASP 2021 category (A01-A10).
4. Estimate a CVSS v3.1 base score (0.0 - 10.0) for each finding.

OUTPUT FORMAT — STRICT
======================
ONE JSON block in ```json fences, then ONE short paragraph (<= 4 lines).

```json
{
  "agent": "ScannerAgent",
  "findings": [
    {
      "id": "VULN-001",
      "title": "<short title>",
      "cwe": "CWE-XXX",
      "owasp_2021": "A0X:2021 - <name>",
      "severity": "info|low|medium|high|critical",
      "cvss_v3_estimate": 0.0,
      "evidence": "<why this is plausible given the recon data>",
      "false_positive_likelihood": "low|medium|high",
      "affected_asset": "<from recon>"
    }
  ],
  "scanner_confidence": 0,
  "summary": "<one-liner>"
}
```

Never invent CVE identifiers here — that is ThreatIntelAgent's job.
"""

THREAT_INTEL_SYSTEM_MESSAGE: Final[str] = """\
You are THREATINTEL-AGENT, a Senior Cyber Threat Intelligence (CTI) analyst
with 15+ years correlating findings against MITRE ATT&CK Enterprise, the
NVD/CVE database, Exploit-DB, Metasploit modules and threat-actor TTP
libraries.

ROLE
====
You are the THIRD agent. You enrich each ScannerAgent finding with threat
context so the SOC can quantify business risk.

RESPONSIBILITIES
================
1. For each finding, propose plausible CVE matches:
   - Use only well-known IDs you are confident in.
   - When uncertain, set "candidate": true to flag it as a hypothesis.
   - Never fabricate CVE numbers that do not exist.
2. Map each finding to MITRE ATT&CK Enterprise:
   - tactics: TA0001..TA0040
   - techniques: Txxxx and sub-techniques Txxxx.xxx (with the human name)
3. Assess exploit availability on a 5-step ladder:
   none | poc | metasploit | weaponized | in-the-wild
4. Identify the most plausible threat-actor archetype:
   opportunistic | apt | ransomware | hacktivist | insider
   Avoid naming specific groups unless evidence is overwhelming.

OUTPUT FORMAT — STRICT
======================
ONE JSON block in ```json fences, then ONE short paragraph (<= 4 lines).

```json
{
  "agent": "ThreatIntelAgent",
  "enrichments": [
    {
      "finding_id": "VULN-001",
      "cve_matches": [
        {"id": "CVE-YYYY-NNNNN", "candidate": false, "cvss_v3": 0.0}
      ],
      "mitre_tactics": ["TA0001"],
      "mitre_techniques": [
        {"id": "T1190", "name": "Exploit Public-Facing Application"}
      ],
      "exploit_availability": "none|poc|metasploit|weaponized|in-the-wild",
      "actor_archetype": "opportunistic|apt|ransomware|hacktivist|insider"
    }
  ],
  "intel_confidence": 0
}
```
"""

SOC_SYSTEM_MESSAGE: Final[str] = """\
You are SOC-AGENT, a Tier-3 SOC Analyst with 20+ years of incident
correlation, alert triage and risk quantification (CVSS v3.1, DREAD, FAIR).

ROLE
====
You are the FOURTH agent. You consume the Recon + Scanner + ThreatIntel JSON
emitted earlier in the conversation and convert it into a prioritised,
fatigue-resistant alert queue.

RESPONSIBILITIES
================
1. Compute a composite risk score for each alert on a 0.0 - 10.0 scale:
       risk = (cvss_v3 * 0.5)
            + (exploitability_factor * 0.3)
            + (asset_criticality * 0.2)
   where exploitability_factor maps the ThreatIntel ladder to a 0-10 value
   (none=0, poc=3, metasploit=6, weaponized=8, in-the-wild=10).
2. Assign a priority tier:
       P0 = page now / active exploitation possible
       P1 = mitigate within 24h
       P2 = mitigate within 7 days
       P3 = mitigate within the current sprint
       P4 = backlog / accept-with-monitoring
3. Identify multi-finding attack chains (e.g. info-disclosure ->
   auth-bypass -> RCE) and ELEVATE the priority of any finding that
   participates in such a chain.
4. Suppress duplicates and noisy signals to prevent alert fatigue —
   mark each alert as signal | likely_signal | noise.
5. Recommend a concrete containment action per high-priority alert
   (e.g. "block /debug at the WAF", "rotate JWT signing keys").

OUTPUT FORMAT — STRICT
======================
ONE JSON block in ```json fences, then ONE short paragraph (<= 4 lines).

```json
{
  "agent": "SocAgent",
  "prioritized_alerts": [
    {
      "alert_id": "ALERT-001",
      "linked_findings": ["VULN-001"],
      "priority": "P0|P1|P2|P3|P4",
      "composite_risk": 0.0,
      "attack_chain": ["recon", "initial_access", "execution"],
      "containment_action": "<concrete action>",
      "fatigue_assessment": "signal|likely_signal|noise"
    }
  ],
  "overall_posture": "critical|high|medium|low",
  "incident_declared": false
}
```
"""

AUDITOR_SYSTEM_MESSAGE: Final[str] = """\
You are AUDITOR-AGENT, a Senior Compliance Auditor (CISSP, ISO 27001 Lead
Auditor, CISA) with 18+ years writing audit reports for regulated industries
(PCI-DSS, HIPAA, GDPR, SOC 2).

ROLE
====
You are the FINAL agent. You consume the full Recon + Scanner + ThreatIntel
+ SOC conversation above and produce the executive + technical deliverable.

RESPONSIBILITIES
================
Compile a polished Markdown audit report with the following sections:

  1. Executive Summary  (5-10 lines, business-readable)
  2. Scope & Methodology
  3. Consolidated Findings table (severity-sorted, includes CVSS, OWASP,
     ATT&CK technique IDs)
  4. Detailed Findings — one block per finding containing:
       * Description and evidence
       * Mapped controls:
           - OWASP Top 10 2021  (A01..A10)
           - ISO/IEC 27001:2022 Annex A controls (A.5 - A.8)
           - NIST Cybersecurity Framework 2.0 categories
           - CIS Controls v8 safeguards
       * Concrete technical remediation: configuration snippets, code
         patterns, network controls, or detection rules. Be specific —
         no vague advice such as "patch the system".
  5. Remediation Roadmap — split into Quick Wins (24h), 30-day plan,
     90-day plan.
  6. Residual Risk Statement.

OUTPUT REQUIREMENTS
===================
* Emit POLISHED MARKDOWN, not JSON.
* Be precise, prescriptive, and concise.
* Once your report is complete, end your message with the literal token
  TERMINATE on its own final line. The orchestrator listens for that token
  to close the conversation cleanly.
"""


# =============================================================================
# 4. Model client factory  — Ollama via the OpenAI-compatible /v1 endpoint
# =============================================================================
def build_model_client() -> OpenAIChatCompletionClient:
    """
    Construct an :class:`OpenAIChatCompletionClient` pointed at the local
    Ollama daemon. Ollama exposes an OpenAI-compatible endpoint at /v1, so we
    reuse the canonical AutoGen client and declare the model capabilities
    explicitly via ``model_info`` (mandatory for non-OpenAI catalog models).

    Returns
    -------
    OpenAIChatCompletionClient
        A configured async chat-completion client ready for AutoGen agents.
    """
    model_info: ModelInfo = {
        "vision": False,
        # qwen2.5-coder supports tool-calling but we do NOT pass tools to the
        # agents in this pipeline — keeping it False removes a class of
        # parser ambiguity on the OpenAI-compat shim.
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
# 5. Agent factory
# =============================================================================
def build_agents(model_client: OpenAIChatCompletionClient) -> list[AssistantAgent]:
    """
    Instantiate the 5-agent SecOps pipeline in execution order.

    The order matters because the team uses a deterministic round-robin:
    Recon -> Scanner -> ThreatIntel -> SOC -> Auditor.
    """
    return [
        AssistantAgent(
            name="ReconAgent",
            description="Senior reconnaissance & attack-surface analyst (PTES, OSSTMM).",
            model_client=model_client,
            system_message=RECON_SYSTEM_MESSAGE,
        ),
        AssistantAgent(
            name="ScannerAgent",
            description="Senior vulnerability scanner & misconfiguration analyst (CWE/CVSS).",
            model_client=model_client,
            system_message=SCANNER_SYSTEM_MESSAGE,
        ),
        AssistantAgent(
            name="ThreatIntelAgent",
            description="Senior CTI analyst — CVE / MITRE ATT&CK enrichment.",
            model_client=model_client,
            system_message=THREAT_INTEL_SYSTEM_MESSAGE,
        ),
        AssistantAgent(
            name="SocAgent",
            description="Tier-3 SOC analyst — correlation, triage, prioritisation.",
            model_client=model_client,
            system_message=SOC_SYSTEM_MESSAGE,
        ),
        AssistantAgent(
            name="AuditorAgent",
            description="Senior compliance auditor — final report & remediation roadmap.",
            model_client=model_client,
            system_message=AUDITOR_SYSTEM_MESSAGE,
        ),
    ]


# =============================================================================
# 6. Team factory  — RoundRobinGroupChat with composite termination
# =============================================================================
def build_team(agents: list[AssistantAgent]) -> RoundRobinGroupChat:
    """
    Wire the agents into a deterministic Recon -> ... -> Auditor pipeline
    governed by two termination conditions ORed together (v0.4 supports
    the ``|`` operator on conditions):

      * ``MaxMessageTermination`` — hard upper bound on agent turns to
        prevent runaway loops on small local models.
      * ``TextMentionTermination("TERMINATE")`` — clean stop when the
        AuditorAgent declares the report finished.
    """
    termination = MaxMessageTermination(
        max_messages=SETTINGS.max_agent_turns
    ) | TextMentionTermination("TERMINATE")

    return RoundRobinGroupChat(
        participants=agents,
        termination_condition=termination,
    )


# =============================================================================
# 7. Default scenario  — example task per the project brief
# =============================================================================
DEFAULT_TASK: Final[str] = (
    "Auditar la presencia de una API expuesta en el subdominio "
    "`dev.company.local` que muestra un stack trace detallado al recibir "
    "payloads maliciosos. Indicios: la API parece estar construida sobre "
    "Python (probablemente Flask o FastAPI), corre detras de Nginx 1.18 sin "
    "WAF aparente, y esta accidentalmente expuesta a Internet desde un "
    "entorno preproductivo. Realizar el flujo completo: reconocimiento, "
    "escaneo de vulnerabilidades, enriquecimiento con threat intelligence "
    "(CVE + MITRE ATT&CK), triaje SOC con priorizacion de alertas, y "
    "reporte final alineado a OWASP Top 10 2021 e ISO/IEC 27001:2022."
)


# =============================================================================
# 8. Report persistence
# =============================================================================
def persist_report(result: TaskResult) -> Path | None:
    """
    Persist the final AuditorAgent message to a timestamped Markdown file
    inside ``SETTINGS.reports_dir``. Returns the file path on success, or
    ``None`` if no auditor message could be located.
    """
    final_md: str | None = None
    for message in reversed(result.messages):
        # The auditor's final answer is the last TextMessage in the conversation.
        source = getattr(message, "source", None)
        content = getattr(message, "content", None)
        if source == "AuditorAgent" and isinstance(content, str):
            final_md = content
            break

    if not final_md:
        logger.warning("No AuditorAgent message found — skipping report persistence.")
        return None

    SETTINGS.reports_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = SETTINGS.reports_dir / f"vanguard-x-report-{stamp}.md"
    out_path.write_text(final_md, encoding="utf-8")
    logger.info("Audit report persisted to %s", out_path)
    return out_path


# =============================================================================
# 9. Pipeline orchestration
# =============================================================================
async def run_pipeline(task: str) -> TaskResult:
    """
    Run the full multi-agent SecOps pipeline for ``task`` and return the
    final :class:`TaskResult`. The model client is closed in a ``finally``
    block to guarantee underlying httpx connections are released even when
    the run is cancelled mid-flight.
    """
    logger.info("Bootstrapping VANGUARD-X SecOps multi-agent pipeline")
    model_client = build_model_client()
    try:
        agents = build_agents(model_client)
        team = build_team(agents)
        logger.info(
            "Team ready | agents=%d | max_turns=%d | termination=Max|TERMINATE",
            len(agents),
            SETTINGS.max_agent_turns,
        )
        logger.info(
            "Dispatching task to pipeline: Recon -> Scanner -> ThreatIntel "
            "-> SOC -> Auditor"
        )
        # Console() consumes the async stream from team.run_stream() and
        # pretty-prints every message to stdout while returning the final
        # TaskResult once a termination condition fires.
        result: TaskResult = await Console(team.run_stream(task=task))
        logger.info(
            "Pipeline completed | messages=%d | stop_reason=%s",
            len(result.messages),
            result.stop_reason,
        )
        return result
    finally:
        await model_client.close()


# =============================================================================
# 10. Signal handling — graceful shutdown in containers
# =============================================================================
def install_signal_handlers(loop: asyncio.AbstractEventLoop) -> None:
    """
    Wire SIGINT / SIGTERM to cancel all running asyncio tasks. Required for
    clean shutdown when Docker / Kubernetes sends SIGTERM during termination.
    """

    def _cancel_all(sig: signal.Signals) -> None:
        logger.warning("Received %s — cancelling all in-flight tasks...", sig.name)
        for task in asyncio.all_tasks(loop):
            task.cancel()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _cancel_all, sig)
        except (NotImplementedError, RuntimeError):
            # Windows / restricted runtimes — fall back to default handler.
            pass


# =============================================================================
# 11. Entrypoint
# =============================================================================
async def main() -> int:
    """Async entrypoint. Returns a POSIX-style exit code."""
    task = os.getenv("SECOPS_TASK", DEFAULT_TASK).strip() or DEFAULT_TASK

    banner = "=" * 78
    logger.info(banner)
    logger.info("VANGUARD-X · Autonomous Multi-Agent SecOps Pipeline")
    logger.info("AutoGen v0.4  |  Local LLM: %s", SETTINGS.ollama_model)
    logger.info(banner)
    logger.info("Task:\n%s", task)
    logger.info(banner)

    try:
        result = await run_pipeline(task)
    except asyncio.CancelledError:
        logger.warning("Pipeline cancelled by signal.")
        return 130
    except Exception as exc:  # noqa: BLE001 — top-level safety net by design
        logger.exception("Pipeline failed with unhandled error: %s", exc)
        return 1

    try:
        persist_report(result)
    except Exception as exc:  # noqa: BLE001
        # Persistence is a side-effect; never let it mask a successful run.
        logger.error("Report persistence failed: %s", exc)

    logger.info("VANGUARD-X pipeline finished cleanly.")
    return 0


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
