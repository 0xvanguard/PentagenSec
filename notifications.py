"""
================================================================================
 VANGUARD-X Blue Team — Notification Dispatch Module
--------------------------------------------------------------------------------
 Async clients for Telegram and Discord. Used ONLY by the orchestrator after
 the HumanApprovalAgent has emitted an explicit APPROVE token.

 Hard policy enforced upstream (main.py):
   * Notifiers are NEVER invoked without a human APPROVE.
   * The gate is fail-closed: timeout / parse-error / missing channel -> halt.

 This module itself contains zero policy — its only job is to deliver an
 already-approved Markdown payload to one or more configured channels.
================================================================================
"""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass
from typing import Final

import httpx

logger: Final[logging.Logger] = logging.getLogger("vanguard.notifications")


# =============================================================================
# Constants — provider-specific limits
# =============================================================================
TELEGRAM_MAX_CHARS: Final[int] = 4096
DISCORD_MAX_CHARS: Final[int] = 2000
HTTP_TIMEOUT_S: Final[float] = 15.0
HTTP_MAX_RETRIES: Final[int] = 3
HTTP_BACKOFF_BASE_S: Final[float] = 1.5


# =============================================================================
# Helpers
# =============================================================================
def _chunk(text: str, max_chars: int) -> list[str]:
    """
    Split ``text`` into chunks of at most ``max_chars`` characters, preferring
    to break on newline boundaries so Markdown formatting is not torn apart.
    """
    if len(text) <= max_chars:
        return [text]

    chunks: list[str] = []
    remaining = text
    while len(remaining) > max_chars:
        slice_ = remaining[:max_chars]
        cut = slice_.rfind("\n")
        if cut < int(max_chars * 0.5):
            # Avoid pathological tiny chunks — fall back to a hard slice.
            cut = max_chars
        chunks.append(remaining[:cut])
        remaining = remaining[cut:].lstrip("\n")
    if remaining:
        chunks.append(remaining)
    return chunks


async def _post_with_retries(
    client: httpx.AsyncClient,
    url: str,
    *,
    json: dict | None = None,
    data: dict | None = None,
    label: str,
) -> bool:
    """
    POST helper with bounded retries and exponential backoff. Returns ``True``
    on a 2xx response, ``False`` after exhausting retries. Never raises — the
    caller decides what to do with a failed channel.
    """
    last_error: str = "unknown"
    for attempt in range(1, HTTP_MAX_RETRIES + 1):
        try:
            response = await client.post(url, json=json, data=data)
            if 200 <= response.status_code < 300:
                logger.info("%s: delivery OK (status=%s)", label, response.status_code)
                return True
            last_error = f"HTTP {response.status_code} — {response.text[:200]}"
            # Don't retry hard client errors (auth, bad request).
            if 400 <= response.status_code < 500 and response.status_code != 429:
                logger.error("%s: non-retriable error %s", label, last_error)
                return False
        except httpx.HTTPError as exc:
            last_error = f"{type(exc).__name__}: {exc}"

        if attempt < HTTP_MAX_RETRIES:
            backoff = HTTP_BACKOFF_BASE_S * (2 ** (attempt - 1))
            logger.warning(
                "%s: attempt %d/%d failed (%s) — retrying in %.1fs",
                label,
                attempt,
                HTTP_MAX_RETRIES,
                last_error,
                backoff,
            )
            await asyncio.sleep(backoff)

    logger.error(
        "%s: all %d attempts failed — last error: %s",
        label,
        HTTP_MAX_RETRIES,
        last_error,
    )
    return False


# =============================================================================
# Telegram
# =============================================================================
@dataclass(frozen=True, slots=True)
class TelegramConfig:
    bot_token: str
    chat_id: str

    @classmethod
    def from_env(cls) -> "TelegramConfig | None":
        token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
        chat = os.getenv("TELEGRAM_CHAT_ID", "").strip()
        if not token or not chat:
            return None
        return cls(bot_token=token, chat_id=chat)


class TelegramNotifier:
    """Minimal async Telegram Bot API client (sendMessage only)."""

    def __init__(self, config: TelegramConfig) -> None:
        self._config = config
        self._url = (
            f"https://api.telegram.org/bot{config.bot_token}/sendMessage"
        )

    async def send(self, client: httpx.AsyncClient, markdown: str) -> bool:
        """
        Deliver ``markdown`` to the configured chat, splitting if necessary.
        Returns ``True`` only when **every** chunk delivered successfully.
        """
        chunks = _chunk(markdown, TELEGRAM_MAX_CHARS)
        all_ok = True
        for index, chunk in enumerate(chunks, start=1):
            payload = {
                "chat_id": self._config.chat_id,
                "text": chunk,
                # Telegram's "Markdown" mode is forgiving; "MarkdownV2" rejects
                # unescaped punctuation. Stay on legacy "Markdown".
                "parse_mode": "Markdown",
                "disable_web_page_preview": True,
            }
            label = f"Telegram[{index}/{len(chunks)}]"
            ok = await _post_with_retries(
                client, self._url, data=payload, label=label
            )
            all_ok = all_ok and ok
        return all_ok


# =============================================================================
# Discord
# =============================================================================
@dataclass(frozen=True, slots=True)
class DiscordConfig:
    webhook_url: str

    @classmethod
    def from_env(cls) -> "DiscordConfig | None":
        url = os.getenv("DISCORD_WEBHOOK_URL", "").strip()
        if not url:
            return None
        return cls(webhook_url=url)


class DiscordNotifier:
    """Minimal async Discord webhook client."""

    def __init__(self, config: DiscordConfig) -> None:
        self._config = config

    async def send(self, client: httpx.AsyncClient, markdown: str) -> bool:
        chunks = _chunk(markdown, DISCORD_MAX_CHARS)
        all_ok = True
        for index, chunk in enumerate(chunks, start=1):
            payload = {
                "content": chunk,
                "username": "VANGUARD-X SOC",
                "allowed_mentions": {"parse": []},
            }
            label = f"Discord[{index}/{len(chunks)}]"
            ok = await _post_with_retries(
                client, self._config.webhook_url, json=payload, label=label
            )
            all_ok = all_ok and ok
        return all_ok


# =============================================================================
# Dispatcher
# =============================================================================
@dataclass(slots=True)
class DispatchResult:
    telegram: bool | None       # None = not configured
    discord: bool | None
    any_configured: bool
    all_succeeded: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "telegram": self.telegram,
            "discord": self.discord,
            "any_configured": self.any_configured,
            "all_succeeded": self.all_succeeded,
        }


class NotificationDispatcher:
    """
    Fan-out to all configured notification channels. Skips channels that
    are not configured, never raises, returns a structured result.
    """

    def __init__(self) -> None:
        tg_cfg = TelegramConfig.from_env()
        dc_cfg = DiscordConfig.from_env()
        self._telegram = TelegramNotifier(tg_cfg) if tg_cfg else None
        self._discord = DiscordNotifier(dc_cfg) if dc_cfg else None

        if self._telegram:
            logger.info("Telegram notifier: configured.")
        else:
            logger.info(
                "Telegram notifier: NOT configured (TELEGRAM_BOT_TOKEN or "
                "TELEGRAM_CHAT_ID missing) — channel disabled."
            )
        if self._discord:
            logger.info("Discord notifier: configured.")
        else:
            logger.info(
                "Discord notifier: NOT configured (DISCORD_WEBHOOK_URL "
                "missing) — channel disabled."
            )

    @property
    def has_any_channel(self) -> bool:
        return bool(self._telegram or self._discord)

    async def dispatch(self, markdown: str) -> DispatchResult:
        """
        Send ``markdown`` to every configured channel concurrently.
        """
        if not self.has_any_channel:
            logger.warning(
                "No notification channels configured — skipping dispatch."
            )
            return DispatchResult(
                telegram=None,
                discord=None,
                any_configured=False,
                all_succeeded=True,
            )

        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_S) as client:
            tasks: list[asyncio.Task[bool]] = []
            if self._telegram:
                tasks.append(asyncio.create_task(self._telegram.send(client, markdown)))
            if self._discord:
                tasks.append(asyncio.create_task(self._discord.send(client, markdown)))
            outcomes = await asyncio.gather(*tasks, return_exceptions=True)

        # Re-attribute results in declaration order (telegram, discord).
        idx = 0
        tg_ok: bool | None = None
        dc_ok: bool | None = None
        if self._telegram:
            tg_ok = bool(outcomes[idx]) if not isinstance(outcomes[idx], BaseException) else False
            if isinstance(outcomes[idx], BaseException):
                logger.error("Telegram dispatch raised: %s", outcomes[idx])
            idx += 1
        if self._discord:
            dc_ok = bool(outcomes[idx]) if not isinstance(outcomes[idx], BaseException) else False
            if isinstance(outcomes[idx], BaseException):
                logger.error("Discord dispatch raised: %s", outcomes[idx])
            idx += 1

        all_ok = (tg_ok is not False) and (dc_ok is not False)
        return DispatchResult(
            telegram=tg_ok,
            discord=dc_ok,
            any_configured=True,
            all_succeeded=all_ok,
        )
