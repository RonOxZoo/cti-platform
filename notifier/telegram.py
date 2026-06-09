"""
Telegram notification system for the CTI platform.

Talks to the Telegram Bot API directly via `requests` (no extra dependency).
All sends are best-effort: a failed notification is logged but never raised, so
the ingestion/enrichment pipeline can never be brought down by Telegram.

Security:
- The bot token is a secret — it is never logged and never returned to callers.
- The chat ID is never exposed in API responses.
- IOC hashes (and other indicators) are wrapped in <code> blocks so they render
  as inert monospace text rather than tappable/clickable links.
- Outbound messages are throttled to 1/second (Telegram API limit).
"""
import html
import time
import logging
import threading
from datetime import datetime, timezone

import requests

from config import TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID

log = logging.getLogger(__name__)

# Telegram hard limits.
_MAX_MESSAGE_LEN = 4096
_SEND_TIMEOUT = 15

# Rate limiting — at most one message per second across the whole process.
_MIN_SEND_INTERVAL = 1.0
_send_lock = threading.Lock()
_last_send_ts = 0.0


# ── Helpers ──────────────────────────────────────────────────
def _configured() -> bool:
    """True only if both the token and chat ID are present."""
    return bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)


def _esc(value) -> str:
    """HTML-escape a value for safe inclusion in an HTML-parse-mode message."""
    return html.escape(str(value if value is not None else ""))


def _code(value) -> str:
    """Wrap a value in an escaped <code> block (inert monospace, no auto-link)."""
    return f"<code>{_esc(value)}</code>"


def _code_list(values, empty: str = "None") -> str:
    """Render a list of indicators as comma-separated <code> blocks."""
    items = [v for v in (values or []) if v not in (None, "")]
    if not items:
        return _esc(empty)
    return ", ".join(_code(v) for v in items)


def _throttle():
    """Block until at least _MIN_SEND_INTERVAL has elapsed since the last send."""
    global _last_send_ts
    elapsed = time.time() - _last_send_ts
    if elapsed < _MIN_SEND_INTERVAL:
        time.sleep(_MIN_SEND_INTERVAL - elapsed)
    _last_send_ts = time.time()


def _now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


# ── Core send ────────────────────────────────────────────────
def send_message(text: str, parse_mode: str = "HTML") -> bool:
    """Send a simple text message to the CTI channel.

    Returns True on success, False on any failure or if Telegram is not
    configured. Never raises.
    """
    if not _configured():
        log.warning("[TELEGRAM] Not configured (token/chat ID missing) — skipping send")
        return False

    if not text:
        return False

    # Telegram rejects messages over 4096 chars.
    if len(text) > _MAX_MESSAGE_LEN:
        text = text[: _MAX_MESSAGE_LEN - 1] + "…"

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": text,
        "parse_mode": parse_mode,
        "disable_web_page_preview": True,
    }

    with _send_lock:
        _throttle()
        try:
            resp = requests.post(url, json=payload, timeout=_SEND_TIMEOUT)
            if resp.status_code == 200:
                return True
            # Never log resp.url / payload — they contain the token / chat ID.
            log.error(f"[TELEGRAM] Send failed — HTTP {resp.status_code}: {resp.text[:200]}")
            return False
        except Exception as e:
            log.error(f"[TELEGRAM] Send error: {str(e)[:200]}")
            return False


# ── Formatted notifications ──────────────────────────────────
def _severity_badge(severity: str) -> str:
    """Map a severity label to its emoji badge."""
    s = (severity or "").strip().lower()
    return {
        "critical": "🔴 CRITICAL",
        "high": "🟠 HIGH",
        "medium": "🟡 MEDIUM",
        "low": "⚪ LOW",
    }.get(s, f"⚪ {_esc(severity or 'UNKNOWN').upper()}")


def _first_or(value, default: str = "") -> str:
    """Return value if scalar/truthy, first element if a list, else default."""
    if isinstance(value, list):
        return value[0] if value else default
    return value if value not in (None, "") else default


def send_critical_alert(item: dict) -> bool:
    """Send a formatted critical/high severity alert."""
    item = item or {}

    severity = item.get("severity") or "Unknown"
    source = item.get("source") or item.get("source_name") or item.get("source_category") or "Unknown"
    title = item.get("title") or item.get("title_en") or "(untitled)"
    confidence = item.get("confidence")
    if confidence is None:
        confidence = item.get("confidence_score")
    category = _first_or(item.get("category") or item.get("categories"), "Uncategorized")
    summary = (item.get("summary_en") or "").strip()
    timestamp = item.get("timestamp") or item.get("processed_at") or _now_str()

    text = (
        f"{_severity_badge(severity)} — {_esc(str(source).upper())}\n\n"
        f"<b>{_esc(title)}</b>\n\n"
        f"📊 Severity: {_esc(severity)} | Confidence: {_esc(confidence if confidence is not None else 'N/A')}/100\n"
        f"🎯 Category: {_esc(category)}\n"
        f"👤 Actors: {_code_list(item.get('actors'), empty='Unknown')}\n"
        f"🔍 CVEs: {_code_list(item.get('cves'), empty='None')}\n"
        f"🛡 MITRE: {_code_list(item.get('mitre'), empty='N/A')}\n\n"
        f"📝 {_esc(summary[:300])}\n\n"
        f"⏰ {_esc(timestamp)}"
    )
    return send_message(text)


def _fmt_top(entries, empty: str = "—") -> str:
    """Format a top-N list. Accepts ['name', ...] or [{'value','count'}, ...]."""
    if not entries:
        return empty
    parts = []
    for e in entries:
        if isinstance(e, dict):
            val = e.get("value", "")
            cnt = e.get("count")
            parts.append(f"{_esc(val)} ({cnt})" if cnt is not None else _esc(val))
        else:
            parts.append(_esc(e))
    return ", ".join(parts) if parts else empty


def send_daily_summary(stats: dict) -> bool:
    """Send daily ingestion summary."""
    stats = stats or {}
    date = stats.get("date") or datetime.now(timezone.utc).strftime("%Y-%m-%d")

    text = (
        f"📡 <b>CTI Daily Brief</b> — {_esc(date)}\n\n"
        f"✅ Sources processed: {_esc(stats.get('sources_processed', 0))}\n"
        f"📥 Items ingested: {_esc(stats.get('items_ingested', 0))}\n"
        f"🤖 Items enriched: {_esc(stats.get('items_enriched', 0))}\n"
        f"🔴 Critical: {_esc(stats.get('critical', 0))} | "
        f"🟠 High: {_esc(stats.get('high', 0))} | "
        f"🟡 Medium: {_esc(stats.get('medium', 0))}\n\n"
        f"Top actors today: {_fmt_top(stats.get('top_actors'))}\n"
        f"Top CVEs today: {_code_list([e.get('value') if isinstance(e, dict) else e for e in (stats.get('top_cves') or [])], empty='—')}"
    )
    return send_message(text)


def send_weekly_summary(stats: dict) -> bool:
    """Send 5-day pattern analysis summary."""
    stats = stats or {}
    start = stats.get("start_date", "")
    end = stats.get("end_date", "")
    window = f"{_esc(start)} → {_esc(end)}" if start or end else "last 5 days"

    text = (
        f"📈 <b>CTI Weekly Pattern Analysis</b> — {window}\n\n"
        f"📥 Items ingested: {_esc(stats.get('items_ingested', 0))}\n"
        f"🤖 Items enriched: {_esc(stats.get('items_enriched', 0))}\n"
        f"🔴 Critical: {_esc(stats.get('critical', 0))} | "
        f"🟠 High: {_esc(stats.get('high', 0))} | "
        f"🟡 Medium: {_esc(stats.get('medium', 0))}\n\n"
        f"🔥 Trending actors: {_fmt_top(stats.get('top_actors'))}\n"
        f"🐛 Trending CVEs: {_code_list([e.get('value') if isinstance(e, dict) else e for e in (stats.get('top_cves') or [])], empty='—')}\n"
        f"📊 Top categories: {_fmt_top(stats.get('top_categories'))}"
    )
    return send_message(text)


def send_monthly_summary(stats: dict) -> bool:
    """Send a monthly strategic report summary."""
    stats = stats or {}
    month = stats.get("report_month", "")
    prev = stats.get("previous_month") or {}
    delta = (stats.get("total", 0) or 0) - (prev.get("total", 0) or 0)
    arrow = "📈" if delta > 0 else ("📉" if delta < 0 else "➡️")

    text = (
        f"🗓 <b>CTI Monthly Strategic Brief</b> — {_esc(month)}\n\n"
        f"📊 Items: {_esc(stats.get('total', 0))} {arrow} ({'+' if delta >= 0 else ''}{_esc(delta)} vs last month)\n"
        f"🔴 Critical: {_esc(stats.get('critical', 0))} | "
        f"🟠 High: {_esc(stats.get('high', 0))}\n"
        f"🇮🇱 Israel: {_esc(stats.get('israel', 0))} | "
        f"🌐 Iran nexus: {_esc(stats.get('iran_nexus', 0))}\n"
        f"📚 Weekly reports synthesised: {_esc(stats.get('weekly_reports', 0))}\n\n"
        f"🔥 Top actors: {_fmt_top(stats.get('top_actors'))}"
    )
    return send_message(text)


def notify_enrichment_complete(stats: dict) -> bool:
    """Send a notification when an enrichment batch completes.

    Only sends if at least one item succeeded.
    """
    stats = stats or {}
    succeeded = stats.get("succeeded", 0) or 0
    if succeeded <= 0:
        return False

    text = (
        f"🧠 <b>Enrichment Complete</b>\n"
        f"✅ {_esc(succeeded)} items processed\n"
        f"🔴 Critical: {_esc(stats.get('critical', 0))} | "
        f"🟠 High: {_esc(stats.get('high', 0))}"
    )
    return send_message(text)


def send_error_alert(service: str, error: str) -> bool:
    """Send an alert when a service fails."""
    text = (
        f"⚠️ <b>CTI Platform Error</b>\n"
        f"Service: {_esc(service)}\n"
        f"Error: {_esc(str(error)[:200])}\n"
        f"Time: {_esc(_now_str())}"
    )
    return send_message(text)
