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
import re
import html
import time
import logging
import threading
from datetime import datetime, timezone

import requests

from config import TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
from utils.defang import defang_all

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
    """Wrap an indicator in an escaped, DEFANGED <code> block.

    All <code>-wrapped values are IOC-ish (IPs/domains/hashes/actors/CVEs/MITRE);
    defanging neutralizes any live URL/IP/domain before it leaves the platform
    (Pillar 7). Non-IOC tokens (CVE ids, MITRE ids, actor names) are unaffected.
    """
    return f"<code>{_esc(defang_all(str(value if value is not None else '')))}</code>"


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


# Bold-header rendering — the spec format uses *…* to denote bold. We honour that
# visual intent with HTML <b> (parse_mode="HTML"), keeping the existing safe-
# escaping pipeline rather than switching to Telegram's fragile Markdown mode.
_SEP = "━━━━━━━━━━━━━━━"


def _split_5(text: str) -> list:
    """Split an expert summary into its 5 paragraphs (INCIDENT/ATTRIBUTION/
    EXECUTION/IMPACT/DEFENSE). Robust to a model that returned fewer blocks:
    pads to length 5 with '—' so every labelled line still renders."""
    text = (text or "").strip()
    if not text:
        return ["—"] * 5
    paras = [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]
    if len(paras) < 5:
        # Fall back to single-newline splitting, then pad.
        single = [p.strip() for p in text.split("\n") if p.strip()]
        if len(single) > len(paras):
            paras = single
    paras = (paras + ["—"] * 5)[:5]
    return paras


def _flatten_iocs(iocs: dict) -> list:
    """Flatten an enrichment iocs dict to a flat list of indicator values."""
    out = []
    if not isinstance(iocs, dict):
        return out
    for bucket, vals in iocs.items():
        if isinstance(vals, dict):           # hashes -> {md5:[],sha1:[],sha256:[]}
            for sub in vals.values():
                if isinstance(sub, list):
                    out.extend(str(v) for v in sub if v)
        elif isinstance(vals, list):
            out.extend(str(v) for v in vals if v)
    return out


def send_critical_alert(item: dict) -> bool:
    """Send a formatted CRITICAL THREAT ALERT (expert 5-section format).

    The 5 WHAT/WHO/HOW/IMPACT/DO-NOW lines map to the 5 paragraphs of the expert
    summary_en (INCIDENT/ATTRIBUTION/EXECUTION/IMPACT/DEFENSE)."""
    item = item or {}

    severity = item.get("severity") or "Unknown"
    source = item.get("source") or item.get("source_name") or item.get("source_category") or "Unknown"
    title = item.get("title") or item.get("title_en") or "(untitled)"
    confidence = item.get("confidence")
    if confidence is None:
        confidence = item.get("confidence_score")
    category = _first_or(item.get("category") or item.get("categories"), "Uncategorized")
    actor = _first_or(item.get("actors") or item.get("actor"), "Unknown")
    country = _first_or(item.get("country") or item.get("targeted_countries"), "Unknown")
    model = item.get("model") or "—"
    timestamp = item.get("timestamp") or item.get("processed_at") or _now_str()

    p1, p2, p3, p4, p5 = _split_5(item.get("summary_en") or "")
    iocs = _flatten_iocs(item.get("iocs") or {})
    techniques = item.get("mitre") or item.get("mitre_techniques") or item.get("techniques")

    text = (
        f"🔴 <b>CRITICAL THREAT ALERT</b>\n"
        f"{_SEP}\n"
        f"📋 <b>{_esc(title)}</b>\n"
        f"🏢 {_esc(source)} | 🎯 {_esc(category)} | 👤 {_esc(actor)} | 🌍 {_esc(country)}\n"
        f"📊 Severity: {_esc(severity)} | Confidence: "
        f"{_esc(confidence if confidence is not None else 'N/A')}%\n"
        f"{_SEP}\n"
        f"🔍 <b>WHAT:</b> {_esc(defang_all(p1))}\n"
        f"👤 <b>WHO:</b> {_esc(defang_all(p2))}\n"
        f"⚙️ <b>HOW:</b> {_esc(defang_all(p3))}\n"
        f"🎯 <b>IMPACT:</b> {_esc(defang_all(p4))}\n"
        f"🛡️ <b>DO NOW:</b> {_esc(defang_all(p5))}\n"
        f"{_SEP}\n"
        f"🔗 IOCs: {_code_list(iocs, empty='None')}\n"
        f"CVEs: {_code_list(item.get('cves'), empty='None')} | "
        f"MITRE: {_code_list(techniques, empty='N/A')}\n"
        f"⏰ {_esc(timestamp)} | 🤖 Claude {_esc(model)}"
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


# ── Daily brief (full, Telegram-only per routing policy) ─────
# Per-section caps keep the message under Telegram's 4096-char hard limit.
_DAILY_CRIT_CAP = 12
_DAILY_HIGH_CAP = 12
_DAILY_REGION_CAP = 10
# How many items get a written summary, in each language.
_DAILY_SUMMARY_CAP = 3
# Per-item, per-language excerpt length. The full expert summary is 5 paragraphs
# (~900 chars Hebrew / ~1300 English, up to ~4200), so printing whole summaries
# for 3 items in 2 languages would blow past Telegram's 4096-char hard limit.
# We show the opening paragraph (INCIDENT — what happened), cut to whole
# sentences, which is the "what this is about" line.
_DAILY_EXCERPT_CHARS = 300


def _trim_to_sentence(text: str, limit: int) -> str:
    """Trim `text` to at most `limit` chars WITHOUT cutting mid-sentence.

    Keeps as many complete sentences as fit, so the reader always gets a
    finished thought rather than a dangling "…". Only if the very first
    sentence alone exceeds the limit do we fall back to a word-boundary cut.
    """
    text = text.strip()
    if len(text) <= limit:
        return text

    # Walk sentence endings (. ! ? — same punctuation in Hebrew) and keep the
    # longest run of whole sentences that still fits.
    end = 0
    for i, ch in enumerate(text):
        if ch in ".!?" and (i + 1 >= len(text) or text[i + 1] in " \n"):
            if i + 1 <= limit:
                end = i + 1
            else:
                break
    if end:
        return text[:end].strip()

    # Single over-long sentence: cut on a word boundary so we at least never
    # split a word in half.
    cut = text[:limit].rsplit(" ", 1)[0].rstrip(" ,;:")
    return (cut or text[:limit].rstrip()) + "…"


def _excerpt(text: str, limit: int = _DAILY_EXCERPT_CHARS) -> str:
    """First paragraph of an expert summary, collapsed and sentence-trimmed."""
    first = " ".join(_split_5(text)[0].split())
    if first in ("", "—"):
        return ""
    return _trim_to_sentence(first, limit)


def _item_title(item: dict) -> str:
    return (item.get("title_en") or item.get("title_he")
            or item.get("title") or "(untitled)")


def _item_actor(item: dict) -> str:
    ed = item.get("enrichment_data") or {}
    return _first_or(ed.get("actors") or item.get("actors"), "")


def _item_cve(item: dict) -> str:
    ed = item.get("enrichment_data") or {}
    return _first_or(ed.get("cves") or item.get("cves"), "")


def _norm_sev(severity) -> str:
    s = (str(severity or "")).strip().lower()
    return s if s in ("critical", "high", "medium", "low") else "unknown"


def send_daily_summary(stats: dict) -> bool:
    """Send the FULL daily intelligence brief to Telegram.

    Routing policy: the daily brief goes to Telegram ONLY (never Gmail).

    Expects ``stats`` to carry an ``items`` list of intelligence_items rows
    (title_en/title_he, severity, israel_relevance, iran_nexus, summary_he and a
    nested enrichment_data with iocs/cves/actors). When ``items`` is absent it
    degrades to a compact counts-only brief so older callers still work."""
    stats = stats or {}
    date = stats.get("date") or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    items = stats.get("items")

    # ── Degraded fallback: no per-item data available ──
    if not items:
        text = (
            f"📡 <b>CTI DAILY BRIEF — {_esc(date)}</b>\n"
            f"{_SEP}\n"
            f"Total: {_esc(stats.get('total', stats.get('items_enriched', 0)))} | "
            f"🔴 {_esc(stats.get('critical', 0))} | "
            f"🟠 {_esc(stats.get('high', 0))} | "
            f"🟡 {_esc(stats.get('medium', 0))}\n"
            f"{_SEP}\n"
            f"🤖 CTI Platform"
        )
        return send_message(text)

    # ── Partition the day's items ──
    critical = [i for i in items if _norm_sev(i.get("severity")) == "critical"]
    high = [i for i in items if _norm_sev(i.get("severity")) == "high"]
    medium = [i for i in items if _norm_sev(i.get("severity")) == "medium"]
    israel = [i for i in items if i.get("israel_relevance")]
    iran = [i for i in items if i.get("iran_nexus")]

    # ── Aggregate IOCs / actors / CVEs across the day ──
    ioc_vals, actor_vals, cve_vals, model = [], [], [], None
    for i in items:
        ed = i.get("enrichment_data") or {}
        ioc_vals.extend(_flatten_iocs(ed.get("iocs") or {}))
        actor_vals.extend(str(a) for a in (ed.get("actors") or []) if a)
        cve_vals.extend(str(c) for c in (ed.get("cves") or []) if c)
        model = model or ed.get("model")

    # Dedupe preserving order.
    def _uniq(seq):
        seen, out = set(), []
        for v in seq:
            if v not in seen:
                seen.add(v)
                out.append(v)
        return out

    top_iocs = _uniq(ioc_vals)[:5]
    actors = _uniq(actor_vals)[:10]
    cves = _uniq(cve_vals)[:10]

    def _line_ta(i):  # title | actor | cve
        t, a, c = _item_title(i), _item_actor(i), _item_cve(i)
        bits = [f"<b>{_esc(t)}</b>"]
        if a:
            bits.append(_esc(a))
        if c:
            bits.append(_esc(c))
        return "• " + " | ".join(bits)

    def _line_t(i):  # title only
        return f"• {_esc(_item_title(i))}"

    parts = [
        f"📡 <b>CTI DAILY BRIEF — {_esc(date)}</b>",
        _SEP,
        (f"Total: {len(items)} | 🔴 {len(critical)} | "
         f"🟠 {len(high)} | 🟡 {len(medium)}"),
        _SEP,
    ]

    parts.append("🔴 <b>CRITICAL:</b>")
    parts.append("\n".join(_line_ta(i) for i in critical[:_DAILY_CRIT_CAP]) or "• None")

    parts.append("\n🟠 <b>HIGH:</b>")
    parts.append("\n".join(_line_ta(i) for i in high[:_DAILY_HIGH_CAP]) or "• None")

    if israel:
        parts.append("\n🇮🇱 <b>ISRAEL:</b>")
        parts.append("\n".join(_line_t(i) for i in israel[:_DAILY_REGION_CAP]))

    if iran:
        parts.append("\n🇮🇷 <b>IRAN NEXUS:</b>")
        parts.append("\n".join(_line_t(i) for i in iran[:_DAILY_REGION_CAP]))

    parts.append(_SEP)
    parts.append(f"🦠 <b>TOP IOCs:</b> {_code_list(top_iocs, empty='None')}")
    parts.append(f"👤 <b>ACTORS:</b> {_fmt_top(actors)}")
    parts.append(f"🔑 <b>CVEs:</b> {_code_list(cves, empty='None')}")

    # Bilingual summaries of the top items (critical first, then high, then rest).
    # Each bullet leads with the item's subject in English so the reader knows
    # what the entry is about before the body text, then the body in that
    # section's language.
    ranked = critical + high + medium + [
        i for i in items if i not in critical and i not in high and i not in medium
    ]
    he_bits, en_bits = [], []
    for i in ranked[:_DAILY_SUMMARY_CAP]:
        subject = _esc(_item_title(i))
        he = _excerpt(i.get("summary_he") or "")
        en = _excerpt(i.get("summary_en") or "")
        if he:
            he_bits.append(f"• <b>{subject}</b>\n{_esc(defang_all(he))}")
        if en:
            en_bits.append(f"• <b>{subject}</b>\n{_esc(defang_all(en))}")

    if he_bits:
        parts.append(_SEP)
        parts.append("🇮🇱 <b>סיכום בעברית:</b>")
        parts.append("\n\n".join(he_bits))

    if en_bits:
        parts.append(_SEP)
        parts.append("🇬🇧 <b>English Summary:</b>")
        parts.append("\n\n".join(en_bits))

    parts.append(_SEP)
    parts.append(f"🤖 CTI Platform | Claude {_esc(model or '—')}")

    return send_message("\n".join(parts))


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
