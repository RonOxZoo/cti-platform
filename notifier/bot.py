"""
Interactive Telegram bot for browsing collected intelligence.

Button-driven navigation (inline keyboards + callback_query). Every tap EDITS
the existing message instead of sending a new one, so the chat stays clean.

Navigation is STATELESS: everything needed to render a view is encoded in the
callback_data (Telegram's hard limit is 64 bytes), and an item's position is
resolved by re-running the same deterministic ordered query. Nothing is stored
per user, so a restart — routine on Render's free tier — can never strand a
user mid-navigation or leave dead buttons behind.

Layers:
  0  dashboard — counts only, plus entry buttons
  1  list      — items of one severity (or the recommended set), paginated
  2  card      — one item's metadata, plus the language choice
  3  content   — the full summary in the chosen language

This module is additive: the existing push notifications in telegram.py are
untouched and keep working exactly as before.
"""
import logging
from datetime import datetime, timezone

import requests

from config import TELEGRAM_BOT_TOKEN
from database.supabase_client import client
from notifier.telegram import _esc, _split_5, _trim_to_sentence
from utils.defang import defang_all

log = logging.getLogger(__name__)

_API_TIMEOUT = 15
_MAX_MESSAGE_LEN = 4096
# Leave room for the metadata header we prepend to the body text.
_MAX_BODY_LEN = 3500


# ─────────────────────────────────────────────────────────────
# Recommendation scoring — CHANGE THIS BLOCK to retune 🟢 מומלץ
# ─────────────────────────────────────────────────────────────
# There is no CVSS field in the schema, so the score is built from the signals
# that DO exist. Every weight lives here; nothing else in the file hardcodes a
# ranking rule.
SEVERITY_POINTS = {"critical": 100, "high": 60, "medium": 30, "low": 10}
CONFIDENCE_WEIGHT = 0.5      # confidence_score is 0-100 -> up to 50 points
ISRAEL_BONUS = 25            # israel_relevance = true
IRAN_BONUS = 15              # iran_nexus = true
HAS_CVE_BONUS = 10           # at least one CVE in enrichment_data
FRESH_24H_BONUS = 30
FRESH_48H_BONUS = 15
# An item is flagged 🟢 מומלץ at or above this score. With the weights above a
# fresh critical item scores ~130+, a stale low-severity one ~15.
RECOMMENDED_THRESHOLD = 120
# ─────────────────────────────────────────────────────────────

PAGE_SIZE = 8
LIST_FETCH_LIMIT = 200

# Short codes keep callback_data well inside the 64-byte limit.
# Add "m": "medium" / "l": "low" here to expose those severities too.
SEVERITY_CODES = {"c": "critical", "h": "high"}
RECOMMENDED_CODE = "r"

_SEV_LABEL = {"critical": "🔴 Critical", "high": "🟠 High",
              "medium": "🟡 Medium", "low": "⚪ Low"}

_SELECT = (
    "id,title_en,title_he,summary_en,summary_he,severity,confidence_score,"
    "israel_relevance,iran_nexus,processed_at,enrichment_data,categories,"
    "source_category,raw_items(url)"
)

# Paragraph labels for the 5-part expert summary.
_LABELS_EN = ["🔍 WHAT", "👤 WHO", "⚙️ HOW", "🎯 IMPACT", "🛡️ DO NOW"]
_LABELS_HE = ["🔍 מה קרה", "👤 מי", "⚙️ איך", "🎯 השפעה", "🛡️ מה לעשות"]

# Right-to-left mark — prefixes Hebrew blocks so mixed Hebrew/English lines
# (CVE ids, product names) don't render in a jumbled order.
_RLM = "‏"


# ── Telegram API ─────────────────────────────────────────────
def _api(method: str, payload: dict) -> dict:
    """Call the Bot API. Returns the parsed response; never raises."""
    if not TELEGRAM_BOT_TOKEN:
        log.error("[BOT] TELEGRAM_BOT_TOKEN not configured")
        return {}
    try:
        resp = requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/{method}",
            json=payload, timeout=_API_TIMEOUT,
        )
        data = resp.json()
        if not data.get("ok"):
            # Never log the payload — it carries the chat ID.
            log.error(f"[BOT] {method} failed: {str(data.get('description'))[:200]}")
        return data
    except Exception as e:
        log.error(f"[BOT] {method} error: {str(e)[:200]}")
        return {}


def _answer_callback(callback_id: str, text: str = ""):
    """Always call this, or the client shows a stuck loading spinner."""
    _api("answerCallbackQuery", {"callback_query_id": callback_id, "text": text})


def _edit(chat_id, message_id, text: str, keyboard: list):
    _api("editMessageText", {
        "chat_id": chat_id, "message_id": message_id, "text": text,
        "parse_mode": "HTML", "disable_web_page_preview": True,
        "reply_markup": {"inline_keyboard": keyboard},
    })


def _send(chat_id, text: str, keyboard: list):
    _api("sendMessage", {
        "chat_id": chat_id, "text": text,
        "parse_mode": "HTML", "disable_web_page_preview": True,
        "reply_markup": {"inline_keyboard": keyboard},
    })


# ── Data layer ───────────────────────────────────────────────
def _score(item: dict) -> float:
    """Weighted recommendation score. Tune via the constants block above."""
    score = float(SEVERITY_POINTS.get((item.get("severity") or "").lower(), 0))
    score += (item.get("confidence_score") or 0) * CONFIDENCE_WEIGHT
    if item.get("israel_relevance"):
        score += ISRAEL_BONUS
    if item.get("iran_nexus"):
        score += IRAN_BONUS
    ed = item.get("enrichment_data") or {}
    if ed.get("cves"):
        score += HAS_CVE_BONUS

    processed = item.get("processed_at")
    if processed:
        try:
            ts = datetime.fromisoformat(str(processed).replace("Z", "+00:00"))
            age_h = (datetime.now(timezone.utc) - ts).total_seconds() / 3600
            if age_h < 24:
                score += FRESH_24H_BONUS
            elif age_h < 48:
                score += FRESH_48H_BONUS
        except (ValueError, TypeError):
            pass
    return score


def _fetch(severity: str = None) -> list:
    """Fetch items (one severity, or all for the recommended view), scored and
    sorted. Sort is deterministic so stateless index lookups stay stable.

    Only list/card fields are selected here — the full summaries come along
    because a single item lookup would otherwise need a second round trip, and
    these lists are small (tens of rows, not thousands).
    """
    try:
        q = client.table("intelligence_items").select(_SELECT)
        if severity:
            q = q.eq("severity", severity)
        else:
            # Recommended view: only severities worth surfacing.
            q = q.in_("severity", ["critical", "high", "medium"])
        rows = q.order("processed_at", desc=True).limit(LIST_FETCH_LIMIT).execute().data or []
    except Exception as e:
        log.error(f"[BOT] fetch(severity={severity}) failed: {str(e)[:200]}")
        return []

    for r in rows:
        r["_score"] = _score(r)
    # Sort by score, then recency — ties broken by id so ordering is total and
    # repeatable across calls (stateless index resolution depends on this).
    rows.sort(key=lambda r: (-r["_score"], str(r.get("processed_at") or ""), str(r.get("id"))))
    return rows


def _items_for(code: str) -> list:
    """Resolve a severity code to its ordered item list."""
    if code == RECOMMENDED_CODE:
        return [r for r in _fetch(None) if r["_score"] >= RECOMMENDED_THRESHOLD]
    return _fetch(SEVERITY_CODES.get(code))


def _counts() -> dict:
    """Dashboard counts. One query per severity, plus the recommended set."""
    out = {}
    for code, sev in SEVERITY_CODES.items():
        try:
            out[code] = (client.table("intelligence_items")
                         .select("id", count="exact")
                         .eq("severity", sev).execute().count) or 0
        except Exception as e:
            log.error(f"[BOT] count({sev}) failed: {str(e)[:200]}")
            out[code] = 0
    out[RECOMMENDED_CODE] = len(_items_for(RECOMMENDED_CODE))
    return out


# ── Rendering ────────────────────────────────────────────────
def _title(item: dict) -> str:
    """Item subject. title_he is not populated by the enrichment pipeline, so
    this is English in practice — which suits CTI, where CVE ids, product and
    actor names are English anyway."""
    return (item.get("title_en") or item.get("title_he") or "(untitled)").strip()


def _short_title(item: dict, limit: int = 40) -> str:
    """Button label — Telegram truncates long labels unhelpfully, so trim here."""
    mark = "🟢 " if item["_score"] >= RECOMMENDED_THRESHOLD else ""
    t = _title(item)
    if len(t) > limit:
        t = t[: limit - 1].rstrip() + "…"
    return f"{mark}{t}"


def _date_of(item: dict) -> str:
    raw = item.get("processed_at")
    if not raw:
        return "—"
    try:
        ts = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        return ts.strftime("%Y-%m-%d %H:%M UTC")
    except (ValueError, TypeError):
        return str(raw)[:16]


def _source_url(item: dict) -> str:
    raw = item.get("raw_items") or {}
    if isinstance(raw, list):
        raw = raw[0] if raw else {}
    return (raw.get("url") or "").strip()


def render_dashboard() -> tuple:
    counts = _counts()
    text = (
        "🛡 <b>CTI Intelligence</b>\n"
        "━━━━━━━━━━━━━━━\n"
        f"🔴 Critical ({counts.get('c', 0)}) · 🟠 High ({counts.get('h', 0)})\n"
        f"🟢 מומלצים ({counts.get(RECOMMENDED_CODE, 0)})\n"
        "━━━━━━━━━━━━━━━\n"
        "בחר קטגוריה להצגת האירועים 👇"
    )
    kb = [
        [{"text": f"🔴 Critical ({counts.get('c', 0)})", "callback_data": "l:c:0"},
         {"text": f"🟠 High ({counts.get('h', 0)})", "callback_data": "l:h:0"}],
        [{"text": f"🟢 מומלצים ({counts.get(RECOMMENDED_CODE, 0)})",
          "callback_data": f"l:{RECOMMENDED_CODE}:0"}],
    ]
    return text, kb


def render_list(code: str, page: int) -> tuple:
    items = _items_for(code)
    if not items:
        return ("✅ אין כרגע אירועים ברמה זו.",
                [[{"text": "⬅️ חזרה", "callback_data": "h"}]])

    pages = max(1, (len(items) + PAGE_SIZE - 1) // PAGE_SIZE)
    page = max(0, min(page, pages - 1))
    start = page * PAGE_SIZE
    chunk = items[start:start + PAGE_SIZE]

    heading = {"c": "🔴 Critical", "h": "🟠 High"}.get(code, "🟢 מומלצים")
    text = (
        f"<b>{heading}</b> — {len(items)} אירועים\n"
        "━━━━━━━━━━━━━━━\n"
        f"עמוד {page + 1}/{pages}\n"
        "🟢 = מומלץ"
    )

    kb = [[{"text": _short_title(it), "callback_data": f"i:{code}:{page}:{start + idx}"}]
          for idx, it in enumerate(chunk)]

    nav = []
    if page > 0:
        nav.append({"text": "⬅️", "callback_data": f"l:{code}:{page - 1}"})
    if pages > 1:
        nav.append({"text": f"{page + 1}/{pages}", "callback_data": "x"})
    if page < pages - 1:
        nav.append({"text": "➡️", "callback_data": f"l:{code}:{page + 1}"})
    if nav:
        kb.append(nav)
    kb.append([{"text": "🏠 תפריט ראשי", "callback_data": "h"}])
    return text, kb


def render_card(code: str, page: int, idx: int) -> tuple:
    items = _items_for(code)
    if idx >= len(items):
        return ("⚠️ האירוע לא נמצא — ייתכן שהרשימה התעדכנה.",
                [[{"text": "⬅️ חזרה", "callback_data": f"l:{code}:{page}"}]])

    item = items[idx]
    ed = item.get("enrichment_data") or {}
    sev = (item.get("severity") or "").lower()
    rec = "🟢 <b>מומלץ</b>\n" if item["_score"] >= RECOMMENDED_THRESHOLD else ""

    tags = []
    for cve in (ed.get("cves") or [])[:3]:
        tags.append(f"<code>{_esc(cve)}</code>")
    for actor in (ed.get("actors") or [])[:2]:
        tags.append(f"<code>{_esc(defang_all(str(actor)))}</code>")

    lines = [
        rec,
        f"📋 <b>{_esc(_title(item))}</b>",
        "━━━━━━━━━━━━━━━",
        f"📊 {_SEV_LABEL.get(sev, sev)} · Confidence: {item.get('confidence_score', '—')}%",
        f"📅 {_date_of(item)}",
    ]
    if item.get("source_category"):
        lines.append(f"🏢 {_esc(item['source_category'])}")
    if tags:
        lines.append(f"🏷 {' · '.join(tags)}")
    flags = []
    if item.get("israel_relevance"):
        flags.append("🇮🇱 Israel")
    if item.get("iran_nexus"):
        flags.append("🇮🇷 Iran nexus")
    if flags:
        lines.append(" · ".join(flags))
    lines += ["━━━━━━━━━━━━━━━", "בחר שפה לקריאת הדוח המלא 👇"]

    kb = [
        [{"text": "🇮🇱 עברית", "callback_data": f"v:{code}:{page}:{idx}:he"},
         {"text": "🇬🇧 English", "callback_data": f"v:{code}:{page}:{idx}:en"}],
        [{"text": "⬅️ חזרה", "callback_data": f"l:{code}:{page}"},
         {"text": "🏠 ראשי", "callback_data": "h"}],
    ]
    return "\n".join(x for x in lines if x), kb


def render_content(code: str, page: int, idx: int, lang: str) -> tuple:
    items = _items_for(code)
    if idx >= len(items):
        return ("⚠️ האירוע לא נמצא — ייתכן שהרשימה התעדכנה.",
                [[{"text": "⬅️ חזרה", "callback_data": f"l:{code}:{page}"}]])

    item = items[idx]
    other = "en" if lang == "he" else "he"
    summary = (item.get(f"summary_{lang}") or "").strip()

    if not summary:
        # Missing translation — offer the language we do have rather than
        # showing an empty screen.
        alt = (item.get(f"summary_{other}") or "").strip()
        note = ("⚠️ אין תרגום לעברית לאירוע זה."
                if lang == "he" else "⚠️ No English text for this item.")
        kb = [[{"text": "🇬🇧 English" if lang == "he" else "🇮🇱 עברית",
                "callback_data": f"v:{code}:{page}:{idx}:{other}"}]] if alt else []
        kb.append([{"text": "⬅️ חזרה", "callback_data": f"i:{code}:{page}:{idx}"},
                   {"text": "🏠 ראשי", "callback_data": "h"}])
        return note, kb

    labels = _LABELS_HE if lang == "he" else _LABELS_EN
    paras = _split_5(summary)
    body_lines = []
    for label, para in zip(labels, paras):
        if para and para != "—":
            prefix = _RLM if lang == "he" else ""
            body_lines.append(f"{label}: {prefix}{_esc(defang_all(para))}")
    body = "\n\n".join(body_lines)
    if len(body) > _MAX_BODY_LEN:
        body = _trim_to_sentence(body, _MAX_BODY_LEN)

    header = (
        f"📋 <b>{_esc(_title(item))}</b>\n"
        f"📊 {_SEV_LABEL.get((item.get('severity') or '').lower(), '')} · {_date_of(item)}\n"
        "━━━━━━━━━━━━━━━\n"
    )
    text = header + body
    if len(text) > _MAX_MESSAGE_LEN:
        text = text[: _MAX_MESSAGE_LEN - 1] + "…"

    kb = [[{"text": "🇬🇧 English" if lang == "he" else "🇮🇱 עברית",
            "callback_data": f"v:{code}:{page}:{idx}:{other}"}]]
    url = _source_url(item)
    if url.startswith(("http://", "https://")):
        kb.append([{"text": "🔗 קרא בכתבה המקורית", "url": url}])
    kb.append([{"text": "⬅️ חזרה לרשימה", "callback_data": f"l:{code}:{page}"},
               {"text": "🏠 ראשי", "callback_data": "h"}])
    return text, kb


# ── Routing ──────────────────────────────────────────────────
# Recently-handled callback ids. Telegram retries deliveries, and an impatient
# double-tap sends two updates; both would otherwise re-render the same view.
_seen_callbacks = []
_SEEN_MAX = 200


def _already_handled(callback_id: str) -> bool:
    if callback_id in _seen_callbacks:
        return True
    _seen_callbacks.append(callback_id)
    if len(_seen_callbacks) > _SEEN_MAX:
        del _seen_callbacks[: len(_seen_callbacks) - _SEEN_MAX]
    return False


def _route(data: str) -> tuple:
    """Map callback_data to a rendered (text, keyboard). Returns None for no-op."""
    parts = data.split(":")
    kind = parts[0]

    if kind == "x":                                   # page counter — inert
        return None
    if kind == "h":
        return render_dashboard()
    if kind == "l" and len(parts) == 3:
        return render_list(parts[1], int(parts[2]))
    if kind == "i" and len(parts) == 4:
        return render_card(parts[1], int(parts[2]), int(parts[3]))
    if kind == "v" and len(parts) == 5:
        return render_content(parts[1], int(parts[2]), int(parts[3]), parts[4])

    log.warning(f"[BOT] unroutable callback_data: {data[:64]}")
    return render_dashboard()


def handle_update(update: dict) -> None:
    """Entry point for a Telegram webhook update. Never raises."""
    try:
        if "callback_query" in update:
            cb = update["callback_query"]
            cb_id = cb.get("id", "")
            data = cb.get("data", "")
            msg = cb.get("message") or {}
            chat_id = (msg.get("chat") or {}).get("id")
            message_id = msg.get("message_id")

            log.info(f"[BOT] callback data={data[:32]}")

            if _already_handled(cb_id):
                _answer_callback(cb_id)
                return

            rendered = _route(data)
            _answer_callback(cb_id)
            if rendered and chat_id and message_id:
                text, kb = rendered
                _edit(chat_id, message_id, text, kb)
            return

        message = update.get("message") or {}
        text = (message.get("text") or "").strip()
        chat_id = (message.get("chat") or {}).get("id")
        if not chat_id:
            return

        if text.startswith("/start") or text.startswith("/menu"):
            log.info(f"[BOT] command {text[:16]}")
            body, kb = render_dashboard()
            _send(chat_id, body, kb)
        elif text.startswith("/help"):
            _send(chat_id,
                  "🛡 <b>CTI Bot</b>\n\n"
                  "/start — פתיחת התפריט\n"
                  "/menu — אותו דבר\n\n"
                  "כל הניווט מתבצע בכפתורים.", [])
    except Exception as e:
        # A crash here would make Telegram retry the same update forever.
        log.error(f"[BOT] handle_update failed: {str(e)[:300]}", exc_info=True)
