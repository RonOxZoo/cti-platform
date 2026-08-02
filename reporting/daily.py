"""
Daily HTML intelligence report generator for the CTI platform.

Pulls the last 24 hours (or a specific calendar day) of enriched
`intelligence_items` from Supabase and renders a self-contained, dark-themed,
mobile-responsive HTML email report. The same HTML is used both for the Gmail
daily brief and the browser `/report/preview` endpoint.

Data model notes (see enrichment/gemini.py build_intelligence_payload):
- Structured indicators (iocs / cves / actors / mitre) live inside the
  `enrichment_data` jsonb column.
- `severity` casing is not guaranteed (Gemini emits "Critical" / "critical" /
  "CRITICAL"), so it is always normalized before comparison.
- CVSS scores are NOT stored by the enrichment path; the CVE spotlight shows
  per-day occurrence counts and renders CVSS as "—" unless a score happens to
  be present in enrichment_data.

Everything is best-effort: any query failure degrades to an empty section so a
report is always produced (a "quiet day" report when nothing is found).
"""
import html
import logging
from collections import Counter
from datetime import datetime, timezone, timedelta

from database.supabase_client import client
from utils.defang import defang_all

log = logging.getLogger(__name__)

# Columns pulled for the report. Explicit so we never select internal plumbing.
_ITEM_COLS = (
    "id, title_en, title_he, summary_en, summary_he, severity, "
    "confidence_score, categories, source_category, israel_relevance, "
    "iran_nexus, enrichment_data, processed_at"
)

# Bound on how many items a single report will pull.
_FETCH_LIMIT = 1000

# ── Theme ────────────────────────────────────────────────────
_BG = "#1a1a2e"
_PANEL = "#16213e"
_PANEL_ALT = "#0f3460"
_BORDER = "#2a2a4a"
_TEXT = "#e6e6e6"
_MUTED = "#9aa0b4"
_ACCENT = "#4d9fff"

_SEV_COLOR = {
    "critical": "#e74c3c",
    "high": "#ff9f43",
    "medium": "#f1c40f",
    "low": "#7f8fa6",
}


# ── Helpers ──────────────────────────────────────────────────
def _esc(value) -> str:
    """HTML-escape a value for safe inclusion in the report."""
    return html.escape(str(value if value is not None else ""))


def _esc_defang(value) -> str:
    """Defang IOCs then HTML-escape — for any value shown to a human (Pillar 7).

    Applied to IOC values and summaries so no live URL/IP/domain reaches the
    Gmail/preview output (http:// -> hxxp://, dots in hosts/IPs -> [.]).
    """
    return html.escape(defang_all(str(value if value is not None else "")))


def _norm_sev(severity) -> str:
    """Normalize a severity label to one of critical/high/medium/low/unknown."""
    s = (str(severity or "")).strip().lower()
    return s if s in _SEV_COLOR else "unknown"


def _sev_color(severity) -> str:
    return _SEV_COLOR.get(_norm_sev(severity), _MUTED)


def _source_of(item: dict) -> str:
    """Best-effort human label for an item's source."""
    return (
        item.get("source_category")
        or (item.get("categories") or [None])[0]
        or "Unknown"
    )


# Buckets inside enrichment_data['iocs'] that are not network/host indicators
# and so are excluded from the IOC summary table (malware_families has its own
# typed column and rendering).
_IOC_SKIP_BUCKETS = {"malware_families"}


def _iter_ioc_pairs(iocs: dict):
    """Yield (type, value) for every IOC in an enrichment_data['iocs'] dict.

    Handles both the flat buckets (ips/domains/urls/emails/c2_servers) and the
    nested hashes bucket ({"md5": [], "sha1": [], "sha256": []}). The bucket
    name (minus a trailing 's') is used as the IOC type label.
    """
    if not isinstance(iocs, dict):
        return
    for bucket, values in iocs.items():
        if bucket in _IOC_SKIP_BUCKETS:
            continue
        if isinstance(values, dict):
            # Nested bucket, e.g. hashes -> {md5: [...], sha1: [...], ...}.
            for sub, subvals in values.items():
                if isinstance(subvals, list):
                    for v in subvals:
                        if v:
                            yield str(sub), str(v)
        elif isinstance(values, list):
            label = str(bucket).rstrip("s") or str(bucket)
            for v in values:
                if v:
                    yield label, str(v)


def _day_bounds(date: str = None):
    """Return (start_iso, end_iso, label) for the report window.

    If `date` is None → rolling last 24 hours ending now.
    If `date` is "YYYY-MM-DD" → that full UTC calendar day.
    """
    if date:
        try:
            d = datetime.strptime(date.strip(), "%Y-%m-%d").replace(tzinfo=timezone.utc)
            start = d
            end = d + timedelta(days=1)
            return start.isoformat(), end.isoformat(), date.strip()
        except ValueError:
            log.warning(f"[REPORT] Bad date {date!r}; falling back to last 24h")
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=24)
    return start.isoformat(), now.isoformat(), now.strftime("%Y-%m-%d")


def _fetch_items(start_iso: str, end_iso: str) -> list:
    """Fetch enriched items processed within the window. Never raises."""
    try:
        result = (
            client.table("intelligence_items")
            .select(_ITEM_COLS)
            .gte("processed_at", start_iso)
            .lt("processed_at", end_iso)
            .order("processed_at", desc=True)
            .limit(_FETCH_LIMIT)
            .execute()
        )
        return result.data or []
    except Exception as e:
        log.error(f"[REPORT] _fetch_items failed: {e}")
        return []


def _fetch_source_health() -> list:
    """Active sources with error_count > 0, worst first. Best-effort -> []."""
    try:
        res = (client.table("rss_sources")
               .select("name, error_count, active")
               .gt("error_count", 0)
               .order("error_count", desc=True)
               .limit(50)
               .execute())
        return res.data or []
    except Exception as e:
        log.warning(f"[REPORT] source-health query unavailable: {str(e)[:120]}")
        return []


def _fetch_contradictions(start_iso: str, end_iso: str) -> list:
    """contradiction_checks rows created within the window. Best-effort -> []."""
    try:
        res = (client.table("contradiction_checks")
               .select("conflict_type, old_value, new_value, analyst_note, created_at")
               .gte("created_at", start_iso)
               .lt("created_at", end_iso)
               .order("created_at", desc=True)
               .limit(50)
               .execute())
        return res.data or []
    except Exception as e:
        log.warning(f"[REPORT] contradiction query unavailable: {str(e)[:120]}")
        return []


# ── HTML building blocks (all inline-styled for mail-client safety) ──
def _section(title: str, inner_html: str, *, accent: str = _ACCENT) -> str:
    """Wrap a section body in a titled, bordered panel."""
    return f"""
    <tr><td style="padding:0 20px 18px 20px;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0"
             style="background:{_PANEL};border:1px solid {_BORDER};border-radius:10px;">
        <tr><td style="padding:14px 18px 6px 18px;border-bottom:2px solid {accent};">
          <span style="font-size:16px;font-weight:700;color:{_TEXT};letter-spacing:.3px;">{title}</span>
        </td></tr>
        <tr><td style="padding:14px 18px 16px 18px;color:{_TEXT};font-size:14px;line-height:1.55;">
          {inner_html}
        </td></tr>
      </table>
    </td></tr>"""


def _event_card(item: dict, *, show_summary: bool = True, show_indicators: bool = False) -> str:
    """Render a single intelligence event as a left-bordered card."""
    sev = _norm_sev(item.get("severity"))
    color = _sev_color(sev)
    title = _esc(item.get("title_en") or item.get("title_he") or "(untitled)")
    source = _esc(_source_of(item))
    summary = _esc_defang((item.get("summary_en") or "").strip())

    indicators_html = ""
    if show_indicators:
        ed = item.get("enrichment_data") or {}
        iocs = [v for _, v in _iter_ioc_pairs(ed.get("iocs", {}))]
        cves = [str(c) for c in (ed.get("cves") or []) if c]
        actors = [str(a) for a in (ed.get("actors") or []) if a]
        rows = []
        if cves:
            rows.append(f'<div style="margin-top:6px;color:{_MUTED};font-size:12px;">'
                        f'<b style="color:{_TEXT};">CVEs:</b> {_esc(", ".join(cves[:12]))}</div>')
        if actors:
            rows.append(f'<div style="margin-top:4px;color:{_MUTED};font-size:12px;">'
                        f'<b style="color:{_TEXT};">Actors:</b> {_esc(", ".join(actors[:12]))}</div>')
        if iocs:
            rows.append(f'<div style="margin-top:4px;color:{_MUTED};font-size:12px;font-family:monospace;">'
                        f'<b style="color:{_TEXT};font-family:Arial,sans-serif;">IOCs:</b> '
                        f'{_esc_defang(", ".join(iocs[:10]))}</div>')
        indicators_html = "".join(rows)

    summary_html = ""
    if show_summary and summary:
        summary_html = f'<div style="margin-top:6px;color:{_TEXT};font-size:13px;line-height:1.5;">{summary}</div>'

    return f"""
    <div style="background:{_PANEL_ALT};border-left:4px solid {color};border-radius:6px;
                padding:10px 12px;margin-bottom:10px;">
      <div>
        <span style="display:inline-block;background:{color};color:#10101a;font-size:11px;
                     font-weight:700;padding:2px 8px;border-radius:10px;text-transform:uppercase;">{_esc(sev)}</span>
        <span style="color:{_MUTED};font-size:12px;margin-left:8px;">{source}</span>
      </div>
      <div style="margin-top:6px;font-size:14px;font-weight:600;color:{_TEXT};">{title}</div>
      {summary_html}
      {indicators_html}
    </div>"""


def _events_block(items: list, *, show_indicators: bool = False, empty: str = "No events.") -> str:
    if not items:
        return f'<span style="color:{_MUTED};">{empty}</span>'
    return "".join(_event_card(i, show_indicators=show_indicators) for i in items)


def _kv_chips(pairs) -> str:
    """Render [(label, value)] as a row of stat chips."""
    chips = []
    for label, value, color in pairs:
        chips.append(
            f'<td style="padding:4px;"><table role="presentation" cellpadding="0" cellspacing="0" '
            f'style="background:{_PANEL_ALT};border-radius:8px;"><tr>'
            f'<td style="padding:10px 14px;text-align:center;">'
            f'<div style="font-size:22px;font-weight:800;color:{color};">{_esc(value)}</div>'
            f'<div style="font-size:11px;color:{_MUTED};text-transform:uppercase;letter-spacing:.5px;">{_esc(label)}</div>'
            f'</td></tr></table></td>'
        )
    return ('<table role="presentation" cellpadding="0" cellspacing="0" width="100%"><tr>'
            + "".join(chips) + "</tr></table>")


def _table(headers: list, rows: list, *, empty: str = "Nothing to report.") -> str:
    """Render a simple dark-themed data table."""
    if not rows:
        return f'<span style="color:{_MUTED};">{empty}</span>'
    head = "".join(
        f'<th style="text-align:left;padding:8px 10px;font-size:12px;color:{_MUTED};'
        f'border-bottom:1px solid {_BORDER};text-transform:uppercase;letter-spacing:.5px;">{_esc(h)}</th>'
        for h in headers
    )
    body = []
    for row in rows:
        cells = "".join(
            f'<td style="padding:8px 10px;font-size:13px;color:{_TEXT};'
            f'border-bottom:1px solid {_BORDER};font-family:{"monospace" if mono else "Arial,sans-serif"};'
            f'word-break:break-all;">{_esc(c)}</td>'
            for c, mono in row
        )
        body.append(f"<tr>{cells}</tr>")
    return (f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
            f'style="border-collapse:collapse;">'
            f"<tr>{head}</tr>{''.join(body)}</table>")


# ── Report assembly ──────────────────────────────────────────
def _build_html(date_label: str, items: list, stats: dict) -> str:
    """Assemble the full HTML document from the day's items + computed stats."""
    gen_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Partition / aggregate.
    critical = [i for i in items if _norm_sev(i.get("severity")) == "critical"]
    high = [i for i in items if _norm_sev(i.get("severity")) == "high"]
    israel = [i for i in items if i.get("israel_relevance")]
    iran = [i for i in items if i.get("iran_nexus")]

    cve_counter = Counter()
    actor_counter = Counter()
    ioc_counter = Counter()
    ioc_types = {}
    he_summaries = []
    # Token-efficiency + language telemetry (from enrichment_data).
    total_tokens = 0
    total_cost = 0.0
    comp_sum = 0.0
    comp_n = 0
    engine_counter = Counter()
    lang_counter = Counter()
    for i in items:
        ed = i.get("enrichment_data") or {}
        for c in (ed.get("cves") or []):
            if c:
                cve_counter[str(c).strip()] += 1
        for a in (ed.get("actors") or []):
            if a:
                actor_counter[str(a).strip()] += 1
        for typ, val in _iter_ioc_pairs(ed.get("iocs", {})):
            ioc_counter[val] += 1
            ioc_types.setdefault(val, typ)
        he = (i.get("summary_he") or "").strip()
        if he:
            he_summaries.append((i.get("title_he") or i.get("title_en") or "", he))
        # Telemetry.
        total_tokens += int(ed.get("tokens_used") or 0)
        total_cost += float(ed.get("estimated_cost_usd") or 0.0)
        cr = ed.get("compression_ratio")
        if cr is not None:
            comp_sum += float(cr)
            comp_n += 1
        engine_counter[(ed.get("enriched_by") or "unknown").lower()] += 1
        lang_counter[(ed.get("detected_language") or "en").lower()] += 1

    avg_comp = round(comp_sum / comp_n, 1) if comp_n else 0.0
    items_skipped = stats.get("skipped", 0) or 0

    # ── Build sections ──────────────────────────────────────
    sections = []

    # Severity chip row (executive header continuation).
    sections.append(
        '<tr><td style="padding:0 20px 18px 20px;">'
        + _kv_chips([
            ("Total", stats["total"], _ACCENT),
            ("Critical", stats["critical"], _SEV_COLOR["critical"]),
            ("High", stats["high"], _SEV_COLOR["high"]),
            ("Medium", stats["medium"], _SEV_COLOR["medium"]),
            ("Low", stats["low"], _SEV_COLOR["low"]),
        ])
        + "</td></tr>"
    )

    if not items:
        sections.append(_section(
            "Quiet Day",
            f'<span style="color:{_MUTED};">No new enriched intelligence in this window. '
            f'All monitored sources were checked and produced no items meeting the reporting threshold.</span>',
        ))
    else:
        sections.append(_section(
            f"🔴 Critical Events ({len(critical)})",
            _events_block(critical, show_indicators=True, empty="No critical events today."),
            accent=_SEV_COLOR["critical"],
        ))
        sections.append(_section(
            f"🟠 High Severity Events ({len(high)})",
            _events_block(high, show_indicators=False, empty="No high-severity events today."),
            accent=_SEV_COLOR["high"],
        ))
        sections.append(_section(
            f"🇮🇱 Israel Cyber Events ({len(israel)})",
            _events_block(israel, show_indicators=True, empty="No Israel-relevant events today."),
        ))
        sections.append(_section(
            f"🌐 Iran Nexus Events ({len(iran)})",
            _events_block(iran, show_indicators=True, empty="No Iran-nexus events today."),
        ))

        # CVE spotlight — per-day occurrence; CVSS shown if present, else "—".
        cve_rows = []
        for cve, count in cve_counter.most_common(10):
            cve_rows.append([(cve, True), (str(count), False), ("—", False)])
        sections.append(_section(
            "🐛 CVE Spotlight",
            _table(["CVE", "Mentions", "CVSS"], cve_rows, empty="No CVEs referenced today."),
        ))

        # IOC summary — top 10 by occurrence count.
        ioc_rows = []
        for val, count in ioc_counter.most_common(10):
            # Defang the indicator before display (Pillar 7).
            ioc_rows.append([(ioc_types.get(val, "ioc"), False),
                             (defang_all(str(val)), True), (str(count), False)])
        sections.append(_section(
            "🔎 IOC Summary (Top 10)",
            _table(["Type", "Indicator", "Count"], ioc_rows, empty="No IOCs extracted today."),
        ))

        # Threat actor activity.
        actor_rows = [[(name, False), (str(count), False)] for name, count in actor_counter.most_common(15)]
        sections.append(_section(
            "👤 Threat Actor Activity",
            _table(["Actor", "Mentions"], actor_rows, empty="No threat actors mentioned today."),
        ))

        # Hebrew summary section (RTL).
        if he_summaries:
            he_html = "".join(
                f'<div dir="rtl" style="margin-bottom:12px;padding:10px 12px;background:{_PANEL_ALT};'
                f'border-radius:6px;text-align:right;">'
                f'<div style="font-weight:600;color:{_TEXT};font-size:14px;">{_esc(title)}</div>'
                f'<div style="margin-top:4px;color:{_TEXT};font-size:13px;line-height:1.6;">{_esc_defang(summary)}</div>'
                f'</div>'
                for title, summary in he_summaries
            )
            sections.append(
                '<tr><td style="padding:0 20px 18px 20px;">'
                f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
                f'style="background:{_PANEL};border:1px solid {_BORDER};border-radius:10px;">'
                f'<tr><td dir="rtl" style="padding:14px 18px 6px 18px;border-bottom:2px solid {_ACCENT};text-align:right;">'
                f'<span style="font-size:16px;font-weight:700;color:{_TEXT};">סיכום מודיעין (עברית)</span></td></tr>'
                f'<tr><td style="padding:14px 18px 16px 18px;">{he_html}</td></tr>'
                f'</table></td></tr>'
            )

    # ── A · Token-efficiency / compression stats ──
    engine_label = ", ".join(f"{k}:{v}" for k, v in engine_counter.most_common()) or "—"
    comp_rows = [
        [("Items enriched", False), (str(stats["total"]), False)],
        [("Avg compression", False), (f"{avg_comp}%", False)],
        [("Total tokens used", False), (f"{total_tokens:,}", False)],
        [("Estimated cost", False), (f"${total_cost:.4f}", False)],
        [("Items skipped (quota/error)", False), (str(items_skipped), False)],
        [("Engines", False), (engine_label, False)],
    ]
    sections.append(_section(
        "⚙️ Token Efficiency",
        _table(["Metric", "Value"], comp_rows, empty="No telemetry today."),
        accent=_MUTED,
    ))

    # ── B · Source health ──
    health = _fetch_source_health()
    health_rows = []
    for h in health:
        ec = h.get("error_count") or 0
        rec = "DISABLE (errors > 5)" if ec > 5 else "monitor"
        health_rows.append([(h.get("name") or "—", False), (str(ec), False), (rec, False)])
    sections.append(_section(
        f"🩺 Source Health ({len(health_rows)} with errors)",
        _table(["Source", "Errors", "Recommendation"], health_rows,
               empty="All sources healthy — no errors recorded."),
        accent=_SEV_COLOR["high"],
    ))

    # ── C · Contradiction alerts ──
    contras = _fetch_contradictions(stats.get("window_start", ""), stats.get("window_end", ""))
    if contras:
        contra_rows = []
        for c in contras:
            contra_rows.append([
                (c.get("conflict_type") or "—", False),
                (defang_all(str(c.get("old_value") or ""))[:60], False),
                (defang_all(str(c.get("new_value") or ""))[:60], False),
            ])
        contra_inner = _table(["Type", "OLD claim", "NEW claim"], contra_rows)
    else:
        contra_inner = f'<span style="color:{_MUTED};">No contradictions detected today.</span>'
    sections.append(_section(
        f"⚠️ Contradiction Alerts ({len(contras)})",
        contra_inner,
        accent=_SEV_COLOR["critical"],
    ))

    # ── D · Language distribution ──
    _LANG_LABEL = {"en": "English", "ru": "Russian (translated)",
                   "zh": "Chinese (translated)"}
    lang_rows = []
    for code, count in lang_counter.most_common():
        lang_rows.append([(_LANG_LABEL.get(code, f"Other ({code})"), False),
                          (str(count), False)])
    sections.append(_section(
        "🌍 Language Distribution",
        _table(["Language", "Items"], lang_rows, empty="No items."),
        accent=_ACCENT,
    ))

    sections_html = "".join(sections)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="color-scheme" content="dark">
<title>CTI Daily Brief — {_esc(date_label)}</title>
<style>
  @media only screen and (max-width:620px) {{
    .cti-container {{ width:100% !important; }}
    .cti-chip {{ display:inline-block !important; width:auto !important; }}
  }}
</style>
</head>
<body style="margin:0;padding:0;background:{_BG};
             font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;color:{_TEXT};">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:{_BG};">
    <tr><td align="center" style="padding:24px 8px;">
      <table role="presentation" class="cti-container" width="640" cellpadding="0" cellspacing="0"
             style="width:640px;max-width:640px;background:{_BG};border-radius:14px;overflow:hidden;">

        <!-- Executive header -->
        <tr><td style="padding:24px 20px 8px 20px;">
          <div style="font-size:13px;color:{_ACCENT};letter-spacing:2px;text-transform:uppercase;font-weight:700;">
            Cyber Threat Intelligence
          </div>
          <div style="font-size:26px;font-weight:800;color:{_TEXT};margin-top:4px;">CTI Daily Brief</div>
          <div style="font-size:14px;color:{_MUTED};margin-top:4px;">{_esc(date_label)} · {stats['total']} items</div>
        </td></tr>

        {sections_html}

        <!-- Footer -->
        <tr><td style="padding:16px 20px 28px 20px;border-top:1px solid {_BORDER};">
          <div style="font-size:12px;color:{_MUTED};line-height:1.6;">
            CTI Platform · automated intelligence report<br>
            Generated {_esc(gen_ts)}
          </div>
        </td></tr>

      </table>
    </td></tr>
  </table>
</body>
</html>"""


def _store(report_date: str, html_doc: str, stats: dict):
    """Upsert the report into daily_reports. Best-effort — never raises.

    The daily report was the only one not persisted: it was rendered, pushed to
    Telegram and discarded, so a missed message meant the day was simply gone
    while weekly and monthly kept full history.

    Upsert on report_date rather than insert, because the report is regenerated
    whenever /report/daily is called and a plain insert would stack duplicate
    rows for the same day.
    """
    payload = {
        "report_date": report_date,
        "report_html_en": html_doc,
        "summary_stats": stats,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "delivered_gmail": False,
        "delivered_telegram": True,
    }
    try:
        client.table("daily_reports").upsert(payload, on_conflict="report_date").execute()
        log.info(f"[REPORT] Stored daily report for {report_date}")
    except Exception as e:
        # A missing unique index on report_date, or a schema drift, must never
        # cost us the report that was already generated and delivered.
        log.error(f"[REPORT] _store failed (non-fatal): {str(e)[:200]}")


def generate_daily_report(date: str = None) -> dict:
    """Generate the daily HTML intelligence report.

    Queries the last 24 hours (or the given "YYYY-MM-DD" UTC day) of enriched
    intelligence_items and renders a dark-themed, mobile-responsive HTML report
    with severity breakdown, critical/high/Israel/Iran sections, CVE/IOC/actor
    tables, and a Hebrew (RTL) summary section. Always returns a report — a
    "quiet day" report when no items are found.

    Returns: {"html": "...", "stats": {...}, "items": [...]}

    The raw ``items`` are returned alongside the HTML so the Telegram daily
    brief (notifier.telegram.send_daily_summary) can render per-item lines
    without re-querying Supabase.
    """
    start_iso, end_iso, date_label = _day_bounds(date)
    items = _fetch_items(start_iso, end_iso)

    sev_counts = Counter(_norm_sev(i.get("severity")) for i in items)
    stats = {
        "date": date_label,
        "window_start": start_iso,
        "window_end": end_iso,
        "total": len(items),
        "critical": sev_counts.get("critical", 0),
        "high": sev_counts.get("high", 0),
        "medium": sev_counts.get("medium", 0),
        "low": sev_counts.get("low", 0),
        "israel": sum(1 for i in items if i.get("israel_relevance")),
        "iran_nexus": sum(1 for i in items if i.get("iran_nexus")),
    }

    html_doc = _build_html(date_label, items, stats)
    log.info(f"[REPORT] Daily report generated — {date_label} total={stats['total']} "
             f"critical={stats['critical']} high={stats['high']}")
    _store(date_label, html_doc, stats)
    return {"html": html_doc, "stats": stats, "items": items}
