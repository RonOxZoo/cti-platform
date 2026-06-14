"""
Monthly strategic intelligence report generator for the CTI platform.

Synthesises the month: it pulls the `weekly_reports` produced during the month
plus the full month of enriched `intelligence_items`, asks Gemini to write a
strategic (CISO-level) narrative, renders a dark-themed HTML report, and stores
it in the `monthly_reports` table.

Reuses the weekly module's data aggregation and the daily module's HTML
building blocks so the three reports stay visually and statistically
consistent. Everything is best-effort — a report is always returned, with a
deterministic narrative fallback when Gemini is unavailable.

Returns: {"html", "stats"}.
"""
import json
import logging
from collections import Counter
from datetime import datetime, timezone

from database.supabase_client import client
from enrichment.gemini import _is_missing_column_error
from reporting.narrative import generate_narrative
from reporting.weekly import _fetch_window, _aggregate, _prior_actor_set, _prose
from reporting.daily import (
    _esc, _norm_sev, _section, _table, _kv_chips, _events_block,
    _BG, _PANEL, _BORDER, _TEXT, _MUTED, _ACCENT, _SEV_COLOR,
)

log = logging.getLogger(__name__)

_RANSOMWARE_TAGS = {"ransomware", "criminal", "data_breach"}
_INFRA_TAGS = {"ics", "critical_infrastructure", "energy", "telecom", "scada", "water"}


# ── Month bounds ─────────────────────────────────────────────
def _month_bounds(month: str = None):
    """Return (start, next_start, prev_start, label) datetimes (UTC).

    `month` is "YYYY-MM"; defaults to the current calendar month.
    """
    now = datetime.now(timezone.utc)
    year, mon = now.year, now.month
    if month:
        try:
            parsed = datetime.strptime(month.strip(), "%Y-%m")
            year, mon = parsed.year, parsed.month
        except ValueError:
            log.warning(f"[MONTHLY] bad month {month!r}; using current month")

    start = datetime(year, mon, 1, tzinfo=timezone.utc)
    next_start = datetime(year + (mon // 12), (mon % 12) + 1, 1, tzinfo=timezone.utc)
    prev_year, prev_mon = (year - 1, 12) if mon == 1 else (year, mon - 1)
    prev_start = datetime(prev_year, prev_mon, 1, tzinfo=timezone.utc)
    return start, next_start, prev_start, start.strftime("%Y-%m")


# ── Data ─────────────────────────────────────────────────────
def _fetch_weekly_reports(start_iso: str, next_iso: str) -> list:
    """Weekly reports whose window starts within the month. Best-effort."""
    try:
        result = (
            client.table("weekly_reports")
            .select("start_date, end_date, summary_stats, generated_at")
            .gte("start_date", start_iso[:10])
            .lt("start_date", next_iso[:10])
            .order("start_date", desc=False)
            .execute()
        )
        return result.data or []
    except Exception as e:
        log.error(f"[MONTHLY] _fetch_weekly_reports failed: {e}")
        return []


def _prev_month_totals(prev_start_iso: str, start_iso: str) -> dict:
    """Lightweight previous-month counts for month-over-month comparison."""
    def count(fn, default=0):
        try:
            return fn() or 0
        except Exception as e:
            log.warning(f"[MONTHLY] prev-month metric unavailable: {str(e)[:120]}")
            return default

    total = count(lambda: client.table("intelligence_items").select("id", count="exact")
                  .gte("processed_at", prev_start_iso).lt("processed_at", start_iso).execute().count)
    critical = count(lambda: client.table("intelligence_items").select("id", count="exact")
                     .in_("severity", ["critical", "Critical", "CRITICAL"])
                     .gte("processed_at", prev_start_iso).lt("processed_at", start_iso).execute().count)
    return {"total": total, "critical": critical}


# ── Gemini narrative ─────────────────────────────────────────
_MONTHLY_NARRATIVE_PROMPT = """You are the chief Cyber Threat Intelligence analyst at an Israeli security operations center.
Synthesise the WEEKLY reports and monthly statistics below into a STRATEGIC monthly report for a CISO / executive audience.
Be analytical and forward-looking. Base claims on the data; do not fabricate IOCs or attribution.
The executive summaries must be strategic and largely non-technical (~2 pages of substance).

OUTPUT — return ONLY valid JSON (no markdown, no preamble) with these string fields:
{
  "strategic_landscape": "the overall threat environment this month",
  "geopolitical_context": "geopolitical cyber context relevant to Israel and the region",
  "shifts_from_previous": "key shifts vs the previous month (use the comparison numbers)",
  "actor_analysis": "top threat actors of the month, activity levels/trends, new capabilities, attribution updates",
  "israel_summary": "monthly Israel-specific threat assessment, key incidents, and a trend verdict (escalating/stable/de-escalating)",
  "iran_analysis": "monthly Iran cyber activity assessment, specific campaigns, and comparison to the previous month",
  "cve_trends": "most exploited CVEs this month, patch-compliance guidance, zero-day activity",
  "ransomware_analysis": "active ransomware/criminal groups, targeted sectors, negotiation/payment trends",
  "infra_risk": "critical-infrastructure risk assessment by sector with specific incidents",
  "collection_assessment": "source quality this month, coverage gaps, recommended new sources",
  "executive_summary_en": "strategic executive summary for a CISO (multi-paragraph, non-technical)",
  "executive_summary_he": "identical executive summary in professional Hebrew"
}
"""


def _fallback_narrative(stats: dict, agg: dict, prev: dict) -> dict:
    top_actors = ", ".join(a for a, _ in agg["actor_counter"].most_common(5)) or "no notable actors"
    top_cves = ", ".join(c for c, _ in agg["cve_counter"].most_common(5)) or "no CVEs"
    delta = stats["total"] - prev.get("total", 0)
    trend = "an increase" if delta > 0 else ("a decrease" if delta < 0 else "no change")
    summary = (
        f"In {stats['report_month']} the platform enriched {stats['total']} items "
        f"({stats['critical']} critical, {stats['high']} high), {trend} of {abs(delta)} versus the "
        f"previous month ({prev.get('total', 0)}). Most active actors: {top_actors}. "
        f"Most referenced CVEs: {top_cves}. {stats['israel']} item(s) were Israel-relevant and "
        f"{stats['iran_nexus']} had an Iran nexus."
    )
    summary_he = (
        f"בחודש {stats['report_month']} הופקו {stats['total']} פריטי מודיעין "
        f"({stats['critical']} קריטיים). גורמי איום בולטים: {top_actors}. פרצות מובילות: {top_cves}."
    )
    return {
        "strategic_landscape": summary,
        "geopolitical_context": "Automated summary — narrative generation was unavailable this run.",
        "shifts_from_previous": f"Volume {trend} of {abs(delta)} items vs the previous month.",
        "actor_analysis": f"Most active actors: {top_actors}.",
        "israel_summary": f"{stats['israel']} Israel-relevant item(s); trend verdict unavailable.",
        "iran_analysis": f"{stats['iran_nexus']} Iran-nexus item(s) this month.",
        "cve_trends": f"Top CVEs: {top_cves}.",
        "ransomware_analysis": f"{len(agg.get('ransomware_items', []))} ransomware/criminal item(s) observed.",
        "infra_risk": f"{len(agg['infra_items'])} critical-infrastructure item(s) observed.",
        "collection_assessment": "Narrative generation unavailable; manual analyst review recommended.",
        "executive_summary_en": summary,
        "executive_summary_he": summary_he,
    }


def _gemini_narrative(stats: dict, agg: dict, prev: dict, weekly_rows: list) -> dict:
    weekly_ctx = [
        {"window": f"{w.get('start_date')}..{w.get('end_date')}",
         "stats": (w.get("summary_stats") or {})}
        for w in weekly_rows
    ]
    data = {
        "month": stats["report_month"],
        "totals": {k: stats[k] for k in ("total", "critical", "high", "medium", "low", "israel", "iran_nexus")},
        "previous_month": prev,
        "top_actors": agg["actor_counter"].most_common(10),
        "new_actors": agg["new_actors"],
        "top_cves": agg["cve_counter"].most_common(10),
        "top_mitre": agg["mitre_counter"].most_common(10),
        "top_sectors": agg["sector_counter"].most_common(10),
        "weekly_reports": weekly_ctx,
    }
    prompt = f"{_MONTHLY_NARRATIVE_PROMPT}\n\n=== MONTHLY DATA ===\n{json.dumps(data, ensure_ascii=False)[:14000]}\n"
    # Claude primary, Gemini fallback (PRIORITY ZERO); None -> deterministic.
    result = generate_narrative(prompt)
    if isinstance(result, dict) and result.get("executive_summary_en"):
        merged = _fallback_narrative(stats, agg, prev)
        merged.update({k: v for k, v in result.items() if v})
        return merged
    return _fallback_narrative(stats, agg, prev)


# ── HTML ─────────────────────────────────────────────────────
def _build_html(stats: dict, agg: dict, narrative: dict, weekly_rows: list) -> str:
    gen_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sections = []

    sections.append(
        '<tr><td style="padding:0 20px 18px 20px;">'
        + _kv_chips([
            ("Items", stats["total"], _ACCENT),
            ("Critical", stats["critical"], _SEV_COLOR["critical"]),
            ("High", stats["high"], _SEV_COLOR["high"]),
            ("Israel", stats["israel"], _ACCENT),
            ("Iran", stats["iran_nexus"], _SEV_COLOR["high"]),
            ("Weeks", len(weekly_rows), _MUTED),
        ])
        + "</td></tr>"
    )

    # 1. Strategic threat landscape.
    sections.append(_section(
        "1 · Strategic Threat Landscape",
        _prose(narrative.get("strategic_landscape"))
        + f'<div style="margin-top:10px;font-weight:600;color:{_ACCENT};">Geopolitical context</div>'
        + _prose(narrative.get("geopolitical_context"))
        + f'<div style="margin-top:10px;font-weight:600;color:{_ACCENT};">Shifts from previous month</div>'
        + _prose(narrative.get("shifts_from_previous")),
    ))

    # 2. Top threat actors of the month.
    actor_rows = [[(n, False), (str(c), False)] for n, c in agg["actor_counter"].most_common(20)]
    sections.append(_section(
        "2 · Top Threat Actors of the Month",
        _prose(narrative.get("actor_analysis"))
        + _table(["Actor", "Mentions"], actor_rows, empty="No actors observed."),
    ))

    # 3. Israel threat summary.
    sections.append(_section(
        f"3 · Israel Threat Summary ({len(agg['israel_items'])})",
        _prose(narrative.get("israel_summary"))
        + _events_block(agg["israel_items"][:15], show_indicators=True, empty="No Israel-relevant events."),
        accent=_ACCENT,
    ))

    # 4. Iran-Israel cyber conflict analysis.
    sections.append(_section(
        f"4 · Iran-Israel Cyber Conflict Analysis ({len(agg['iran_items'])})",
        _prose(narrative.get("iran_analysis"))
        + _events_block(agg["iran_items"][:15], show_indicators=True, empty="No Iran-nexus events."),
        accent=_SEV_COLOR["high"],
    ))

    # 5. CVE and vulnerability trends.
    cve_rows = [[(c, True), (str(n), False), ("—", False)] for c, n in agg["cve_counter"].most_common(20)]
    sections.append(_section(
        "5 · CVE & Vulnerability Trends",
        _prose(narrative.get("cve_trends"))
        + _table(["CVE", "Mentions", "CVSS"], cve_rows, empty="No CVEs referenced."),
    ))

    # 6. Ransomware & criminal activity.
    sections.append(_section(
        "6 · Ransomware & Criminal Activity",
        _prose(narrative.get("ransomware_analysis")),
    ))

    # 7. Critical infrastructure risk assessment.
    sector_rows = [[(s, False), (str(n), False)] for s, n in agg["sector_counter"].most_common(12)]
    sections.append(_section(
        f"7 · Critical Infrastructure Risk ({len(agg['infra_items'])})",
        _prose(narrative.get("infra_risk"))
        + f'<div style="margin:10px 0 4px 0;font-weight:600;color:{_ACCENT};">Targeted sectors</div>'
        + _table(["Sector", "Items"], sector_rows, empty="No targeted-sector data."),
        accent=_SEV_COLOR["critical"],
    ))

    # 8. Intelligence collection assessment.
    sections.append(_section(
        "8 · Intelligence Collection Assessment",
        _prose(narrative.get("collection_assessment")),
        accent=_MUTED,
    ))

    # 9. Executive summary (English).
    sections.append(_section(
        "9 · Executive Summary",
        _prose(narrative.get("executive_summary_en")),
        accent=_ACCENT,
    ))

    # 10. Executive summary (Hebrew, RTL).
    sections.append(
        '<tr><td style="padding:0 20px 18px 20px;">'
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        f'style="background:{_PANEL};border:1px solid {_BORDER};border-radius:10px;">'
        f'<tr><td dir="rtl" style="padding:14px 18px 6px 18px;border-bottom:2px solid {_ACCENT};text-align:right;">'
        f'<span style="font-size:16px;font-weight:700;color:{_TEXT};">10 · תקציר מנהלים (עברית)</span></td></tr>'
        f'<tr><td dir="rtl" style="padding:14px 18px 16px 18px;text-align:right;">'
        f'{_prose(narrative.get("executive_summary_he"))}</td></tr>'
        f'</table></td></tr>'
    )

    sections_html = "".join(sections)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="color-scheme" content="dark">
<title>CTI Monthly Strategic Brief — {_esc(stats['report_month'])}</title>
<style>
  @media only screen and (max-width:620px) {{ .cti-container {{ width:100% !important; }} }}
</style>
</head>
<body style="margin:0;padding:0;background:{_BG};
             font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;color:{_TEXT};">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:{_BG};">
    <tr><td align="center" style="padding:24px 8px;">
      <table role="presentation" class="cti-container" width="640" cellpadding="0" cellspacing="0"
             style="width:640px;max-width:640px;background:{_BG};border-radius:14px;overflow:hidden;">
        <tr><td style="padding:24px 20px 8px 20px;">
          <div style="font-size:13px;color:{_ACCENT};letter-spacing:2px;text-transform:uppercase;font-weight:700;">
            Cyber Threat Intelligence
          </div>
          <div style="font-size:26px;font-weight:800;color:{_TEXT};margin-top:4px;">Monthly Strategic Brief</div>
          <div style="font-size:14px;color:{_MUTED};margin-top:4px;">
            {_esc(stats['report_month'])} · {stats['total']} items · {len(weekly_rows)} weekly report(s)
          </div>
        </td></tr>
        {sections_html}
        <tr><td style="padding:16px 20px 28px 20px;border-top:1px solid {_BORDER};">
          <div style="font-size:12px;color:{_MUTED};line-height:1.6;">
            CTI Platform · automated monthly strategic report<br>
            Generated {_esc(gen_ts)}
          </div>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""


# ── Storage ──────────────────────────────────────────────────
def _store(stats: dict, html_en: str, narrative: dict):
    """Insert into monthly_reports. Best-effort — never raises."""
    payload = {
        # report_month is a date column — store the first of the month.
        "report_month": f"{stats['report_month']}-01",
        "report_html_en": html_en,
        "report_html_he": f'<div dir="rtl">{_prose(narrative.get("executive_summary_he"))}</div>',
        "executive_summary_en": narrative.get("executive_summary_en", ""),
        "executive_summary_he": narrative.get("executive_summary_he", ""),
        "strategic_trends": {
            "shifts_from_previous": narrative.get("shifts_from_previous"),
            "actor_analysis": narrative.get("actor_analysis"),
            "iran_analysis": narrative.get("iran_analysis"),
        },
        "summary_stats": stats,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "delivered_gmail": False,
    }
    try:
        client.table("monthly_reports").insert(payload).execute()
        log.info(f"[MONTHLY] Stored report {stats['report_month']}")
    except Exception as e:
        if _is_missing_column_error(e):
            log.warning("[MONTHLY] monthly_reports schema mismatch — storing minimal row.")
            try:
                client.table("monthly_reports").insert({
                    "report_month": f"{stats['report_month']}-01",
                    "summary_stats": stats,
                }).execute()
                return
            except Exception as e2:
                log.error(f"[MONTHLY] minimal store failed: {e2}")
        else:
            log.error(f"[MONTHLY] _store failed: {e}")


# ── Entry point ──────────────────────────────────────────────
def generate_monthly_report(month: str = None) -> dict:
    """Generate, render, and store the monthly strategic report.

    Returns: {"html", "stats"}.
    """
    start, next_start, prev_start, label = _month_bounds(month)
    start_iso, next_iso = start.isoformat(), next_start.isoformat()

    items = _fetch_window(start_iso, next_iso)
    prior_actors = _prior_actor_set(prev_start.isoformat(), start_iso)
    agg = _aggregate(items, prior_actors)
    # ransomware/criminal items for the dedicated section.
    agg["ransomware_items"] = [
        i for i in items
        if {str(t).lower() for t in (i.get("tags") or [])} & _RANSOMWARE_TAGS
    ]

    weekly_rows = _fetch_weekly_reports(start_iso, next_iso)
    prev = _prev_month_totals(prev_start.isoformat(), start_iso)

    sev = agg["severity"]
    stats = {
        "report_month": label,
        "total": len(items),
        "critical": sev.get("critical", 0),
        "high": sev.get("high", 0),
        "medium": sev.get("medium", 0),
        "low": sev.get("low", 0),
        "israel": len(agg["israel_items"]),
        "iran_nexus": len(agg["iran_items"]),
        "weekly_reports": len(weekly_rows),
        "previous_month": prev,
        "top_actors": agg["actor_counter"].most_common(10),
        "top_cves": agg["cve_counter"].most_common(10),
    }

    narrative = _gemini_narrative(stats, agg, prev, weekly_rows)
    html_en = _build_html(stats, agg, narrative, weekly_rows)
    _store(stats, html_en, narrative)

    log.info(f"[MONTHLY] Report generated — {label} total={stats['total']} "
             f"critical={stats['critical']} weeks={len(weekly_rows)}")
    return {"html": html_en, "stats": stats}
