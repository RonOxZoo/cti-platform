"""
Weekly intelligence report generator for the CTI platform.

Pulls the last N days (default 7) of enriched `intelligence_items` from
Supabase, computes the statistics, asks Gemini to write the narrative sections
(executive summary, actor / Israel / Iran / CVE / phishing / infra analysis,
intelligence gaps), and renders a dark-themed, mobile-responsive HTML report.
The result is stored in the `weekly_reports` table.

Design:
- All hard numbers (counts, top actors/CVEs/IOCs/MITRE) come from Supabase.
- All prose comes from Gemini, with a deterministic fallback so a quota
  exhaustion never produces an empty report.
- Theme + HTML building blocks are reused from reporting/daily.py so the daily
  and weekly briefs look consistent.
- Everything is best-effort: any failure degrades gracefully and a report is
  always returned.

Returns: {"html", "stats", "summary_en", "summary_he"}.
"""
import json
import logging
from collections import Counter
from datetime import datetime, timezone, timedelta

from database.supabase_client import client
from enrichment.gemini import call_gemini, _is_rate_limit_error, _is_missing_column_error
from reporting.daily import (
    _esc, _norm_sev, _source_of, _iter_ioc_pairs,
    _section, _table, _kv_chips, _events_block,
    _ITEM_COLS, _FETCH_LIMIT,
    _BG, _PANEL, _PANEL_ALT, _BORDER, _TEXT, _MUTED, _ACCENT, _SEV_COLOR,
)

log = logging.getLogger(__name__)

# Categories / tags that mark critical-infrastructure relevance.
_INFRA_TAGS = {"ics", "critical_infrastructure", "energy", "telecom", "scada", "water"}
_PHISHING_TAGS = {"phishing", "criminal"}


# ── Data ─────────────────────────────────────────────────────
def _fetch_window(start_iso: str, end_iso: str) -> list:
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
        log.error(f"[WEEKLY] _fetch_window failed: {e}")
        return []


def _prior_actor_set(prior_start_iso: str, start_iso: str) -> set:
    """Actor names seen in the previous comparable window (for 'new actors').

    Bounded, best-effort — returns an empty set on any error.
    """
    seen = set()
    try:
        result = (
            client.table("intelligence_items")
            .select("enrichment_data, processed_at")
            .gte("processed_at", prior_start_iso)
            .lt("processed_at", start_iso)
            .limit(_FETCH_LIMIT)
            .execute()
        )
        for row in (result.data or []):
            ed = row.get("enrichment_data") or {}
            for a in (ed.get("actors") or []):
                if a:
                    seen.add(str(a).strip().lower())
    except Exception as e:
        log.error(f"[WEEKLY] _prior_actor_set failed: {e}")
    return seen


def _quota_days(start_iso: str, end_iso: str) -> list:
    """UTC dates in the window where the Gemini enrichment quota was hit.

    Reads ingestion_logs rows written by enrichment/gemini.py with
    scenario_name='python_gemini_enrichment' and status='quota_exceeded'.
    Best-effort -> [].
    """
    from enrichment.gemini import ENRICHMENT_SCENARIO
    days = set()
    try:
        res = (client.table("ingestion_logs")
               .select("started_at, status, scenario_name")
               .eq("scenario_name", ENRICHMENT_SCENARIO)
               .eq("status", "quota_exceeded")
               .gte("started_at", start_iso)
               .lt("started_at", end_iso)
               .limit(200)
               .execute())
        for row in (res.data or []):
            ts = str(row.get("started_at") or "")[:10]
            if ts:
                days.add(ts)
    except Exception as e:
        log.warning(f"[WEEKLY] quota-days query unavailable: {str(e)[:120]}")
    return sorted(days)


def _tags_of(item: dict) -> list:
    """All lowercased tags + categories for an item."""
    out = [str(t).strip().lower() for t in (item.get("tags") or []) if t]
    out += [str(c).strip().lower() for c in (item.get("categories") or []) if c]
    return out


def _aggregate(items: list, prior_actors: set) -> dict:
    """Compute every statistic the report needs from the fetched items."""
    sev = Counter(_norm_sev(i.get("severity")) for i in items)
    cve_c, actor_c, ioc_c, mitre_c, sector_c = Counter(), Counter(), Counter(), Counter(), Counter()
    engine_c = Counter()
    tokens_total = 0
    ioc_types = {}

    for i in items:
        ed = i.get("enrichment_data") or {}
        engine_c[(ed.get("enriched_by") or "unknown").lower()] += 1
        tokens_total += int(ed.get("tokens_used") or 0)
        for c in (ed.get("cves") or []):
            if c:
                cve_c[str(c).strip()] += 1
        for a in (ed.get("actors") or []):
            if a:
                actor_c[str(a).strip()] += 1
        for m in (ed.get("mitre") or []):
            if m:
                mitre_c[str(m).strip()] += 1
        for typ, val in _iter_ioc_pairs(ed.get("iocs", {})):
            ioc_c[val] += 1
            ioc_types.setdefault(val, typ)
        for s in (i.get("targeted_sectors") or []):
            if s:
                sector_c[str(s).strip()] += 1

    seen_actors = {a.lower() for a in actor_c}
    new_actors = sorted(a for a in seen_actors if a not in prior_actors)

    return {
        "severity": sev,
        "cve_counter": cve_c,
        "actor_counter": actor_c,
        "ioc_counter": ioc_c,
        "ioc_types": ioc_types,
        "mitre_counter": mitre_c,
        "sector_counter": sector_c,
        "engine_counter": engine_c,
        "tokens_total": tokens_total,
        "new_actors": new_actors[:15],
        "israel_items": [i for i in items if i.get("israel_relevance")],
        "iran_items": [i for i in items if i.get("iran_nexus")],
        "phishing_items": [i for i in items if set(_tags_of(i)) & _PHISHING_TAGS],
        "infra_items": [i for i in items if set(_tags_of(i)) & _INFRA_TAGS],
    }


# ── Gemini narrative ─────────────────────────────────────────
_WEEKLY_NARRATIVE_PROMPT = """You are a senior Cyber Threat Intelligence analyst at an Israeli security operations center.
Write the narrative sections of a WEEKLY intelligence report from the structured data below.
Be specific, professional, and analytical. Base every statement on the data provided — do not invent IOCs or attribution.

OUTPUT — return ONLY valid JSON (no markdown, no preamble) with these string fields:
{
  "executive_summary_en": "4-6 sentences: overall threat landscape this week, key trends, most significant events",
  "executive_summary_he": "identical executive summary in professional Hebrew",
  "key_trends": "2-4 sentences on patterns/trends observed",
  "actor_analysis": "2-4 sentences: which actors were most active, new actors, notable TTPs",
  "israel_assessment": "2-4 sentences on the Israel cyber situation + threat level (low/elevated/high) + recommended actions",
  "iran_assessment": "2-4 sentences on Iran-Israel nexus activity + an escalation verdict (escalating/stable/de-escalating)",
  "cve_analysis": "2-3 sentences on top CVEs, exploitation status, and patch guidance",
  "phishing_analysis": "1-3 sentences on phishing/criminal campaign activity and targeted sectors",
  "infra_analysis": "1-3 sentences on critical-infrastructure / ICS threats",
  "intelligence_gaps": "2-4 sentences: what we don't know and which additional sources are recommended"
}
"""


def _fallback_narrative(stats: dict, agg: dict) -> dict:
    """Deterministic narrative used when Gemini is unavailable (quota/error)."""
    top_actors = ", ".join(a for a, _ in agg["actor_counter"].most_common(5)) or "no notable actors"
    top_cves = ", ".join(c for c, _ in agg["cve_counter"].most_common(5)) or "no CVEs"
    base = (
        f"During {stats['start_date']} → {stats['end_date']} the platform enriched "
        f"{stats['total']} items ({stats['critical']} critical, {stats['high']} high, "
        f"{stats['medium']} medium). Most active actors: {top_actors}. "
        f"Most referenced CVEs: {top_cves}. "
        f"{stats['israel']} item(s) were Israel-relevant and {stats['iran_nexus']} had an Iran nexus."
    )
    base_he = (
        f"בין התאריכים {stats['start_date']} ל-{stats['end_date']} הופקו {stats['total']} פריטי מודיעין "
        f"({stats['critical']} קריטיים, {stats['high']} גבוהים). "
        f"גורמי איום בולטים: {top_actors}. פרצות אבטחה מובילות: {top_cves}."
    )
    return {
        "executive_summary_en": base,
        "executive_summary_he": base_he,
        "key_trends": "Automated summary — narrative generation was unavailable this run.",
        "actor_analysis": f"Most active actors this week: {top_actors}.",
        "israel_assessment": f"{stats['israel']} Israel-relevant item(s) observed; review the section below.",
        "iran_assessment": f"{stats['iran_nexus']} Iran-nexus item(s) observed; escalation verdict unavailable.",
        "cve_analysis": f"Top CVEs: {top_cves}.",
        "phishing_analysis": f"{len(agg['phishing_items'])} phishing/criminal item(s) observed.",
        "infra_analysis": f"{len(agg['infra_items'])} critical-infrastructure item(s) observed.",
        "intelligence_gaps": "Narrative generation unavailable; manual analyst review recommended.",
    }


def _gemini_narrative(stats: dict, agg: dict, items: list) -> dict:
    """Ask Gemini for the narrative sections; fall back deterministically."""
    # Compact context: aggregated numbers + a sample of the most severe items.
    sample = sorted(
        items,
        key=lambda i: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(_norm_sev(i.get("severity")), 4),
    )[:20]
    sample_ctx = [
        {
            "title": (i.get("title_en") or "")[:160],
            "severity": i.get("severity"),
            "source": _source_of(i),
            "israel": bool(i.get("israel_relevance")),
            "iran": bool(i.get("iran_nexus")),
            "summary": (i.get("summary_en") or "")[:300],
        }
        for i in sample
    ]
    data = {
        "window": f"{stats['start_date']} to {stats['end_date']}",
        "totals": {k: stats[k] for k in ("total", "critical", "high", "medium", "low", "israel", "iran_nexus")},
        "top_actors": agg["actor_counter"].most_common(10),
        "new_actors": agg["new_actors"],
        "top_cves": agg["cve_counter"].most_common(10),
        "top_mitre": agg["mitre_counter"].most_common(10),
        "top_sectors": agg["sector_counter"].most_common(10),
        "counts": {
            "phishing_items": len(agg["phishing_items"]),
            "infra_items": len(agg["infra_items"]),
        },
        "sample_items": sample_ctx,
    }
    prompt = f"{_WEEKLY_NARRATIVE_PROMPT}\n\n=== WEEKLY DATA ===\n{json.dumps(data, ensure_ascii=False)[:12000]}\n"
    try:
        result = call_gemini(prompt)
        if isinstance(result, dict) and result.get("executive_summary_en"):
            # Merge over the fallback so any missing key is still populated.
            merged = _fallback_narrative(stats, agg)
            merged.update({k: v for k, v in result.items() if v})
            return merged
    except Exception as e:
        if _is_rate_limit_error(e):
            log.warning("[WEEKLY] Gemini quota reached — using deterministic narrative.")
        else:
            log.error(f"[WEEKLY] narrative generation failed: {e}")
    return _fallback_narrative(stats, agg)


# ── HTML ─────────────────────────────────────────────────────
def _prose(text) -> str:
    """Render a narrative string (or list) as escaped HTML paragraphs."""
    if isinstance(text, list):
        items = "".join(f"<li>{_esc(t)}</li>" for t in text if t)
        return f'<ul style="margin:0;padding-left:20px;">{items}</ul>' if items else ""
    text = str(text or "").strip()
    if not text:
        return f'<span style="color:{_MUTED};">—</span>'
    paras = [p.strip() for p in text.split("\n") if p.strip()]
    return "".join(
        f'<p style="margin:0 0 8px 0;color:{_TEXT};font-size:14px;line-height:1.6;">{_esc(p)}</p>'
        for p in paras
    )


def _build_html(stats: dict, agg: dict, narrative: dict) -> str:
    gen_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sections = []

    # Severity chip row.
    sections.append(
        '<tr><td style="padding:0 20px 18px 20px;">'
        + _kv_chips([
            ("Total", stats["total"], _ACCENT),
            ("Critical", stats["critical"], _SEV_COLOR["critical"]),
            ("High", stats["high"], _SEV_COLOR["high"]),
            ("Medium", stats["medium"], _SEV_COLOR["medium"]),
            ("Israel", stats["israel"], _ACCENT),
            ("Iran", stats["iran_nexus"], _SEV_COLOR["high"]),
        ])
        + "</td></tr>"
    )

    # 1. Executive summary (+ key trends + significant events).
    sections.append(_section(
        "1 · Executive Summary",
        _prose(narrative.get("executive_summary_en"))
        + f'<div style="margin-top:10px;font-weight:600;color:{_ACCENT};">Key trends</div>'
        + _prose(narrative.get("key_trends")),
    ))

    # 2. Threat actor activity.
    actor_rows = [[(n, False), (str(c), False)] for n, c in agg["actor_counter"].most_common(15)]
    new_actors = ", ".join(agg["new_actors"]) or "none observed"
    sections.append(_section(
        "2 · Threat Actor Activity",
        _prose(narrative.get("actor_analysis"))
        + f'<div style="margin:10px 0 4px 0;color:{_MUTED};font-size:12px;">New actors this week: '
        f'<span style="color:{_TEXT};">{_esc(new_actors)}</span></div>'
        + _table(["Actor", "Mentions"], actor_rows, empty="No actors observed."),
    ))

    # 3. Israel cyber situation.
    sections.append(_section(
        f"3 · Israel Cyber Situation ({len(agg['israel_items'])})",
        _prose(narrative.get("israel_assessment"))
        + _events_block(agg["israel_items"][:15], show_indicators=True, empty="No Israel-relevant events."),
        accent=_ACCENT,
    ))

    # 4. Iran-Israel nexus.
    sections.append(_section(
        f"4 · Iran-Israel Nexus ({len(agg['iran_items'])})",
        _prose(narrative.get("iran_assessment"))
        + _events_block(agg["iran_items"][:15], show_indicators=True, empty="No Iran-nexus events."),
        accent=_SEV_COLOR["high"],
    ))

    # 5. Top CVEs.
    cve_rows = [[(c, True), (str(n), False), ("—", False)] for c, n in agg["cve_counter"].most_common(15)]
    sections.append(_section(
        "5 · Top CVEs of the Week",
        _prose(narrative.get("cve_analysis"))
        + _table(["CVE", "Mentions", "CVSS"], cve_rows, empty="No CVEs referenced."),
    ))

    # 6. Phishing & campaign activity.
    sector_rows = [[(s, False), (str(n), False)] for s, n in agg["sector_counter"].most_common(10)]
    sections.append(_section(
        f"6 · Phishing & Campaign Activity ({len(agg['phishing_items'])})",
        _prose(narrative.get("phishing_analysis"))
        + f'<div style="margin:10px 0 4px 0;font-weight:600;color:{_ACCENT};">Targeted sectors</div>'
        + _table(["Sector", "Items"], sector_rows, empty="No targeted-sector data."),
    ))

    # 7. Critical infrastructure threats.
    sections.append(_section(
        f"7 · Critical Infrastructure Threats ({len(agg['infra_items'])})",
        _prose(narrative.get("infra_analysis"))
        + _events_block(agg["infra_items"][:10], show_indicators=False, empty="No critical-infrastructure events."),
        accent=_SEV_COLOR["critical"],
    ))

    # 8. IOC summary (top 20).
    ioc_rows = [[(agg["ioc_types"].get(v, "ioc"), False), (v, True), (str(n), False)]
                for v, n in agg["ioc_counter"].most_common(20)]
    sections.append(_section(
        "8 · IOC Summary (Top 20)",
        _table(["Type", "Indicator", "Count"], ioc_rows, empty="No IOCs extracted."),
    ))

    # 9. MITRE ATT&CK heatmap data.
    mitre_rows = [[(m, True), (str(n), False)] for m, n in agg["mitre_counter"].most_common(20)]
    sections.append(_section(
        "9 · MITRE ATT&CK Techniques",
        _table(["Technique", "Count"], mitre_rows, empty="No MITRE techniques observed."),
    ))

    # 10. Intelligence gaps.
    sections.append(_section(
        "10 · Intelligence Gaps",
        _prose(narrative.get("intelligence_gaps")),
        accent=_MUTED,
    ))

    # 11. Engine usage & Gemini quota tracking.
    engine_c = agg.get("engine_counter") or Counter()
    claude_n = engine_c.get("claude", 0)
    gemini_n = engine_c.get("gemini", 0)
    quota_days = stats.get("quota_days") or []
    claude_days = max(0, stats.get("days", 7) - len(quota_days))
    if quota_days:
        rec = (f"Gemini quota was hit on {len(quota_days)} day(s). "
               "Ensure ANTHROPIC_API_KEY is funded so Claude (primary) carries the "
               "load next week; Gemini should only run when Claude's key is absent.")
    elif gemini_n and not claude_n:
        rec = ("All items ran on the Gemini fallback — ANTHROPIC_API_KEY was not "
               "set. Configure Claude (primary) for next week.")
    else:
        rec = "Claude (primary) handled enrichment with no quota issues. No change needed."
    engine_rows = [
        [("Items via Claude (primary)", False), (str(claude_n), False)],
        [("Items via Gemini (fallback)", False), (str(gemini_n), False)],
        [("Total tokens (Claude)", False), (f"{agg.get('tokens_total', 0):,}", False)],
        [("Days Gemini quota hit", False), (str(len(quota_days)), False)],
        [("Days without quota issues", False), (str(claude_days), False)],
    ]
    sections.append(_section(
        "11 · Engine Usage & Gemini Quota",
        _table(["Metric", "Value"], engine_rows, empty="No enrichment telemetry.")
        + f'<div style="margin-top:10px;color:{_MUTED};font-size:12px;">Quota days: '
        f'<span style="color:{_TEXT};">{_esc(", ".join(quota_days) or "none")}</span></div>'
        + f'<div style="margin-top:8px;font-weight:600;color:{_ACCENT};">Recommendation</div>'
        f'<div style="color:{_TEXT};font-size:13px;line-height:1.6;">{_esc(rec)}</div>',
        accent=_MUTED,
    ))

    # 12. Hebrew executive summary (RTL).
    sections.append(
        '<tr><td style="padding:0 20px 18px 20px;">'
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        f'style="background:{_PANEL};border:1px solid {_BORDER};border-radius:10px;">'
        f'<tr><td dir="rtl" style="padding:14px 18px 6px 18px;border-bottom:2px solid {_ACCENT};text-align:right;">'
        f'<span style="font-size:16px;font-weight:700;color:{_TEXT};">12 · תקציר מנהלים (עברית)</span></td></tr>'
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
<title>CTI Weekly Brief — {_esc(stats['start_date'])} → {_esc(stats['end_date'])}</title>
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
          <div style="font-size:26px;font-weight:800;color:{_TEXT};margin-top:4px;">5-Day / Weekly Intelligence Brief</div>
          <div style="font-size:14px;color:{_MUTED};margin-top:4px;">
            {_esc(stats['start_date'])} → {_esc(stats['end_date'])} · {stats['total']} items
          </div>
        </td></tr>
        {sections_html}
        <tr><td style="padding:16px 20px 28px 20px;border-top:1px solid {_BORDER};">
          <div style="font-size:12px;color:{_MUTED};line-height:1.6;">
            CTI Platform · automated weekly intelligence report<br>
            Generated {_esc(gen_ts)}
          </div>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""


def _build_html_he(summary_he: str, stats: dict) -> str:
    """A compact standalone RTL Hebrew document for report_html_he storage."""
    return f"""<!DOCTYPE html>
<html lang="he" dir="rtl"><head><meta charset="utf-8">
<meta name="color-scheme" content="dark"></head>
<body style="margin:0;padding:24px;background:{_BG};color:{_TEXT};direction:rtl;text-align:right;
             font-family:-apple-system,Segoe UI,Arial,sans-serif;">
  <h2 style="color:{_ACCENT};">תקציר מודיעין שבועי — {_esc(stats['start_date'])} עד {_esc(stats['end_date'])}</h2>
  {_prose(summary_he)}
</body></html>"""


# ── Storage ──────────────────────────────────────────────────
def _store(stats: dict, html_en: str, html_he: str):
    """Insert the report into weekly_reports. Best-effort — never raises."""
    payload = {
        "start_date": stats["start_date"],
        "end_date": stats["end_date"],
        "report_html_en": html_en,
        "report_html_he": html_he,
        "summary_stats": stats,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "delivered_gmail": False,
    }
    try:
        client.table("weekly_reports").insert(payload).execute()
        log.info(f"[WEEKLY] Stored report {stats['start_date']}..{stats['end_date']}")
    except Exception as e:
        if _is_missing_column_error(e):
            log.warning("[WEEKLY] weekly_reports schema mismatch — storing minimal row.")
            try:
                client.table("weekly_reports").insert({
                    "start_date": stats["start_date"],
                    "end_date": stats["end_date"],
                    "summary_stats": stats,
                }).execute()
                return
            except Exception as e2:
                log.error(f"[WEEKLY] minimal store failed: {e2}")
        else:
            log.error(f"[WEEKLY] _store failed: {e}")


# ── Entry point ──────────────────────────────────────────────
def generate_weekly_report(days: int = 7) -> dict:
    """Generate, render, and store the weekly intelligence report.

    Returns: {"html", "stats", "summary_en", "summary_he"}.
    """
    try:
        days = max(1, min(int(days), 31))
    except (TypeError, ValueError):
        days = 7

    now = datetime.now(timezone.utc)
    start = now - timedelta(days=days)
    prior_start = start - timedelta(days=days)
    start_iso, end_iso = start.isoformat(), now.isoformat()

    items = _fetch_window(start_iso, end_iso)
    prior_actors = _prior_actor_set(prior_start.isoformat(), start_iso)
    agg = _aggregate(items, prior_actors)
    quota_days = _quota_days(start_iso, end_iso)

    sev = agg["severity"]
    stats = {
        "start_date": start.strftime("%Y-%m-%d"),
        "end_date": now.strftime("%Y-%m-%d"),
        "days": days,
        "total": len(items),
        "critical": sev.get("critical", 0),
        "high": sev.get("high", 0),
        "medium": sev.get("medium", 0),
        "low": sev.get("low", 0),
        "israel": len(agg["israel_items"]),
        "iran_nexus": len(agg["iran_items"]),
        "top_actors": agg["actor_counter"].most_common(10),
        "top_cves": agg["cve_counter"].most_common(10),
        "top_categories": agg["sector_counter"].most_common(10),
        "quota_days": quota_days,
        "tokens_total": agg.get("tokens_total", 0),
        "engine_usage": dict(agg.get("engine_counter") or {}),
    }

    narrative = _gemini_narrative(stats, agg, items)
    summary_en = narrative.get("executive_summary_en", "")
    summary_he = narrative.get("executive_summary_he", "")

    html_en = _build_html(stats, agg, narrative)
    html_he = _build_html_he(summary_he, stats)
    _store(stats, html_en, html_he)

    log.info(f"[WEEKLY] Report generated — {stats['start_date']}..{stats['end_date']} "
             f"total={stats['total']} critical={stats['critical']} high={stats['high']}")
    return {"html": html_en, "stats": stats, "summary_en": summary_en, "summary_he": summary_he}
