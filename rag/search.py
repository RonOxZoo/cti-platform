"""
RAG retrieval layer — search the collected intelligence in Supabase.

All searches read from `intelligence_items` (enriched output) plus the
`iocs` aggregate table. Structured indicators (IOCs / CVEs / actors / MITRE)
live inside the `enrichment_data` jsonb column — see enrichment/gemini.py
build_intelligence_payload() — so the indicator searches scan that column.

Every public search logs the query to ingestion_logs (scenario_name=
'rag_query') and returns *sanitized* items only — never raw Supabase rows.
All functions degrade gracefully to an empty list on error or no match.
"""
import logging
from datetime import datetime, timezone, timedelta

from database.supabase_client import client

log = logging.getLogger(__name__)

RAG_SCENARIO = "rag_query"

# Severity labels we treat as actionable. Matched case-insensitively because
# Gemini's casing is not guaranteed.
_CRITICAL_SEVERITIES = ["Critical", "High", "critical", "high", "CRITICAL", "HIGH"]

# How many enriched items an indicator scan will pull before filtering in
# Python. Bounded so a query can never sweep the whole table.
_INDICATOR_SCAN_LIMIT = 500


# ── Sanitization ─────────────────────────────────────────────
def _sanitize_item(row: dict) -> dict:
    """Project an intelligence_items row onto a safe, curated shape.

    Drops internal plumbing (raw_item_id, gemini_processed flags, etc.) and
    lifts the structured indicators out of enrichment_data so callers get a
    flat, predictable object.
    """
    ed = row.get("enrichment_data") or {}
    return {
        "id": row.get("id"),
        "title_en": row.get("title_en"),
        "title_he": row.get("title_he"),
        "summary_en": row.get("summary_en"),
        "summary_he": row.get("summary_he"),
        "severity": row.get("severity"),
        "confidence_score": row.get("confidence_score"),
        "categories": row.get("categories") or [],
        "source_category": row.get("source_category"),
        "israel_relevance": row.get("israel_relevance"),
        "iran_nexus": row.get("iran_nexus"),
        "iocs": ed.get("iocs", {}),
        "cves": ed.get("cves", []),
        "actors": ed.get("actors", []),
        "mitre": ed.get("mitre", []),
        "processed_at": row.get("processed_at"),
    }


def _sanitize_ioc(row: dict) -> dict:
    """Curated shape for an `iocs` aggregate row."""
    return {
        "type": row.get("type"),
        "value": row.get("value"),
        "occurrence_count": row.get("occurrence_count"),
        "linked_actors": row.get("linked_actors") or [],
        "linked_cves": row.get("linked_cves") or [],
        "first_seen_at": row.get("first_seen_at"),
        "last_seen_at": row.get("last_seen_at"),
    }


# Columns pulled for every item search. Explicit so we never accidentally
# select internal/raw columns.
_ITEM_COLS = (
    "id, title_en, title_he, summary_en, summary_he, severity, "
    "confidence_score, categories, source_category, israel_relevance, "
    "iran_nexus, enrichment_data, processed_at"
)


# ── Logging ──────────────────────────────────────────────────
def log_rag_query(query_type: str, query_text: str, result_count: int, error: str = None):
    """Record a RAG query in ingestion_logs. Best-effort — never raises."""
    try:
        started = datetime.now(timezone.utc).isoformat()
        client.table("ingestion_logs").insert({
            "scenario_name": RAG_SCENARIO,
            "started_at": started,
            "finished_at": started,
            "status": "error" if error else "success",
            "items_fetched": result_count,
            "items_inserted": 0,
            "items_skipped_dedup": 0,
            "errors": [error[:200]] if error else [],
            # Tag the row with the query type + text so the audit trail is useful.
            "make_execution_id": f"{query_type}: {str(query_text)[:200]}",
        }).execute()
    except Exception as e:
        log.error(f"[RAG] log_rag_query failed: {e}")


# ── Full-text search ─────────────────────────────────────────
def _run_text_search(query: str, limit: int = 10) -> list:
    """Core full-text search, without query logging (used internally too).

    Uses the PostgreSQL `search_vector` tsvector populated by
    sql/enable_fts.sql. If that column/index is not present yet, falls back to
    a case-insensitive ILIKE across title_en/summary_en so the feature still
    works before the migration is run.
    """
    if not query or not query.strip():
        return []
    query = query.strip()

    rows = []
    try:
        result = (
            client.table("intelligence_items")
            .select(_ITEM_COLS)
            .text_search("search_vector", query, options={"type": "websearch", "config": "english"})
            .order("processed_at", desc=True)
            .limit(limit)
            .execute()
        )
        rows = result.data or []
    except Exception as e:
        # Most likely the search_vector column/index doesn't exist yet, or the
        # installed postgrest lacks text_search — fall back to ILIKE.
        log.warning(f"[RAG] FTS unavailable, falling back to ILIKE: {str(e)[:160]}")
        try:
            pattern = f"%{query}%"
            result = (
                client.table("intelligence_items")
                .select(_ITEM_COLS)
                .or_(f"title_en.ilike.{pattern},summary_en.ilike.{pattern}")
                .order("processed_at", desc=True)
                .limit(limit)
                .execute()
            )
            rows = result.data or []
        except Exception as e2:
            log.error(f"[RAG] ILIKE fallback failed: {e2}")
            rows = []

    return [_sanitize_item(r) for r in rows]


def get_items_by_ids(ids: list) -> list:
    """Fetch + sanitize intelligence_items by id, preserving the input order.

    Used by the vector-RAG path to turn matched chunk item_ids into full context
    items. Best-effort -> [] on error.
    """
    ids = [i for i in (ids or []) if i]
    if not ids:
        return []
    try:
        result = (client.table("intelligence_items").select(_ITEM_COLS)
                  .in_("id", ids).execute())
    except Exception as e:
        log.error(f"[RAG] get_items_by_ids failed: {e}")
        return []
    by_id = {r.get("id"): _sanitize_item(r) for r in (result.data or [])}
    return [by_id[i] for i in ids if i in by_id]


def search_intelligence(query: str, limit: int = 10) -> list:
    """Full-text search across intelligence_items.

    Returns the top matching sanitized items ordered by recency, using the
    PostgreSQL tsvector search index.
    """
    items = _run_text_search(query, limit=limit)
    log_rag_query("text", query, len(items))
    return items


# ── Indicator searches (scan enrichment_data jsonb) ──────────
def _fetch_enriched(limit: int = _INDICATOR_SCAN_LIMIT) -> list:
    """Pull recent enriched items (with enrichment_data) for in-Python scans.

    Searching arbitrary nested arrays inside a jsonb column reliably (and
    case-insensitively) is simplest in Python, and at this platform's scale
    (rolling 2-month retention) the bounded fetch is cheap.
    """
    try:
        result = (
            client.table("intelligence_items")
            .select(_ITEM_COLS)
            .eq("gemini_processed", True)
            .order("processed_at", desc=True)
            .limit(limit)
            .execute()
        )
        return result.data or []
    except Exception as e:
        log.error(f"[RAG] _fetch_enriched failed: {e}")
        return []


def _iter_ioc_values(iocs: dict):
    """Yield every IOC value from an enrichment_data['iocs'] dict.

    Handles flat buckets (ips/domains/urls/emails/c2_servers/malware_families)
    and the nested hashes bucket ({"md5": [], "sha1": [], "sha256": []}).
    """
    if not isinstance(iocs, dict):
        return
    for bucket in iocs.values():
        if isinstance(bucket, list):
            for v in bucket:
                if v:
                    yield str(v)
        elif isinstance(bucket, dict):
            # Nested bucket, e.g. hashes -> {md5: [...], sha1: [...], ...}.
            for subvals in bucket.values():
                if isinstance(subvals, list):
                    for v in subvals:
                        if v:
                            yield str(v)


def search_by_ioc(ioc_value: str) -> list:
    """Return all intelligence items mentioning a specific IOC.

    Scans the IOC buckets inside enrichment_data (case-insensitive,
    substring-tolerant so a bare domain matches a URL that contains it).
    """
    matches = []
    if ioc_value and ioc_value.strip():
        needle = ioc_value.strip().lower()
        for row in _fetch_enriched():
            ed = row.get("enrichment_data") or {}
            values = [v.lower() for v in _iter_ioc_values(ed.get("iocs", {}))]
            if any(needle == v or needle in v for v in values):
                matches.append(_sanitize_item(row))
    log_rag_query("ioc", ioc_value, len(matches))
    return matches


def search_by_actor(actor_name: str) -> list:
    """Return all items mentioning a specific threat actor.

    Case-insensitive substring match against enrichment_data.actors.
    """
    matches = []
    if actor_name and actor_name.strip():
        needle = actor_name.strip().lower()
        for row in _fetch_enriched():
            ed = row.get("enrichment_data") or {}
            actors = ed.get("actors", []) or []
            if any(needle in str(a).lower() for a in actors):
                matches.append(_sanitize_item(row))
    log_rag_query("actor", actor_name, len(matches))
    return matches


def search_by_cve(cve_id: str) -> list:
    """Return all items mentioning a specific CVE.

    Case-insensitive match against enrichment_data.cves.
    """
    matches = []
    if cve_id and cve_id.strip():
        needle = cve_id.strip().lower()
        for row in _fetch_enriched():
            ed = row.get("enrichment_data") or {}
            cves = ed.get("cves", []) or []
            if any(needle == str(c).lower() or needle in str(c).lower() for c in cves):
                matches.append(_sanitize_item(row))
    log_rag_query("cve", cve_id, len(matches))
    return matches


# ── Time / frequency queries ─────────────────────────────────
def get_recent_critical(hours: int = 24) -> list:
    """Return Critical and High severity items from the last N hours."""
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    items = []
    try:
        result = (
            client.table("intelligence_items")
            .select(_ITEM_COLS)
            .in_("severity", _CRITICAL_SEVERITIES)
            .gte("processed_at", cutoff)
            .order("processed_at", desc=True)
            .execute()
        )
        items = [_sanitize_item(r) for r in (result.data or [])]
    except Exception as e:
        log.error(f"[RAG] get_recent_critical failed: {e}")
    log_rag_query("recent_critical", f"last_{hours}h", len(items))
    return items


def get_trending_iocs(days: int = 7, limit: int = 20) -> list:
    """Return the most frequently-seen IOCs over the last N days.

    Queries the `iocs` aggregate table ordered by occurrence_count desc.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    iocs = []
    try:
        result = (
            client.table("iocs")
            .select("type, value, occurrence_count, linked_actors, linked_cves, first_seen_at, last_seen_at")
            .gte("last_seen_at", cutoff)
            .order("occurrence_count", desc=True)
            .limit(limit)
            .execute()
        )
        iocs = [_sanitize_ioc(r) for r in (result.data or [])]
    except Exception as e:
        log.error(f"[RAG] get_trending_iocs failed: {e}")
    log_rag_query("trending_iocs", f"last_{days}d", len(iocs))
    return iocs


def _count_frequency(values) -> list:
    """Return [{"value":.., "count":..}] sorted by count desc."""
    counts = {}
    for v in values:
        if v is None:
            continue
        key = str(v).strip()
        if not key:
            continue
        counts[key] = counts.get(key, 0) + 1
    ranked = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)
    return [{"value": k, "count": c} for k, c in ranked]


def get_trending_actors(days: int = 7, limit: int = 10) -> list:
    """Top threat actors over the last N days, aggregated from enrichment_data.

    Actors are stored per-item in enrichment_data.actors (the threat_actors
    table is not populated by the enrichment path), so we tally across recent
    enriched items.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    values = []
    try:
        result = (
            client.table("intelligence_items")
            .select("enrichment_data, processed_at")
            .eq("gemini_processed", True)
            .gte("processed_at", cutoff)
            .order("processed_at", desc=True)
            .limit(_INDICATOR_SCAN_LIMIT)
            .execute()
        )
        for row in (result.data or []):
            ed = row.get("enrichment_data") or {}
            values.extend(ed.get("actors", []) or [])
    except Exception as e:
        log.error(f"[RAG] get_trending_actors failed: {e}")
    return _count_frequency(values)[:limit]


def get_trending_cves(days: int = 7, limit: int = 10) -> list:
    """Top CVEs over the last N days, aggregated from enrichment_data.cves."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    values = []
    try:
        result = (
            client.table("intelligence_items")
            .select("enrichment_data, processed_at")
            .eq("gemini_processed", True)
            .gte("processed_at", cutoff)
            .order("processed_at", desc=True)
            .limit(_INDICATOR_SCAN_LIMIT)
            .execute()
        )
        for row in (result.data or []):
            ed = row.get("enrichment_data") or {}
            values.extend(ed.get("cves", []) or [])
    except Exception as e:
        log.error(f"[RAG] get_trending_cves failed: {e}")
    return _count_frequency(values)[:limit]
