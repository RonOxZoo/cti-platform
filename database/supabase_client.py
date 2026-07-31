import logging
from supabase import create_client
from config import SUPABASE_URL, SUPABASE_KEY
from datetime import datetime, timezone

log = logging.getLogger(__name__)

# Single client instance
client = create_client(SUPABASE_URL, SUPABASE_KEY)
log.info(f"[DB] Supabase client initialized — {SUPABASE_URL}")

# Tier 3: disable a source automatically after this many consecutive failures.
MAX_SOURCE_FAILURES = 5


def get_active_sources() -> list:
    """Active feed sources, in a STABLE order.

    The ordering matters: /ingest processes sources in offset/limit chunks
    across several calls, and without a deterministic sort Postgres may return
    rows in a different order each time — which would silently skip some
    sources and poll others twice.
    """
    result = client.table("rss_sources") \
        .select("id, url, name, category, trust_score") \
        .eq("active", True) \
        .order("id") \
        .execute()
    return result.data or []


def hash_exists(content_hash: str) -> bool:
    result = client.table("raw_items") \
        .select("id") \
        .eq("content_hash", content_hash) \
        .limit(1) \
        .execute()
    return len(result.data) > 0


def insert_raw_item(source_id, url, title, raw_content, content_hash, published_at) -> str:
    try:
        result = client.table("raw_items").insert({
            "source_id": source_id,
            "url": url,
            "title": title[:500] if title else "",
            "raw_content": raw_content[:10000] if raw_content else "",
            "content_hash": content_hash,
            "published_at": published_at or datetime.now(timezone.utc).isoformat()
        }).execute()
        if result.data:
            return result.data[0]["id"]
        return None
    except Exception as e:
        log.error(f"[DB] insert_raw_item failed: {e}")
        return None


def insert_processing_job(raw_item_id: str):
    try:
        client.table("processing_jobs").insert({
            "raw_item_id": raw_item_id,
            "status": "pending"
        }).execute()
    except Exception as e:
        log.error(f"[DB] insert_processing_job failed: {e}")


def update_source_last_polled(source_id: str, error: bool = False):
    try:
        update_data = {"last_polled": datetime.now(timezone.utc).isoformat()}
        if error:
            source = client.table("rss_sources") \
                .select("error_count") \
                .eq("id", source_id) \
                .execute()
            if source.data:
                update_data["error_count"] = (source.data[0].get("error_count") or 0) + 1
        else:
            # A clean poll clears the failure streak so the Tier-3 auto-disable
            # counter only ever reflects *consecutive* failures.
            update_data["error_count"] = 0
        client.table("rss_sources").update(update_data).eq("id", source_id).execute()
    except Exception as e:
        log.error(f"[DB] update_source_last_polled failed: {e}")


def record_source_failure(source_id: str, source_name: str = ""):
    """Tier 3 — register a failed fetch for a source.

    Increments error_count and, once it reaches MAX_SOURCE_FAILURES consecutive
    failures, flips the source to active=false so the broken feed stops being
    polled. The reason is logged clearly either way.
    """
    try:
        source = client.table("rss_sources") \
            .select("error_count") \
            .eq("id", source_id) \
            .execute()
        current = (source.data[0].get("error_count") or 0) if source.data else 0
        new_count = current + 1
        update_data = {
            "last_polled": datetime.now(timezone.utc).isoformat(),
            "error_count": new_count,
        }
        label = source_name or source_id
        if new_count >= MAX_SOURCE_FAILURES:
            update_data["active"] = False
            log.warning(
                f"[DB] Source '{label}' disabled (active=false) after "
                f"{new_count} consecutive failures"
            )
        else:
            log.info(f"[DB] Source '{label}' failure {new_count}/{MAX_SOURCE_FAILURES}")
        client.table("rss_sources").update(update_data).eq("id", source_id).execute()
    except Exception as e:
        log.error(f"[DB] record_source_failure failed: {e}")


def write_ingestion_log(items_fetched, items_inserted, items_skipped, errors, started_at, make_execution_id=""):
    try:
        client.table("ingestion_logs").insert({
            "scenario_name": "python_rss_ingestion",
            "started_at": started_at,
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "status": "success" if not errors else "partial",
            "items_fetched": items_fetched,
            "items_inserted": items_inserted,
            "items_skipped_dedup": items_skipped,
            "errors": errors[:50],
            "make_execution_id": make_execution_id
        }).execute()
        log.info("[DB] Ingestion log written successfully")
    except Exception as e:
        log.error(f"[DB] write_ingestion_log failed: {e}")