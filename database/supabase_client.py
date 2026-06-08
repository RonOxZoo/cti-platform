import logging
from supabase import create_client
from config import SUPABASE_URL, SUPABASE_KEY
from datetime import datetime, timezone

log = logging.getLogger(__name__)

# Single client instance
client = create_client(SUPABASE_URL, SUPABASE_KEY)
log.info(f"[DB] Supabase client initialized — {SUPABASE_URL}")


def get_active_sources() -> list:
    result = client.table("rss_sources") \
        .select("id, url, name, category, trust_score") \
        .eq("active", True) \
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
                update_data["error_count"] = source.data[0]["error_count"] + 1
        client.table("rss_sources").update(update_data).eq("id", source_id).execute()
    except Exception as e:
        log.error(f"[DB] update_source_last_polled failed: {e}")


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