"""
Populate the pgvector store (intel_chunks) from enriched intelligence_items.

Run from the project root:  python -m scripts.index_vectors [--days N] [--limit N]

Prerequisites:
  - sql/enable_pgvector.sql applied in Supabase (vector extension + intel_chunks
    + match_intel_chunks()).
  - GEMINI_API_KEY set (embeddings provider).

This is intentionally a SEPARATE, opt-in batch job rather than running inside
enrichment — embedding every item inline would burn the free Gemini quota. Run
it on a schedule (e.g. after the daily enrich) or on demand. It chunks each
item's title + EN summary (Pillar 3: <=500 tokens / 10% overlap) and upserts the
embeddings, so re-running only re-embeds changed chunks.
"""
import argparse
import logging
from datetime import datetime, timezone, timedelta

from database.supabase_client import client
from rag import vector as vec

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("index_vectors")


def _recent_items(days: int, limit: int) -> list:
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    try:
        res = (client.table("intelligence_items")
               .select("id, title_en, summary_en, processed_at")
               .gte("processed_at", cutoff)
               .order("processed_at", desc=True)
               .limit(limit)
               .execute())
        return res.data or []
    except Exception as e:
        log.error(f"failed to fetch items: {e}")
        return []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=14, help="look-back window (default 14)")
    ap.add_argument("--limit", type=int, default=500, help="max items to index (default 500)")
    args = ap.parse_args()

    if not vec.is_available():
        log.error("GEMINI_API_KEY not set — cannot produce embeddings. Aborting.")
        return

    items = _recent_items(args.days, args.limit)
    log.info(f"Indexing up to {len(items)} item(s) from the last {args.days} day(s)…")

    total_items = total_chunks = 0
    for it in items:
        text = (it.get("summary_en") or "").strip()
        if not text:
            continue
        n = vec.index_item(it["id"], text, title=it.get("title_en") or "")
        if n:
            total_items += 1
            total_chunks += n

    print("\n" + "=" * 56)
    print("VECTOR INDEXING SUMMARY")
    print("=" * 56)
    print(f"  Items indexed : {total_items}")
    print(f"  Chunks written: {total_chunks}")
    print("=" * 56)


if __name__ == "__main__":
    main()
