import os
import logging
from flask import Flask, request, jsonify
from datetime import datetime, timezone
from config import API_SECRET_KEY, PORT
from database.supabase_client import get_active_sources, write_ingestion_log
from ingestion.rss import run_rss_ingestion

# ── Logging setup ────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger(__name__)

app = Flask(__name__)


# ── Auth ─────────────────────────────────────────────────────
def verify_key(req) -> bool:
    received = req.headers.get("X-API-Key", "").strip()
    expected = API_SECRET_KEY.strip()
    log.info(f"[AUTH] Key check — received='{received}' match={received == expected}")
    return received == expected


# ── Routes ───────────────────────────────────────────────────
@app.route("/", methods=["GET"])
def root():
    return jsonify({
        "service": "CTI Platform",
        "status": "online",
        "version": "1.1.0",
        "endpoints": ["/health", "/ingest"]
    }), 200


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "service": "cti-platform",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }), 200


@app.route("/ingest", methods=["POST"])
def ingest():
    # ── Auth check ───────────────────────────────────────────
    if not verify_key(request):
        log.warning("[INGEST] Unauthorized request blocked")
        return jsonify({"error": "Unauthorized", "hint": "Check X-API-Key header"}), 401

    started_at = datetime.now(timezone.utc).isoformat()
    execution_id = ""
    if request.is_json and request.json:
        execution_id = request.json.get("execution_id", "")

    log.info(f"[INGEST] ═══════════════════════════════════════")
    log.info(f"[INGEST] Starting — {started_at}")
    log.info(f"[INGEST] Execution ID: {execution_id}")

    # ── Load sources ─────────────────────────────────────────
    try:
        sources = get_active_sources()
    except Exception as e:
        log.error(f"[INGEST] Failed to load sources: {e}")
        return jsonify({
            "status": "error",
            "message": f"Failed to load sources: {str(e)}",
            "started_at": started_at
        }), 500

    log.info(f"[INGEST] {len(sources)} active sources loaded")

    if not sources:
        log.warning("[INGEST] No active sources found in rss_sources table")
        return jsonify({
            "status": "warning",
            "message": "No active sources found",
            "inserted": 0,
            "started_at": started_at
        }), 200

    # ── Run ingestion ────────────────────────────────────────
    try:
        stats = run_rss_ingestion(sources)
    except Exception as e:
        log.error(f"[INGEST] Ingestion failed: {e}")
        return jsonify({
            "status": "error",
            "message": f"Ingestion failed: {str(e)}",
            "started_at": started_at
        }), 500

    # ── Write audit log ──────────────────────────────────────
    try:
        write_ingestion_log(
            items_fetched=stats["fetched"],
            items_inserted=stats["inserted"],
            items_skipped=stats["skipped"],
            errors=stats["errors"][:50],
            started_at=started_at,
            make_execution_id=execution_id
        )
    except Exception as e:
        log.error(f"[INGEST] Failed to write log: {e}")

    # ── Summary ──────────────────────────────────────────────
    log.info(f"[INGEST] ═══════════════════════════════════════")
    log.info(f"[INGEST] Sources processed : {stats['sources_processed']}")
    log.info(f"[INGEST] Sources failed    : {stats['sources_failed']}")
    log.info(f"[INGEST] Items fetched     : {stats['fetched']}")
    log.info(f"[INGEST] Items inserted    : {stats['inserted']}")
    log.info(f"[INGEST] Items skipped     : {stats['skipped']}")
    log.info(f"[INGEST] Errors            : {len(stats['errors'])}")
    log.info(f"[INGEST] ═══════════════════════════════════════")

    return jsonify({
        "status": "success",
        "started_at": started_at,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "sources_processed": stats["sources_processed"],
        "sources_failed": stats["sources_failed"],
        "items_fetched": stats["fetched"],
        "items_inserted": stats["inserted"],
        "items_skipped_dedup": stats["skipped"],
        "error_count": len(stats["errors"]),
        "errors": stats["errors"][:10]
    }), 200


@app.route("/status", methods=["GET"])
def status():
    """Returns the last ingestion log entry — useful for monitoring."""
    try:
        from database.supabase_client import client
        result = client.table("ingestion_logs") \
            .select("*") \
            .order("started_at", desc=True) \
            .limit(1) \
            .execute()
        last_run = result.data[0] if result.data else None
        return jsonify({
            "status": "ok",
            "last_run": last_run,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ── Entry point ──────────────────────────────────────────────
if __name__ == "__main__":
    log.info("═══════════════════════════════════════")
    log.info("  CTI Platform v1.1.0 starting...")
    log.info(f"  Port: {PORT}")
    log.info(f"  API Key configured: {'YES' if API_SECRET_KEY else 'NO'}")
    log.info("═══════════════════════════════════════")
    app.run(host="0.0.0.0", port=PORT, debug=False)