from flask import Flask, request, jsonify
from datetime import datetime, timezone
from config import API_SECRET_KEY, PORT
from database.supabase_client import get_active_sources, write_ingestion_log
from ingestion.rss import run_rss_ingestion

app = Flask(__name__)


def verify_key(req):
    return req.headers.get("X-API-Key", "") == API_SECRET_KEY


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "cti-platform"}), 200


@app.route("/ingest", methods=["POST"])
def ingest():
    if not verify_key(request):
        return jsonify({"error": "Unauthorized"}), 401

    started_at = datetime.now(timezone.utc).isoformat()
    make_execution_id = ""
    if request.json:
        make_execution_id = request.json.get("execution_id", "")

    print(f"[INGEST] Starting {started_at}")

    sources = get_active_sources()
    print(f"[INGEST] {len(sources)} sources found")

    if not sources:
        return jsonify({"status": "warning", "message": "No active sources", "inserted": 0}), 200

    stats = run_rss_ingestion(sources)

    write_ingestion_log(
        stats["fetched"],
        stats["inserted"],
        stats["skipped"],
        stats["errors"][:50],
        started_at,
        make_execution_id
    )

    print(f"[INGEST] Done — inserted={stats['inserted']} skipped={stats['skipped']} errors={len(stats['errors'])}")

    return jsonify({
        "status": "success",
        "started_at": started_at,
        "sources_processed": stats["sources_processed"],
        "sources_failed": stats["sources_failed"],
        "items_fetched": stats["fetched"],
        "items_inserted": stats["inserted"],
        "items_skipped_dedup": stats["skipped"],
        "error_count": len(stats["errors"]),
        "errors": stats["errors"][:10]
    }), 200


if __name__ == "__main__":
    print("CTI Platform starting...")
    app.run(host="0.0.0.0", port=PORT, debug=True)