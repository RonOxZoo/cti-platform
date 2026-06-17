import os
import hmac
import json
import time
import logging
import threading
import requests
from flask import Flask, request, jsonify
from datetime import datetime, timezone, timedelta
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
    # Constant-time comparison; never log the key material (it is a secret).
    received = req.headers.get("X-API-Key", "").strip()
    expected = (API_SECRET_KEY or "").strip()
    match = bool(expected) and hmac.compare_digest(received, expected)
    log.info(f"[AUTH] Key check — match={match}")
    return match


# ── Simple in-memory rate limiter ────────────────────────────
# Process-local sliding-window limiter. Used to protect /ask against the free
# Gemini tier (10 requests/minute). Single Render instance, so a per-process
# window is sufficient.
_rate_lock = threading.Lock()
_rate_hits: dict = {}


def rate_limited(bucket: str, max_calls: int, per_seconds: int = 60) -> bool:
    """Return True if `bucket` has exceeded max_calls within per_seconds."""
    now = time.time()
    with _rate_lock:
        hits = [t for t in _rate_hits.get(bucket, []) if now - t < per_seconds]
        if len(hits) >= max_calls:
            _rate_hits[bucket] = hits
            return True
        hits.append(now)
        _rate_hits[bucket] = hits
        return False


# ── Routes ───────────────────────────────────────────────────
@app.route("/", methods=["GET"])
def root():
    return jsonify({
        "service": "CTI Platform",
        "status": "online",
        "version": "1.1.0",
        "endpoints": ["/health", "/ingest", "/enrich", "/enrich/status",
                      "/cleanup", "/status",
                      "/feeds/health", "/ask", "/search", "/trending",
                      "/notify/test", "/notify/daily", "/notify/critical",
                      "/report/daily", "/report/preview",
                      "/report/weekly", "/report/weekly/preview",
                      "/report/monthly", "/report/monthly/preview"]
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


def _month_bounds(now=None):
    """Return (prev_month_start, current_month_start, next_month_start) in UTC.

    With the rolling 2-month policy, prev_month_start is also the retention
    cutoff: anything strictly before it gets deleted.
    """
    now = now or datetime.now(timezone.utc)
    cur_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    if cur_start.month == 1:
        prev_start = cur_start.replace(year=cur_start.year - 1, month=12)
        next_start = cur_start.replace(month=2)
    elif cur_start.month == 12:
        prev_start = cur_start.replace(month=11)
        next_start = cur_start.replace(year=cur_start.year + 1, month=1)
    else:
        prev_start = cur_start.replace(month=cur_start.month - 1)
        next_start = cur_start.replace(month=cur_start.month + 1)
    return prev_start, cur_start, next_start


@app.route("/status", methods=["GET"])
def status():
    """Monitoring — last run, retention-window counts, and next cleanup date."""
    from database.supabase_client import client
    now = datetime.now(timezone.utc)
    prev_start, cur_start, next_start = _month_bounds(now)

    def safe(fn, default=None):
        """Run a metric query, swallowing errors (e.g. a column not yet migrated)."""
        try:
            return fn()
        except Exception as e:
            log.warning(f"[STATUS] metric unavailable: {str(e)[:120]}")
            return default

    payload = {
        "status": "ok",
        "timestamp": now.isoformat(),
        "retention_policy": "current month + previous full month",
        "retention_cutoff": prev_start.isoformat(),
        "next_cleanup_date": next_start.date().isoformat(),
        "last_run": safe(lambda: (client.table("ingestion_logs")
                                  .select("*").order("started_at", desc=True)
                                  .limit(1).execute().data or [None])[0]),
        "current_month_items": safe(lambda: client.table("raw_items")
                                    .select("id", count="exact")
                                    .gte("ingested_at", cur_start.isoformat())
                                    .execute().count),
        "previous_month_items": safe(lambda: client.table("raw_items")
                                     .select("id", count="exact")
                                     .gte("ingested_at", prev_start.isoformat())
                                     .lt("ingested_at", cur_start.isoformat())
                                     .execute().count),
        "archived_items": safe(lambda: client.table("intelligence_items")
                               .select("id", count="exact")
                               .eq("archived", True).execute().count),
        "oldest_active_record": safe(lambda: ((client.table("raw_items")
                                    .select("ingested_at")
                                    .order("ingested_at", desc=False)
                                    .limit(1).execute().data or [{}])[0]
                                    .get("ingested_at"))),
    }
    return jsonify(payload), 200


@app.route("/cleanup", methods=["POST"])
def cleanup():
    """Auth-protected — runs the Supabase data-retention function on demand.

    The scheduled monthly run is driven by pg_cron inside Postgres; this
    endpoint is for manual triggering and returns the function's jsonb result.
    """
    if not verify_key(request):
        log.warning("[CLEANUP] Unauthorized request blocked")
        return jsonify({"error": "Unauthorized", "hint": "Check X-API-Key header"}), 401

    from database.supabase_client import client
    started_at = datetime.now(timezone.utc).isoformat()
    log.info("[CLEANUP] Running cleanup_old_data()")
    try:
        result = client.rpc("cleanup_old_data", {}).execute().data
    except Exception as e:
        log.error(f"[CLEANUP] cleanup_old_data() failed: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

    cutoff = result.get("cutoff_date") if isinstance(result, dict) else None
    log.info(f"[CLEANUP] Done — cutoff={cutoff} result={result}")

    # Audit trail.
    try:
        client.table("ingestion_logs").insert({
            "scenario_name": "monthly_cleanup",
            "started_at": started_at,
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "status": "success",
            "items_fetched": 0,
            "items_inserted": 0,
            "items_skipped_dedup": 0,
            "errors": [],
            "make_execution_id": f"cleanup cutoff={cutoff} {json.dumps(result)[:300]}",
        }).execute()
    except Exception as e:
        log.error(f"[CLEANUP] Failed to write ingestion_log: {e}")

    return jsonify({
        "status": "success",
        "cutoff_date": cutoff,
        "result": result,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }), 200


@app.route("/feeds/health", methods=["GET"])
def feeds_health():
    """Monitoring endpoint — checks reachability of all active feed sources via HEAD."""
    from ingestion.rss import get_browser_headers

    try:
        sources = get_active_sources()
    except Exception as e:
        log.error(f"[FEEDS_HEALTH] Failed to load sources: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

    results = []
    healthy = 0
    broken = 0
    for source in sources:
        name = source.get("name", "")
        url = source.get("url", "")
        headers = get_browser_headers(url)
        entry = {"name": name, "url": url, "status": None}
        try:
            resp = requests.head(url, headers=headers, timeout=10, allow_redirects=True)
            if resp.status_code == 405:
                # Some servers reject HEAD — fall back to a streamed GET without downloading the body.
                resp = requests.get(url, headers=headers, timeout=10, allow_redirects=True, stream=True)
                resp.close()
            entry["status"] = resp.status_code
            if resp.status_code < 400:
                healthy += 1
            else:
                broken += 1
                entry["error"] = f"HTTP {resp.status_code}"
        except Exception as e:
            broken += 1
            entry["status"] = None
            entry["error"] = str(e)[:200]
        results.append(entry)

    total = len(sources)
    log.info(f"[FEEDS_HEALTH] total={total} healthy={healthy} broken={broken}")

    return jsonify({
        "total_sources": total,
        "healthy": healthy,
        "broken": broken,
        "results": results
    }), 200


@app.route("/enrich", methods=["POST"])
def enrich():
    """Auth-protected — runs Gemini AI enrichment on pending processing jobs."""
    if not verify_key(request):
        log.warning("[ENRICH] Unauthorized request blocked")
        return jsonify({"error": "Unauthorized", "hint": "Check X-API-Key header"}), 401

    limit = 50
    if request.is_json and request.json:
        try:
            limit = int(request.json.get("limit", 50))
        except (TypeError, ValueError):
            limit = 50
    limit = max(1, min(limit, 100))

    log.info(f"[ENRICH] Starting enrichment — limit={limit}")
    try:
        from enrichment.gemini import run_enrichment
        stats = run_enrichment(limit=limit)
    except Exception as e:
        log.error(f"[ENRICH] Enrichment run failed: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

    log.info(
        f"[ENRICH] Done — processed={stats.get('processed')} "
        f"succeeded={stats.get('succeeded')} failed={stats.get('failed')}"
    )
    return jsonify({
        "status": "success",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **stats
    }), 200


@app.route("/enrich/status", methods=["GET"])
def enrich_status():
    """No-auth — processing_jobs queue counts so progress can be checked
    without triggering a new enrichment run."""
    from database.supabase_client import client

    def count(status):
        try:
            return (client.table("processing_jobs")
                    .select("id", count="exact")
                    .eq("status", status).execute().count) or 0
        except Exception as e:
            log.warning(f"[ENRICH/STATUS] count({status}) unavailable: {str(e)[:120]}")
            return None

    counts = {s: count(s) for s in ("pending", "in_progress", "done", "failed")}
    return jsonify({
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "jobs": counts,
    }), 200


# ── RAG endpoints ────────────────────────────────────────────
@app.route("/ask", methods=["POST"])
def ask():
    """Auth-protected RAG Q&A — answer a question grounded in our intelligence.

    Rate-limited to 10 requests/minute (free Gemini tier).
    """
    if not verify_key(request):
        log.warning("[ASK] Unauthorized request blocked")
        return jsonify({"error": "Unauthorized", "hint": "Check X-API-Key header"}), 401

    if rate_limited("ask", max_calls=10, per_seconds=60):
        log.warning("[ASK] Rate limit exceeded (10/min)")
        return jsonify({
            "error": "Rate limit exceeded",
            "hint": "Maximum 10 requests per minute",
        }), 429

    body = request.json if request.is_json else None
    question = (body or {}).get("question", "").strip()
    if not question:
        return jsonify({"error": "Missing 'question' in request body"}), 400

    log.info(f"[ASK] Question: {question[:120]}")
    try:
        from rag.gemini_rag import ask_intelligence
        result = ask_intelligence(question)
    except Exception as e:
        log.error(f"[ASK] ask_intelligence failed: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

    return jsonify(result), 200


@app.route("/search", methods=["POST"])
def search_endpoint():
    """Auth-protected — typed search over collected intelligence.

    Body: {"query": "...", "type": "text|ioc|actor|cve", "limit": 10}
    """
    if not verify_key(request):
        log.warning("[SEARCH] Unauthorized request blocked")
        return jsonify({"error": "Unauthorized", "hint": "Check X-API-Key header"}), 401

    body = request.json if request.is_json else None
    body = body or {}
    query = str(body.get("query", "")).strip()
    search_type = str(body.get("type", "text")).strip().lower()
    if not query:
        return jsonify({"error": "Missing 'query' in request body"}), 400

    try:
        limit = int(body.get("limit", 10))
    except (TypeError, ValueError):
        limit = 10
    limit = max(1, min(limit, 50))

    log.info(f"[SEARCH] type={search_type} query={query[:100]} limit={limit}")
    try:
        from rag import search as rag_search
        if search_type == "ioc":
            results = rag_search.search_by_ioc(query)[:limit]
        elif search_type == "actor":
            results = rag_search.search_by_actor(query)[:limit]
        elif search_type == "cve":
            results = rag_search.search_by_cve(query)[:limit]
        elif search_type == "text":
            results = rag_search.search_intelligence(query, limit=limit)
        else:
            return jsonify({"error": f"Unknown type '{search_type}'",
                            "hint": "type must be text|ioc|actor|cve"}), 400
    except Exception as e:
        log.error(f"[SEARCH] search failed: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

    return jsonify({
        "type": search_type,
        "query": query,
        "count": len(results),
        "results": results,
    }), 200


@app.route("/trending", methods=["GET"])
def trending():
    """Public dashboard endpoint — trending IOCs, actors, and CVEs (last 7 days)."""
    try:
        from rag import search as rag_search
        days = 7
        payload = {
            "window_days": days,
            "trending_iocs": rag_search.get_trending_iocs(days=days),
            "top_actors": rag_search.get_trending_actors(days=days),
            "top_cves": rag_search.get_trending_cves(days=days),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        log.error(f"[TRENDING] failed: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

    return jsonify(payload), 200


# ── Telegram notification endpoints ──────────────────────────
@app.route("/notify/test", methods=["POST"])
def notify_test():
    """Auth-protected — send a test message to the Telegram channel."""
    if not verify_key(request):
        log.warning("[NOTIFY] Unauthorized request blocked")
        return jsonify({"error": "Unauthorized", "hint": "Check X-API-Key header"}), 401

    from notifier.telegram import send_message
    sent = send_message(
        "✅ <b>CTI Platform</b> — Telegram test message\n"
        f"Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
    )
    # Note: we never echo the chat ID or token back to the caller.
    if sent:
        return jsonify({"status": "success", "sent": True}), 200
    return jsonify({
        "status": "error",
        "sent": False,
        "hint": "Telegram not configured or send failed — check server logs",
    }), 502


@app.route("/notify/daily", methods=["POST"])
def notify_daily():
    """Auth-protected — build the last-24h daily brief and send it to Telegram.

    Routing policy: the daily brief goes to Telegram ONLY. Delegates to the
    daily report generator so the brief carries full per-item detail (the same
    items the /report/daily brief uses)."""
    if not verify_key(request):
        log.warning("[NOTIFY] Unauthorized request blocked")
        return jsonify({"error": "Unauthorized", "hint": "Check X-API-Key header"}), 401

    from notifier.telegram import send_daily_summary

    date = None
    if request.is_json and request.json:
        date = request.json.get("date") or None

    try:
        from reporting.daily import generate_daily_report
        report = generate_daily_report(date)
    except Exception as e:
        log.error(f"[NOTIFY] daily brief generation failed: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

    stats = report["stats"]
    sent = send_daily_summary({**stats, "items": report.get("items", [])})
    return jsonify({
        "status": "success" if sent else "error",
        "sent": sent,
        "stats": stats,
    }), (200 if sent else 502)


@app.route("/notify/critical", methods=["POST"])
def notify_critical():
    """Auth-protected — push a CRITICAL threat alert to Telegram immediately.

    Routing policy: critical alerts go to Telegram ONLY (no Gmail). The request
    body is the alert item itself, or {"item": {...}}; it should carry the
    enrichment fields (title, source, category, actors/actor, targeted_countries/
    country, severity, confidence, summary_en [5 paragraphs], iocs, cves,
    mitre, model). Delivery is best-effort and never raises.
    """
    if not verify_key(request):
        log.warning("[NOTIFY] Unauthorized request blocked")
        return jsonify({"error": "Unauthorized", "hint": "Check X-API-Key header"}), 401

    body = request.json if request.is_json else None
    body = body or {}
    item = body.get("item") if isinstance(body.get("item"), dict) else body
    if not item:
        return jsonify({"error": "Missing alert item in request body"}), 400

    from notifier.telegram import send_critical_alert
    sent = send_critical_alert(item)
    return jsonify({
        "status": "success" if sent else "error",
        "channel": "telegram",
        "sent": sent,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }), (200 if sent else 502)


# ── Gmail intelligence report endpoints ──────────────────────
@app.route("/report/daily", methods=["POST"])
def report_daily():
    """Auth-protected — generate the daily brief and post it to Telegram.

    Routing policy: the DAILY brief goes to Telegram ONLY (never Gmail). The
    report is always generated (a "quiet day" brief when there are no items);
    Telegram delivery is best-effort and never raises.
    """
    if not verify_key(request):
        log.warning("[REPORT] Unauthorized request blocked")
        return jsonify({"error": "Unauthorized", "hint": "Check X-API-Key header"}), 401

    date = None
    if request.is_json and request.json:
        date = request.json.get("date") or None

    try:
        from reporting.daily import generate_daily_report
        report = generate_daily_report(date)
    except Exception as e:
        log.error(f"[REPORT] Daily report generation failed: {e}")
        # Best-effort: alert via Telegram (daily is Telegram-only) so a silent
        # failure doesn't go unnoticed.
        try:
            from notifier.telegram import send_error_alert
            send_error_alert("report/daily", str(e))
        except Exception:
            pass
        return jsonify({"status": "error", "message": str(e)}), 500

    stats = report["stats"]
    items = report.get("items", [])

    # ── Telegram-only delivery: send the FULL daily brief ──
    telegram_sent = False
    try:
        from notifier.telegram import send_daily_summary
        telegram_sent = send_daily_summary({**stats, "items": items})
    except Exception as e:
        log.error(f"[REPORT] Telegram daily brief raised: {e}")

    return jsonify({
        "status": "sent" if telegram_sent else "error",
        "channel": "telegram",
        # Daily is Telegram-only by routing policy — Gmail is never used here.
        "email_sent": False,
        "telegram_sent": telegram_sent,
        "stats": stats,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }), (200 if telegram_sent else 502)


@app.route("/report/preview", methods=["GET"])
def report_preview():
    """Auth-protected — return the raw daily report HTML for browser preview.

    Accepts an optional ?date=YYYY-MM-DD query param (defaults to last 24h).
    """
    if not verify_key(request):
        log.warning("[REPORT] Unauthorized request blocked")
        return jsonify({"error": "Unauthorized", "hint": "Check X-API-Key header"}), 401

    date = request.args.get("date") or None
    try:
        from reporting.daily import generate_daily_report
        report = generate_daily_report(date)
    except Exception as e:
        log.error(f"[REPORT] Preview generation failed: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

    return report["html"], 200, {"Content-Type": "text/html; charset=utf-8"}


def _top_pairs_to_dicts(pairs):
    """Convert Counter.most_common() [(value, count), ...] to the
    [{"value","count"}, ...] shape the Telegram formatters expect."""
    out = []
    for p in (pairs or []):
        if isinstance(p, (list, tuple)) and len(p) == 2:
            out.append({"value": p[0], "count": p[1]})
        elif isinstance(p, dict):
            out.append(p)
        else:
            out.append({"value": p, "count": None})
    return out


@app.route("/report/weekly", methods=["POST"])
def report_weekly():
    """Auth-protected — generate the weekly report, email it, post a Telegram
    summary. Email/Telegram delivery is best-effort and never raises."""
    if not verify_key(request):
        log.warning("[REPORT] Unauthorized request blocked")
        return jsonify({"error": "Unauthorized", "hint": "Check X-API-Key header"}), 401

    days = 7
    if request.is_json and request.json:
        try:
            days = int(request.json.get("days", 7))
        except (TypeError, ValueError):
            days = 7

    try:
        from reporting.weekly import generate_weekly_report
        report = generate_weekly_report(days)
    except Exception as e:
        log.error(f"[REPORT] Weekly report generation failed: {e}")
        try:
            from notifier.gmail import send_error_alert
            send_error_alert("report/weekly", str(e))
        except Exception:
            pass
        return jsonify({"status": "error", "message": str(e)}), 500

    stats = report["stats"]

    email_sent = False
    try:
        from notifier.gmail import send_weekly_report
        email_sent = send_weekly_report(report["html"], stats)
    except Exception as e:
        log.error(f"[REPORT] Weekly email send raised: {e}")

    telegram_sent = False
    try:
        from notifier.telegram import send_weekly_summary
        telegram_sent = send_weekly_summary({
            "start_date": stats.get("start_date"),
            "end_date": stats.get("end_date"),
            "items_enriched": stats.get("total", 0),
            "critical": stats.get("critical", 0),
            "high": stats.get("high", 0),
            "medium": stats.get("medium", 0),
            "top_actors": _top_pairs_to_dicts(stats.get("top_actors")),
            "top_cves": _top_pairs_to_dicts(stats.get("top_cves")),
            "top_categories": _top_pairs_to_dicts(stats.get("top_categories")),
        })
    except Exception as e:
        log.error(f"[REPORT] Weekly Telegram summary raised: {e}")

    return jsonify({
        "status": "sent" if email_sent else "error",
        "email_sent": email_sent,
        "telegram_sent": telegram_sent,
        "stats": stats,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }), (200 if email_sent else 502)


@app.route("/report/monthly", methods=["POST"])
def report_monthly():
    """Auth-protected — generate the monthly strategic report, email it, post a
    Telegram summary. Email/Telegram delivery is best-effort and never raises."""
    if not verify_key(request):
        log.warning("[REPORT] Unauthorized request blocked")
        return jsonify({"error": "Unauthorized", "hint": "Check X-API-Key header"}), 401

    month = None
    if request.is_json and request.json:
        month = request.json.get("month") or None

    try:
        from reporting.monthly import generate_monthly_report
        report = generate_monthly_report(month)
    except Exception as e:
        log.error(f"[REPORT] Monthly report generation failed: {e}")
        try:
            from notifier.gmail import send_error_alert
            send_error_alert("report/monthly", str(e))
        except Exception:
            pass
        return jsonify({"status": "error", "message": str(e)}), 500

    stats = report["stats"]

    email_sent = False
    try:
        from notifier.gmail import send_monthly_report
        email_sent = send_monthly_report(report["html"], stats)
    except Exception as e:
        log.error(f"[REPORT] Monthly email send raised: {e}")

    telegram_sent = False
    try:
        from notifier.telegram import send_monthly_summary
        telegram_sent = send_monthly_summary({
            **stats,
            "top_actors": _top_pairs_to_dicts(stats.get("top_actors")),
        })
    except Exception as e:
        log.error(f"[REPORT] Monthly Telegram summary raised: {e}")

    return jsonify({
        "status": "sent" if email_sent else "error",
        "email_sent": email_sent,
        "telegram_sent": telegram_sent,
        "stats": stats,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }), (200 if email_sent else 502)


@app.route("/report/weekly/preview", methods=["GET"])
def report_weekly_preview():
    """Auth-protected — return the raw weekly report HTML (?days=7)."""
    if not verify_key(request):
        log.warning("[REPORT] Unauthorized request blocked")
        return jsonify({"error": "Unauthorized", "hint": "Check X-API-Key header"}), 401

    try:
        days = int(request.args.get("days", 7))
    except (TypeError, ValueError):
        days = 7
    try:
        from reporting.weekly import generate_weekly_report
        report = generate_weekly_report(days)
    except Exception as e:
        log.error(f"[REPORT] Weekly preview failed: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

    return report["html"], 200, {"Content-Type": "text/html; charset=utf-8"}


@app.route("/report/monthly/preview", methods=["GET"])
def report_monthly_preview():
    """Auth-protected — return the raw monthly report HTML (?month=YYYY-MM)."""
    if not verify_key(request):
        log.warning("[REPORT] Unauthorized request blocked")
        return jsonify({"error": "Unauthorized", "hint": "Check X-API-Key header"}), 401

    month = request.args.get("month") or None
    try:
        from reporting.monthly import generate_monthly_report
        report = generate_monthly_report(month)
    except Exception as e:
        log.error(f"[REPORT] Monthly preview failed: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

    return report["html"], 200, {"Content-Type": "text/html; charset=utf-8"}


# ── Entry point ──────────────────────────────────────────────
if __name__ == "__main__":
    log.info("═══════════════════════════════════════")
    log.info("  CTI Platform v1.1.0 starting...")
    log.info(f"  Port: {PORT}")
    log.info(f"  API Key configured: {'YES' if API_SECRET_KEY else 'NO'}")
    log.info("═══════════════════════════════════════")
    app.run(host="0.0.0.0", port=PORT, debug=False)