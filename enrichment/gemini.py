"""
Gemini AI enrichment — processes pending jobs from processing_jobs table.
Sends raw_items content to Gemini 2.0 Flash, parses the JSON response,
and inserts results into intelligence_items table.

Tuned for the FREE Gemini API tier: a fixed delay between calls, a hard cap
on the number of items processed per run, and a strict no-retry policy on 429
rate-limit errors. When the daily quota is hit we record it and skip the next
run entirely instead of burning through the remaining quota with retries.
"""
import os
import json
import time
import logging
from datetime import datetime, timezone

from google import genai

from database.supabase_client import client
from notifier.telegram import send_critical_alert, notify_enrichment_complete

log = logging.getLogger(__name__)

# Free-tier-friendly model.
GEMINI_MODEL = "gemini-2.0-flash"

# Free-tier rate-limit protection.
# Free tier ≈ 1500 req/day ≈ 1/min, so 15 items/run with a 5s gap is a safe
# batch size that won't blow the per-minute or daily budget in one run.
CALL_DELAY_SECONDS = 5        # delay between consecutive Gemini calls
MAX_ITEMS_PER_RUN = 15        # hard cap on items processed per /enrich call

# ingestion_logs scenario name used to record enrichment quota state. Kept
# distinct from the RSS scenario so RSS runs don't overwrite the quota marker.
ENRICHMENT_SCENARIO = "python_gemini_enrichment"

SYSTEM_PROMPT = """
ROLE: You are a senior Cyber Threat Intelligence analyst working for
an Israeli cybersecurity operations center. You analyze threat intelligence
from global sources with special focus on:
- Israeli cyber ecosystem and targets
- Iran-Israel cyber conflict
- APT groups targeting Middle East
- Critical infrastructure threats
- Global ransomware and phishing campaigns

INPUT: A raw intelligence item with title and content.

STEP 1 — FULL EXTRACTION:
Extract ALL of the following if present:
- IP addresses (IPv4 and IPv6)
- Domain names and subdomains
- URLs (full paths)
- Email addresses
- File hashes (MD5, SHA1, SHA256) — preserve exact format
- CVE identifiers (CVE-XXXX-XXXXX format)
- Threat actor / APT group names and aliases
- MITRE ATT&CK technique IDs (TXXXX or TXXXX.XXX)
- Campaign names or operation names
- Targeted sectors (healthcare, finance, energy, government, defense, telecom)
- Targeted countries or regions
- Malware family names
- C2 infrastructure indicators

STEP 2 — DEEP CATEGORIZATION:
Primary category (pick ONE):
global_ti, apt, israel, iran_nexus, phishing, cves, ics, research

Secondary tags (pick ALL that apply):
ransomware, espionage, data_breach, zero_day, supply_chain,
critical_infrastructure, financial, healthcare, government,
defense, telecom, energy, middle_east, nation_state, criminal

STEP 3 — SEVERITY:
CRITICAL: Active exploitation, zero-day, critical infrastructure attack,
  mass impact, Israeli target under active attack
HIGH: Nation-state campaign, known APT active, sensitive sector targeted,
  CVSS 8.0+, Israeli/Iranian nexus
MEDIUM: Known vulnerability, targeted phishing, criminal campaign, CVSS 4-7.9
LOW: Research, patched vulnerability, historical analysis, CVSS <4.0

STEP 4 — CONFIDENCE (0-100):
Score based on source reputation, IOC specificity, attribution confidence.
State what would increase the score.

STEP 5 — ISRAEL/IRAN FLAGS:
israel_relevance = true if Israeli org targeted, Israeli actor, INCD advisory
iran_nexus = true if Iranian APT, IRGC linked, Iran-Israel conflict context

STEP 6 — PROFESSIONAL SUMMARIES:
Write 5-7 sentence English summary covering:
what happened, who is involved, what was targeted, TTPs used,
impact/risk, what defenders should do.

Then write identical summary in professional Hebrew using:
גורם איום, פרצת אבטחה, תוכנת כופר, תקיפת סייבר,
מודיעין איומים, תשתית קריטית, קמפיין תקיפה, סממן פשרה

OUTPUT — return ONLY valid JSON:
{
  "category": "global_ti|apt|israel|iran_nexus|phishing|cves|ics|research",
  "tags": [],
  "severity": "critical|high|medium|low",
  "severity_reason": "detailed one sentence",
  "confidence": 0,
  "confidence_reason": "explanation",
  "iocs": {
    "ips": [], "domains": [], "urls": [],
    "hashes": {"md5": [], "sha1": [], "sha256": []},
    "emails": [], "malware_families": [], "c2_servers": []
  },
  "cves": [],
  "actors": [],
  "mitre_techniques": [],
  "targeted_sectors": [],
  "targeted_countries": [],
  "campaign_name": null,
  "summary_en": "5-7 sentence professional summary",
  "summary_he": "5-7 sentence Hebrew summary",
  "israel_relevance": false,
  "iran_nexus": false,
  "contradiction_note": null
}
"""


def get_pending_jobs(limit=50):
    """Fetch pending processing jobs joined with their raw_items content."""
    jobs = []
    try:
        result = (
            client.table("processing_jobs")
            .select("id, raw_item_id, raw_items(title, raw_content, source_id)")
            .eq("status", "pending")
            .limit(limit)
            .execute()
        )
        for row in (result.data or []):
            raw = row.get("raw_items") or {}
            # Supabase may return the joined relation as a dict or a single-element list.
            if isinstance(raw, list):
                raw = raw[0] if raw else {}
            jobs.append({
                "job_id": row.get("id"),
                "raw_item_id": row.get("raw_item_id"),
                "title": raw.get("title", ""),
                "raw_content": raw.get("raw_content", ""),
                "source_id": raw.get("source_id"),
            })
    except Exception as e:
        log.error(f"[GEMINI] get_pending_jobs failed: {e}")
    return jobs


# ── Priority queue ───────────────────────────────────────────
# Lower rank = processed first. Severity (from any prior enrichment) dominates;
# source category breaks ties so high-value feeds go first on a cold queue.
_SEVERITY_PRIORITY = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_CATEGORY_PRIORITY = {
    "iran_nexus": 0, "israel": 0, "apt": 1, "ics": 1,
    "cves": 2, "phishing": 3, "global_ti": 4, "research": 5,
}


def _existing_severities(raw_item_ids: list) -> dict:
    """Map raw_item_id -> prior severity (lowercased) from intelligence_items.

    Used to prioritise re-enrichment: items previously scored critical/high are
    processed first. Best-effort — returns {} on error.
    """
    out = {}
    ids = [r for r in raw_item_ids if r]
    if not ids:
        return out
    try:
        result = (
            client.table("intelligence_items")
            .select("raw_item_id, severity")
            .in_("raw_item_id", ids)
            .execute()
        )
        for row in (result.data or []):
            sev = (row.get("severity") or "").strip().lower()
            if sev:
                out[row.get("raw_item_id")] = sev
    except Exception as e:
        log.error(f"[GEMINI] _existing_severities failed: {e}")
    return out


def _source_categories(source_ids: list) -> dict:
    """Map source_id -> rss_sources.category. Best-effort — returns {} on error."""
    out = {}
    ids = list({s for s in source_ids if s})
    if not ids:
        return out
    try:
        result = (
            client.table("rss_sources")
            .select("id, category")
            .in_("id", ids)
            .execute()
        )
        for row in (result.data or []):
            out[row.get("id")] = (row.get("category") or "").strip().lower()
    except Exception as e:
        log.error(f"[GEMINI] _source_categories failed: {e}")
    return out


def prioritize_jobs(jobs: list) -> list:
    """Order pending jobs so CRITICAL/HIGH (and high-value sources) go first.

    Severity is taken from any prior enrichment of the same raw_item (the common
    case after a re-enrichment reset); source category is the tiebreaker for
    items that have never been scored. Stable sort preserves DB order within a
    rank.
    """
    if len(jobs) <= 1:
        return jobs
    sev_map = _existing_severities([j.get("raw_item_id") for j in jobs])
    cat_map = _source_categories([j.get("source_id") for j in jobs])

    def rank(job):
        sev = sev_map.get(job.get("raw_item_id"))
        cat = cat_map.get(job.get("source_id"))
        return (_SEVERITY_PRIORITY.get(sev, 9), _CATEGORY_PRIORITY.get(cat, 9))

    return sorted(jobs, key=rank)


def build_prompt(title, raw_content):
    """Build the full prompt string for a single feed item."""
    return (
        f"{SYSTEM_PROMPT}\n\n"
        f"raw_title: {title or ''}\n"
        f"raw_body: {raw_content or ''}\n"
    )


def _strip_code_fences(text: str) -> str:
    """Remove markdown ```json ... ``` fences if present."""
    t = text.strip()
    if t.startswith("```"):
        # Drop the opening fence line (``` or ```json)
        lines = t.split("\n")
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        t = "\n".join(lines).strip()
    return t


def _is_rate_limit_error(err) -> bool:
    """Detect a 429 / quota-exhausted error without depending on a specific
    exception class (the genai stack raises several)."""
    text = str(err).lower()
    return (
        "429" in text
        or ("resource" in text and "exhaust" in text)
        or "rate limit" in text
        or "quota" in text
    )


def call_gemini(prompt):
    """Call Gemini and return the parsed JSON dict. Raises on failure.

    No retries: on a 429 rate-limit error the exception propagates so the caller
    can stop the run and preserve the remaining daily quota.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY is not set")

    genai_client = genai.Client(api_key=api_key)
    response = genai_client.models.generate_content(model=GEMINI_MODEL, contents=prompt)

    # Log token usage if available.
    try:
        usage = getattr(response, "usage_metadata", None)
        if usage is not None:
            log.info(
                f"[GEMINI] tokens prompt={getattr(usage, 'prompt_token_count', '?')} "
                f"candidates={getattr(usage, 'candidates_token_count', '?')} "
                f"total={getattr(usage, 'total_token_count', '?')}"
            )
    except Exception:
        pass

    text = getattr(response, "text", None)
    if not text:
        raise RuntimeError("Gemini returned an empty response")

    cleaned = _strip_code_fences(text)
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Failed to parse Gemini JSON: {e}; raw={cleaned[:300]}")


def call_gemini_with_retry(prompt):
    """Call Gemini, retrying ONCE on a transient (non-quota) failure.

    A 429 / quota error is re-raised immediately and never retried — the caller
    stops the run to preserve the remaining daily quota. Any other error (e.g. a
    malformed-JSON response or a blip) gets a single retry after the standard
    inter-call delay before being allowed to propagate.
    """
    try:
        return call_gemini(prompt)
    except Exception as e:
        if _is_rate_limit_error(e):
            raise  # quota errors must not be retried
        log.warning(f"[GEMINI] Call failed, retrying once: {str(e)[:160]}")
        time.sleep(CALL_DELAY_SECONDS)
        return call_gemini(prompt)


# Columns added by sql/add_tags_column.sql. They are mapped from the richer
# Gemini output, but if that migration hasn't been applied yet an upsert that
# includes them fails wholesale (PostgREST PGRST204). To avoid the historical
# "table stays empty" failure mode, insert_intelligence_item retries without
# these columns and logs a clear pointer to the migration.
_OPTIONAL_COLUMNS = ("tags", "targeted_sectors", "targeted_countries",
                     "campaign_name", "malware_families")


def build_intelligence_payload(job, result):
    """Map Gemini's JSON output onto the real intelligence_items columns.

    The richer structured output (full IOC buckets, CVEs, actors, MITRE,
    malware families, C2 servers, contradiction note) is consolidated into the
    `enrichment_data` jsonb column; the flat fields map to dedicated typed
    columns (some added by sql/add_tags_column.sql).
    """
    category = (result.get("category") or "").strip()
    try:
        confidence = int(result.get("confidence"))
    except (TypeError, ValueError):
        confidence = None

    iocs = result.get("iocs", {}) or {}
    # malware_families is nested under iocs in the Gemini schema; surface it both
    # in enrichment_data and in its own typed column.
    malware_families = iocs.get("malware_families", []) or []

    return {
        "raw_item_id": job["raw_item_id"],
        "severity": result.get("severity"),
        "severity_rationale": result.get("severity_reason"),
        "confidence_score": confidence,
        "confidence_rationale": result.get("confidence_reason"),
        # categories is a text[] — wrap the single Gemini primary category.
        "categories": [category] if category else [],
        # New typed columns (sql/add_tags_column.sql).
        "tags": result.get("tags", []) or [],
        "targeted_sectors": result.get("targeted_sectors", []) or [],
        "targeted_countries": result.get("targeted_countries", []) or [],
        "campaign_name": result.get("campaign_name") or None,
        "malware_families": malware_families,
        "summary_en": result.get("summary_en"),
        "summary_he": result.get("summary_he"),
        "israel_relevance": bool(result.get("israel_relevance", False)),
        "iran_nexus": bool(result.get("iran_nexus", False)),
        # All IOC-style structured output lives in the jsonb column. The key
        # names here (iocs/cves/actors/mitre) are the contract the RAG search
        # and report generators read from — keep them stable.
        "enrichment_data": {
            "iocs": iocs,
            "cves": result.get("cves", []),
            "actors": result.get("actors", []),
            "mitre": result.get("mitre_techniques", []),
            "malware_families": malware_families,
            "c2_servers": iocs.get("c2_servers", []),
            "contradiction_note": result.get("contradiction_note"),
        },
        "gemini_processed": True,
        "processed_at": datetime.now(timezone.utc).isoformat(),
    }


def _is_missing_column_error(err) -> bool:
    """True if an error looks like writing to a column that doesn't exist yet."""
    text = str(err).lower()
    return (
        "pgrst204" in text
        or ("column" in text and ("does not exist" in text
                                  or "could not find" in text
                                  or "schema cache" in text))
    )


def insert_intelligence_item(job, result):
    """Upsert an enriched intelligence item, keyed on raw_item_id.

    Upsert (ON CONFLICT raw_item_id) means a re-processed item updates its row
    in place instead of creating a duplicate. Requires a unique index on
    raw_item_id (see sql/fix_intelligence_items.sql).

    If the sql/add_tags_column.sql migration hasn't been applied, the upsert is
    retried without the new columns so enrichment still works (degraded) rather
    than failing every item.

    RAG searchability: the `search_vector` tsvector (built from title_en,
    summary_en, categories) is populated automatically by the BEFORE
    INSERT/UPDATE trigger from sql/enable_fts.sql. That trigger fires on this
    upsert, so every newly-enriched item becomes full-text searchable without
    any extra client write — a tsvector can't be set correctly over PostgREST,
    so the database side owns it. (Run sql/enable_fts.sql once to install it.)
    """
    payload = build_intelligence_payload(job, result)
    try:
        client.table("intelligence_items").upsert(payload, on_conflict="raw_item_id").execute()
    except Exception as e:
        if _is_missing_column_error(e):
            log.warning(
                "[GEMINI] intelligence_items is missing the new columns — run "
                "sql/add_tags_column.sql in Supabase. Upserting without "
                f"{', '.join(_OPTIONAL_COLUMNS)} for now."
            )
            reduced = {k: v for k, v in payload.items() if k not in _OPTIONAL_COLUMNS}
            client.table("intelligence_items").upsert(reduced, on_conflict="raw_item_id").execute()
        else:
            raise


def update_job_status(job_id, status, error=None):
    """Update a processing job's status (done/failed)."""
    try:
        update_data = {"status": status}
        if status == "failed" and error:
            update_data["error_message"] = str(error)[:500]
        client.table("processing_jobs").update(update_data).eq("id", job_id).execute()
    except Exception as e:
        log.error(f"[GEMINI] update_job_status failed for {job_id}: {e}")


def mark_job_pending(job_id):
    """Return a job to the pending queue, clearing any prior error.

    Used when we stop a run early (e.g. on a 429) so the untouched job is
    retried on the next run rather than being marked failed."""
    try:
        client.table("processing_jobs").update(
            {"status": "pending", "error_message": None}
        ).eq("id", job_id).execute()
    except Exception as e:
        log.error(f"[GEMINI] mark_job_pending failed for {job_id}: {e}")


def reset_failed_jobs():
    """Reset every failed job back to pending so it's eligible again.

    Many past failures were transient 429s, so we give them another chance on
    each run instead of leaving them stuck in 'failed'."""
    try:
        result = (
            client.table("processing_jobs")
            .update({"status": "pending", "retries": 0, "error_message": None})
            .eq("status", "failed")
            .execute()
        )
        count = len(result.data or [])
        if count:
            log.info(f"[GEMINI] Reset {count} failed job(s) back to pending")
    except Exception as e:
        log.error(f"[GEMINI] reset_failed_jobs failed: {e}")


def _last_run_quota_exceeded():
    """True if the most recent enrichment log recorded a quota_exceeded status."""
    try:
        result = (
            client.table("ingestion_logs")
            .select("status")
            .eq("scenario_name", ENRICHMENT_SCENARIO)
            .order("started_at", desc=True)
            .limit(1)
            .execute()
        )
        if result.data:
            return result.data[0].get("status") == "quota_exceeded"
    except Exception as e:
        log.error(f"[GEMINI] quota-state check failed: {e}")
    return False


def _log_quota_exceeded(started_at, items_processed):
    """Record a quota_exceeded marker in ingestion_logs so the next run skips."""
    try:
        client.table("ingestion_logs").insert({
            "scenario_name": ENRICHMENT_SCENARIO,
            "started_at": started_at,
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "status": "quota_exceeded",
            "items_fetched": items_processed,
            "items_inserted": 0,
            "items_skipped_dedup": 0,
            "errors": ["Daily Gemini quota reached (429)"],
            "make_execution_id": "",
        }).execute()
    except Exception as e:
        log.error(f"[GEMINI] failed to write quota_exceeded log: {e}")


def _build_alert_item(job, result):
    """Assemble the dict consumed by notifier.send_critical_alert()."""
    iocs = result.get("iocs", {}) or {}
    return {
        "severity": result.get("severity"),
        "source": result.get("category") or "OSINT",
        "title": job.get("title"),
        "confidence": result.get("confidence"),
        "category": result.get("category"),
        "actors": result.get("actors", []),
        "cves": result.get("cves", []),
        "mitre": result.get("mitre_techniques", []),
        # Flatten hashes so the alert can render them inside <code> blocks.
        "iocs": iocs,
        "summary_en": result.get("summary_en"),
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }


def _handle_notifications(job, result, stats):
    """Tally severity for this enriched item and dispatch urgent alerts.

    Alert rules:
      - every CRITICAL item -> immediate alert
      - every HIGH item with israel_relevance=True -> immediate alert
    """
    severity = (result.get("severity") or "").strip().lower()
    if severity in ("critical", "high", "medium", "low"):
        stats[severity] += 1

    if severity == "critical":
        send_critical_alert(_build_alert_item(job, result))
    elif severity == "high" and bool(result.get("israel_relevance", False)):
        send_critical_alert(_build_alert_item(job, result))


def run_enrichment(limit=50):
    """Main orchestrator — enrich pending jobs one by one.

    Processes at most MAX_ITEMS_PER_RUN items per call to stay within the free
    Gemini tier, sleeping CALL_DELAY_SECONDS between calls.
    """
    stats = {"processed": 0, "succeeded": 0, "failed": 0, "skipped": 0,
             "critical": 0, "high": 0, "medium": 0, "low": 0,
             "quota_exceeded": False, "errors": []}
    started_at = datetime.now(timezone.utc).isoformat()

    # If the previous run hit the daily quota, don't even start — wait until a
    # later run records a clean status (i.e. the quota has reset).
    if _last_run_quota_exceeded():
        log.warning("[GEMINI] Daily quota was exhausted on the last run — skipping this run.")
        stats["quota_exceeded"] = True
        return stats

    # Transient 429s in the past left jobs stuck in 'failed'; give them another go.
    reset_failed_jobs()

    # Fetch the requested number of pending jobs, order them by priority
    # (CRITICAL/HIGH and high-value sources first), then cap how many we
    # actually process this run so we don't blow through the free-tier limit.
    fetched = get_pending_jobs(limit=limit)
    ordered = prioritize_jobs(fetched)
    jobs = ordered[:MAX_ITEMS_PER_RUN]
    stats["skipped"] = len(fetched) - len(jobs)
    log.info(
        f"[GEMINI] {len(fetched)} pending jobs fetched — processing {len(jobs)} "
        f"by priority (cap={MAX_ITEMS_PER_RUN}), skipping {stats['skipped']} for next run"
    )

    for i, job in enumerate(jobs):
        # Throttle between calls (not before the first one).
        if i > 0:
            time.sleep(CALL_DELAY_SECONDS)

        stats["processed"] += 1
        job_id = job.get("job_id")
        try:
            prompt = build_prompt(job["title"], job["raw_content"])
            result = call_gemini_with_retry(prompt)
            insert_intelligence_item(job, result)
            update_job_status(job_id, "done")
            stats["succeeded"] += 1
            log.info(f"[GEMINI] Enriched job {job_id} — {str(job.get('title'))[:60]}")

            # Tally severity and fire Telegram alerts for the urgent items.
            # Notification failures must never break enrichment, so this is
            # fully isolated behind its own try/except.
            try:
                _handle_notifications(job, result, stats)
            except Exception as notify_err:
                log.error(f"[GEMINI] Notification step failed (non-fatal): {notify_err}")
        except Exception as e:
            # A 429 means the daily quota is gone. Don't retry and don't fail the
            # job — return it to pending, record the quota state, and stop.
            if _is_rate_limit_error(e):
                log.warning("[GEMINI] Daily quota reached, stopping enrichment.")
                stats["processed"] -= 1  # this job never completed — back to pending
                mark_job_pending(job_id)
                _log_quota_exceeded(started_at, stats["succeeded"])
                stats["quota_exceeded"] = True
                break

            stats["failed"] += 1
            msg = f"job {job_id}: {str(e)[:200]}"
            stats["errors"].append(msg)
            log.error(f"[GEMINI] Enrichment failed for {msg}")
            update_job_status(job_id, "failed", error=str(e))
            continue

    log.info(
        f"[GEMINI] Enrichment complete — processed={stats['processed']} "
        f"succeeded={stats['succeeded']} failed={stats['failed']} "
        f"skipped={stats['skipped']}"
    )

    # Batch-complete summary notification (only sends when succeeded > 0).
    # Isolated so a Telegram outage can never affect the enrichment result.
    if stats["succeeded"] > 0:
        try:
            notify_enrichment_complete(stats)
        except Exception as e:
            log.error(f"[GEMINI] notify_enrichment_complete failed (non-fatal): {e}")

    return stats


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    result_stats = run_enrichment()
    print("Enrichment stats:")
    print(f"  processed : {result_stats['processed']}")
    print(f"  succeeded : {result_stats['succeeded']}")
    print(f"  failed    : {result_stats['failed']}")
    print(f"  skipped   : {result_stats['skipped']}")
    for err in result_stats["errors"]:
        print(f"  error: {err}")
