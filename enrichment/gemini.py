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

import google.generativeai as genai

from database.supabase_client import client

log = logging.getLogger(__name__)

# Free-tier-friendly model.
GEMINI_MODEL = "gemini-2.0-flash"

# Free-tier rate-limit protection.
CALL_DELAY_SECONDS = 5        # delay between consecutive Gemini calls
MAX_ITEMS_PER_RUN = 3         # hard cap on items processed per /enrich call

# ingestion_logs scenario name used to record enrichment quota state. Kept
# distinct from the RSS scenario so RSS runs don't overwrite the quota marker.
ENRICHMENT_SCENARIO = "python_gemini_enrichment"

SYSTEM_INSTRUCTION = """ROLE: You are a Cyber Threat Intelligence analyst-agent for an OSINT platform.
You process ONLY lawfully-obtained, publicly-published sources.

INPUT: One feed item with source_name, raw_title, raw_body.

STEP 1 — EXTRACTION:
Extract: IPs, domains, hashes (MD5/SHA1/SHA256), URLs, emails, CVE IDs, threat-actor names, MITRE ATT&CK techniques (TXXXX).
Categorize: Global | Israel | Iran | Russia | China | Phishing | CVE | Infrastructure | APT.

STEP 2 — SEVERITY (justify in one sentence):
Critical = global impact / critical infra / zero-day
High = active campaign / known APT / sensitive data
Medium = known vuln / targeted phishing
Low = background / research / first disclosure

STEP 3 — CONFIDENCE (0-100): state what reduced confidence and what data would raise it.

STEP 4 — SUMMARY:
Write a professional 3-5 sentence intelligence summary in English.
Then write the same summary in Hebrew. Label it [HEBREW SUMMARY].
Use correct Hebrew cybersecurity terminology.

OUTPUT: Return ONLY valid JSON with these fields:
{
  "category": "",
  "severity": "",
  "severity_reason": "",
  "confidence": 0,
  "confidence_reason": "",
  "iocs": {"ips": [], "domains": [], "urls": [], "hashes": [], "emails": []},
  "cves": [],
  "actors": [],
  "mitre": [],
  "summary_en": "",
  "summary_he": "",
  "israel_relevance": false,
  "iran_nexus": false
}
No preamble. No markdown. Pure JSON only."""


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


def build_prompt(title, raw_content):
    """Build the full prompt string for a single feed item."""
    return (
        f"{SYSTEM_INSTRUCTION}\n\n"
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

    genai.configure(api_key=api_key)
    model = genai.GenerativeModel(GEMINI_MODEL)

    response = model.generate_content(prompt)

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


def insert_intelligence_item(job, result):
    """Insert an enriched intelligence item into intelligence_items."""
    payload = {
        "raw_item_id": job["raw_item_id"],
        "source_id": job["source_id"],
        "category": result["category"],
        "severity": result["severity"],
        "severity_reason": result["severity_reason"],
        "confidence": result["confidence"],
        "confidence_reason": result["confidence_reason"],
        "iocs": result["iocs"],
        "cves": result["cves"],
        "actors": result["actors"],
        "mitre": result["mitre"],
        "summary_en": result["summary_en"],
        "summary_he": result["summary_he"],
        "israel_relevance": result["israel_relevance"],
        "iran_nexus": result["iran_nexus"],
        "enriched_at": datetime.now(timezone.utc).isoformat(),
    }
    client.table("intelligence_items").insert(payload).execute()


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


def run_enrichment(limit=50):
    """Main orchestrator — enrich pending jobs one by one.

    Processes at most MAX_ITEMS_PER_RUN items per call to stay within the free
    Gemini tier, sleeping CALL_DELAY_SECONDS between calls.
    """
    stats = {"processed": 0, "succeeded": 0, "failed": 0, "skipped": 0,
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

    # Fetch the requested number of pending jobs, then cap how many we actually
    # process this run so we don't blow through the free-tier rate limit.
    fetched = get_pending_jobs(limit=limit)
    jobs = fetched[:MAX_ITEMS_PER_RUN]
    stats["skipped"] = len(fetched) - len(jobs)
    log.info(
        f"[GEMINI] {len(fetched)} pending jobs fetched — processing {len(jobs)} "
        f"(cap={MAX_ITEMS_PER_RUN}), skipping {stats['skipped']} for next run"
    )

    for i, job in enumerate(jobs):
        # Throttle between calls (not before the first one).
        if i > 0:
            time.sleep(CALL_DELAY_SECONDS)

        stats["processed"] += 1
        job_id = job.get("job_id")
        try:
            prompt = build_prompt(job["title"], job["raw_content"])
            result = call_gemini(prompt)
            insert_intelligence_item(job, result)
            update_job_status(job_id, "done")
            stats["succeeded"] += 1
            log.info(f"[GEMINI] Enriched job {job_id} — {str(job.get('title'))[:60]}")
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
