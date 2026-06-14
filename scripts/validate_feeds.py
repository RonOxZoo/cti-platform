"""
Validate every active RSS feed in rss_sources and report the dead ones.

Run from the project root:  python -m scripts.validate_feeds

What it does
------------
* Loads active sources from the rss_sources Supabase table.
* For each source with ingest_method = 'rss' (scrape sources are SKIPPED):
    - sends a fast HTTP HEAD (no body download);
    - on HEAD failure / 405, retries once with a streamed GET (timeout 5s);
    - classifies the result: healthy | dead | redirected | auth_required |
      scrape_needed.
* Is polite: one request per second, realistic descriptive User-Agent.
* Writes dead_feeds.csv (source_name, url, status_code, error_reason,
  recommendation) for everything that is not healthy.
* Prints a summary: X healthy, Y dead, Z need scraping.

It is strictly read-only: it never bypasses authentication, never accesses
private sources, and never modifies the database.
"""
import csv
import time
import logging

import requests

from database.supabase_client import client

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("validate_feeds")

USER_AGENT = "CTIPlatform/1.0 (feed validator)"
REQUEST_TIMEOUT = 5          # seconds
RATE_LIMIT_SECONDS = 1.0     # be polite: max 1 request / second
OUTPUT_CSV = "dead_feeds.csv"

# Statuses considered "not healthy" and therefore written to dead_feeds.csv.
_REPORTABLE = {"dead", "redirected", "auth_required", "scrape_needed"}


def load_active_rss_sources() -> list:
    """Return active sources, each as {name, url, ingest_method}.

    ingest_method may be absent on databases seeded before seed_all_feeds.sql —
    such rows are treated as 'rss' (the historical default).
    """
    try:
        res = (client.table("rss_sources")
               .select("name, url, ingest_method, active")
               .eq("active", True)
               .execute())
    except Exception:
        # Older schema without ingest_method — fall back to the minimal columns.
        res = (client.table("rss_sources")
               .select("name, url, active")
               .eq("active", True)
               .execute())
    out = []
    for row in (res.data or []):
        out.append({
            "name": row.get("name") or "",
            "url": (row.get("url") or "").strip(),
            "ingest_method": (row.get("ingest_method") or "rss").strip().lower(),
        })
    return out


def _classify(resp) -> tuple:
    """Map an HTTP response to (status, status_code, reason, recommendation)."""
    code = resp.status_code
    if code in (401, 403):
        return ("auth_required", code, f"HTTP {code} (authentication/forbidden)",
                "Source requires auth or blocks bots — switch to scrape or remove")
    if code in (402,):
        return ("auth_required", code, f"HTTP {code} (payment required)",
                "Paywalled — remove or replace with a free feed")
    if 300 <= code < 400:
        loc = resp.headers.get("Location", "")
        return ("redirected", code, f"HTTP {code} -> {loc[:120]}",
                f"Update url to the redirect target: {loc[:200]}")
    if 400 <= code:
        return ("dead", code, f"HTTP {code}",
                "Feed returned an error — verify URL or replace the source")
    return ("healthy", code, "", "")


def validate_one(source: dict) -> dict:
    """Validate a single RSS source. Returns a result dict (never raises)."""
    url = source["url"]
    headers = {"User-Agent": USER_AGENT, "Accept": "application/rss+xml, application/xml, text/xml, */*"}
    result = {"source_name": source["name"], "url": url,
              "status": "dead", "status_code": "", "error_reason": "",
              "recommendation": ""}
    if not url:
        result["error_reason"] = "empty url"
        result["recommendation"] = "Remove the source — it has no URL"
        return result

    # 1) Fast HEAD.
    try:
        resp = requests.head(url, headers=headers, timeout=REQUEST_TIMEOUT,
                             allow_redirects=False)
        # Some servers reject HEAD (405) or return nothing useful — fall through.
        if resp.status_code != 405:
            status, code, reason, rec = _classify(resp)
            if status == "healthy":
                result.update(status="healthy", status_code=code)
                return result
            result.update(status=status, status_code=code, error_reason=reason,
                          recommendation=rec)
            # For redirects/auth we already have a verdict; for a generic error
            # give GET a chance (some hosts 4xx on HEAD only).
            if status in ("redirected", "auth_required"):
                return result
    except requests.RequestException as e:
        result["error_reason"] = f"HEAD failed: {str(e)[:160]}"

    # 2) Streamed GET fallback (don't download the whole body).
    try:
        resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT,
                            allow_redirects=False, stream=True)
        try:
            status, code, reason, rec = _classify(resp)
        finally:
            resp.close()
        if status == "healthy":
            result.update(status="healthy", status_code=code, error_reason="",
                          recommendation="")
        else:
            result.update(status=status, status_code=code, error_reason=reason,
                          recommendation=rec)
    except requests.RequestException as e:
        result.update(status="dead", status_code="",
                      error_reason=f"GET failed: {str(e)[:160]}",
                      recommendation="Unreachable — DNS/TLS/timeout. Verify or remove")
    return result


def main():
    log.info("Loading active sources from rss_sources …")
    sources = load_active_rss_sources()
    rss = [s for s in sources if s["ingest_method"] == "rss"]
    scrape = [s for s in sources if s["ingest_method"] != "rss"]
    log.info(f"{len(sources)} active sources: {len(rss)} rss, {len(scrape)} scrape (skipped)")

    results = []
    healthy = dead = need_scrape = 0
    for i, src in enumerate(rss):
        if i > 0:
            time.sleep(RATE_LIMIT_SECONDS)  # polite: 1 req/sec
        r = validate_one(src)
        results.append(r)
        if r["status"] == "healthy":
            healthy += 1
        elif r["status"] == "auth_required":
            need_scrape += 1
        else:
            dead += 1
        log.info(f"  [{r['status']:>13}] {r['status_code'] or '---':>4}  {src['name']}")

    # Reclassify auth_required rows as "scrape_needed" recommendations in the CSV.
    reportable = [r for r in results if r["status"] in _REPORTABLE]
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["source_name", "url", "status_code", "error_reason", "recommendation"])
        for r in reportable:
            w.writerow([r["source_name"], r["url"], r["status_code"],
                        r["error_reason"], r["recommendation"]])

    print("\n" + "=" * 60)
    print("FEED VALIDATION SUMMARY")
    print("=" * 60)
    print(f"  Checked (rss)     : {len(rss)}")
    print(f"  Healthy           : {healthy}")
    print(f"  Dead / error      : {dead}")
    print(f"  Auth/scrape needed: {need_scrape}")
    print(f"  Skipped (scrape)  : {len(scrape)}")
    print(f"  Report written    : {OUTPUT_CSV} ({len(reportable)} rows)")
    print("=" * 60)


if __name__ == "__main__":
    main()
