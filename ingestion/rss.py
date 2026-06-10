import os
import time
import json
import random
import logging
import feedparser
import requests
from curl_cffi import requests as cffi_requests
from curl_cffi.requests import exceptions as cffi_exc
from urllib.parse import urlparse
from datetime import datetime, timezone, timedelta
from utils.hashing import compute_hash
from config import BROWSER_SERVICE_URL, FULL_FETCH_THRESHOLD
from database.supabase_client import (
    hash_exists,
    insert_raw_item,
    insert_processing_job,
    update_source_last_polled,
    record_source_failure,
)

log = logging.getLogger(__name__)

LOOKBACK_HOURS = 24
FEED_TIMEOUT = 25

# curl_cffi TLS-fingerprint impersonation targets. We rotate between several
# Chrome releases so successive requests don't share an identical fingerprint.
CHROME_VERSIONS = ["chrome110", "chrome116", "chrome120", "chrome124"]

# Real-world Chrome/Firefox User-Agent strings kept as a backup signal layered
# on top of the curl_cffi TLS impersonation.
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0",
]


def get_browser_headers(url: str) -> dict:
    """Build a realistic browser header dict for the given URL."""
    referer = ""
    try:
        parsed = urlparse(url)
        if parsed.scheme and parsed.netloc:
            referer = f"{parsed.scheme}://{parsed.netloc}"
    except Exception:
        referer = ""
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Cache-Control": "no-cache",
    }
    if referer:
        headers["Referer"] = referer
    return headers


def create_session():
    """Return a curl_cffi Session pre-seeded with browser headers.

    The session carries cookies across requests; per-request impersonation and
    Referer are applied in fetch_source.
    """
    session = cffi_requests.Session()
    session.headers.update(get_browser_headers(""))
    return session


def _curl_get(url: str, headers: dict, session=None, verify: bool = True):
    """GET a URL via curl_cffi, impersonating a randomly chosen Chrome release.

    The rotating impersonate target gives each request a genuine Chrome TLS/JA3
    fingerprint, which is what defeats most 403 bot blocks.
    """
    impersonate = random.choice(CHROME_VERSIONS)
    getter = session.get if session is not None else cffi_requests.get
    return getter(
        url,
        headers=headers,
        timeout=FEED_TIMEOUT,
        impersonate=impersonate,
        verify=verify,
    )


def parse_date(entry):
    for field in ['published_parsed', 'updated_parsed']:
        val = getattr(entry, field, None)
        if val:
            try:
                return datetime(*val[:6], tzinfo=timezone.utc).isoformat()
            except Exception:
                pass
    return datetime.now(timezone.utc).isoformat()


def is_recent(entry):
    for field in ['published_parsed', 'updated_parsed']:
        val = getattr(entry, field, None)
        if val:
            try:
                dt = datetime(*val[:6], tzinfo=timezone.utc)
                return dt >= datetime.now(timezone.utc) - timedelta(hours=LOOKBACK_HOURS)
            except Exception:
                pass
    return True


def get_content(entry):
    if hasattr(entry, 'content') and entry.content:
        return entry.content[0].get('value', '')
    if hasattr(entry, 'summary'):
        return entry.summary
    return entry.get('title', '')


def fetch_via_browser_service(url: str, source_name: str) -> str:
    """
    Call the browser microservice to fetch a URL that blocked direct HTTP.
    Returns the raw response body as text, or raises on failure.
    """
    if not BROWSER_SERVICE_URL:
        raise RuntimeError("BROWSER_SERVICE_URL not configured")
    api_key = os.getenv("API_SECRET_KEY", "")
    resp = requests.post(
        f"{BROWSER_SERVICE_URL}/fetch",
        json={"url": url, "source_name": source_name},
        headers={"X-API-Key": api_key},
        timeout=60,
    )
    resp.raise_for_status()
    data = resp.json()
    if data.get("status") == "failed":
        raise RuntimeError(f"Browser service error: {data.get('error')}")
    return data.get("content", "")


# ── Feed-type detection ──────────────────────────────────────────────────────

def _is_json_url(url: str) -> bool:
    """True if the URL path points at a .json document."""
    try:
        path = urlparse(url).path.lower()
    except Exception:
        path = url.lower()
    return path.endswith(".json")


def _is_json_response(response) -> bool:
    """True if the response advertises a JSON content type."""
    ctype = ""
    try:
        ctype = (response.headers.get("content-type") or "").lower()
    except Exception:
        pass
    return "application/json" in ctype or "text/json" in ctype


# ── Item ingestion ───────────────────────────────────────────────────────────

def maybe_fetch_full_article(title, url, content, source_name):
    """Return full article text for short RSS excerpts; otherwise the excerpt.

    Token-efficiency / resource trade-off: feeds that already deliver the full
    body (>= FULL_FETCH_THRESHOLD chars) are used as-is — no Playwright call.
    Only genuinely short excerpts trigger the (expensive) browser-service fetch,
    so Claude analyzes complete articles without us hammering the browser
    service for feeds that don't need it. Falls back to the excerpt on any error.
    """
    content = content or ""
    if len(content) >= FULL_FETCH_THRESHOLD:
        log.info(f"[FETCH] Using RSS content (sufficient length) for: {title}")
        return content
    if not (url and BROWSER_SERVICE_URL):
        # Can't fetch — keep whatever excerpt we have.
        return content
    try:
        full = fetch_via_browser_service(url, source_name)
        if full and len(full) > len(content):
            log.info(f"[FETCH] Full article fetched via Playwright for: {title}")
            return full
    except Exception as e:
        log.warning(f"[FETCH] Full-article fetch failed for {title!r}: {str(e)[:120]}")
    return content


def _ingest_item(title, url, content, pub_date, source_id, source_name, stats):
    """Dedup and insert a single normalized item (shared by RSS + JSON paths)."""
    title = (title or "").strip()
    url = (url or "").strip()
    if not url:
        stats['skipped'] += 1
        return
    # Upgrade short excerpts to the full article before dedup/insert.
    content = maybe_fetch_full_article(title, url, content, source_name)
    content_hash = compute_hash(title, url, pub_date)
    if hash_exists(content_hash):
        stats['skipped'] += 1
        print(f'      Duplicate: {title[:60]}')
        return
    raw_item_id = insert_raw_item(source_id, url, title, content, content_hash, pub_date)
    if raw_item_id:
        insert_processing_job(raw_item_id)
        stats['inserted'] += 1
        print(f'      OK: {title[:60]}')
    else:
        stats['errors'].append(f'Insert failed: {title[:60]}')


def _process_feed(feed, source_id, source_name, stats):
    """Process a parsed RSS/Atom feed's entries into raw_items + processing_jobs."""
    if feed.bozo and not feed.entries:
        stats['errors'].append(f'Parse error: {feed.bozo_exception}')
        update_source_last_polled(source_id, error=True)
        return stats
    print(f'      {len(feed.entries)} entries found')
    for entry in feed.entries:
        if not is_recent(entry):
            continue
        stats['fetched'] += 1
        _ingest_item(
            title=entry.get('title', ''),
            url=entry.get('link', ''),
            content=get_content(entry),
            pub_date=parse_date(entry),
            source_id=source_id,
            source_name=source_name,
            stats=stats,
        )
    update_source_last_polled(source_id)
    return stats


# ── JSON feed parsing ────────────────────────────────────────────────────────

def _parse_iso_date(value) -> str:
    """Best-effort parse of a date string into a UTC ISO timestamp."""
    if not value:
        return datetime.now(timezone.utc).isoformat()
    text = str(value).strip()
    # CISA KEV uses bare YYYY-MM-DD; JSON Feed uses RFC 3339.
    for parser in (
        lambda t: datetime.fromisoformat(t.replace("Z", "+00:00")),
        lambda t: datetime.strptime(t, "%Y-%m-%d"),
    ):
        try:
            dt = parser(text)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat()
        except Exception:
            continue
    return datetime.now(timezone.utc).isoformat()


def _json_is_recent(pub_date_iso: str) -> bool:
    try:
        dt = datetime.fromisoformat(pub_date_iso)
        return dt >= datetime.now(timezone.utc) - timedelta(hours=LOOKBACK_HOURS)
    except Exception:
        return True


def parse_json_feed(raw_text: str):
    """Normalize a JSON feed body into a list of item dicts.

    Supports two shapes:
      * CISA KEV  — {"vulnerabilities": [{cveID, vulnerabilityName, ...}]}
      * JSON Feed — {"items": [{title, url, content_html|content_text, ...}]}

    Returns a list of {title, url, content, pub_date} dicts.
    """
    data = json.loads(raw_text)
    items = []

    # CISA Known Exploited Vulnerabilities catalog.
    if isinstance(data, dict) and isinstance(data.get("vulnerabilities"), list):
        for v in data["vulnerabilities"]:
            cve = (v.get("cveID") or "").strip()
            vendor = (v.get("vendorProject") or "").strip()
            product = (v.get("product") or "").strip()
            name = (v.get("vulnerabilityName") or "").strip()
            title = f"{cve} — {name}".strip(" —") or cve or name
            body = (
                f"{vendor} {product}: {v.get('shortDescription', '')}\n"
                f"Required action: {v.get('requiredAction', '')}\n"
                f"Date added: {v.get('dateAdded', '')}  Due: {v.get('dueDate', '')}"
            ).strip()
            # KEV has no per-CVE link; the canonical NVD detail page is stable
            # and gives the enrichment stage a real reference URL.
            url = f"https://nvd.nist.gov/vuln/detail/{cve}" if cve else ""
            items.append({
                "title": title,
                "url": url,
                "content": body,
                "pub_date": _parse_iso_date(v.get("dateAdded")),
            })
        return items

    # Generic JSON Feed (jsonfeed.org).
    if isinstance(data, dict) and isinstance(data.get("items"), list):
        for it in data["items"]:
            items.append({
                "title": it.get("title", ""),
                "url": it.get("url") or it.get("external_url") or it.get("id") or "",
                "content": it.get("content_html") or it.get("content_text") or it.get("summary", ""),
                "pub_date": _parse_iso_date(it.get("date_published") or it.get("date_modified")),
            })
        return items

    raise ValueError("Unrecognized JSON feed structure (no 'vulnerabilities' or 'items')")


def _process_json_feed(raw_text, source_id, source_name, stats):
    """Process a JSON feed body into raw_items + processing_jobs."""
    try:
        items = parse_json_feed(raw_text)
    except Exception as e:
        stats['errors'].append(f'JSON parse error: {str(e)[:120]}')
        update_source_last_polled(source_id, error=True)
        return stats
    print(f'      {len(items)} JSON items found')
    for item in items:
        if not _json_is_recent(item["pub_date"]):
            continue
        stats['fetched'] += 1
        _ingest_item(
            title=item["title"],
            url=item["url"],
            content=item["content"],
            pub_date=item["pub_date"],
            source_id=source_id,
            source_name=source_name,
            stats=stats,
        )
    update_source_last_polled(source_id)
    return stats


# ── Fetch orchestration ──────────────────────────────────────────────────────

def _process_body(raw_text, is_json, source_id, source_name, stats):
    """Route a fetched body to the JSON or RSS/Atom processor."""
    if is_json:
        return _process_json_feed(raw_text, source_id, source_name, stats)
    feed = feedparser.parse(raw_text)
    return _process_feed(feed, source_id, source_name, stats)


def _browser_fallback(source, is_json, stats):
    """Tier 2 → Tier 3: try the Playwright browser service; on failure record a
    source failure (which auto-disables the source after repeated failures)."""
    source_id, source_url, source_name = source['id'], source['url'], source['name']
    log.info(f"[RSS] Using browser service fallback for {source_name}")
    try:
        content = fetch_via_browser_service(source_url, source_name)
        return _process_body(content, is_json, source_id, source_name, stats)
    except Exception as browser_err:
        stats['errors'].append(f"Browser fallback failed: {str(browser_err)[:100]}")
        record_source_failure(source_id, source_name)
        return stats


def fetch_source(source, session=None):
    source_id = source['id']
    source_url = source['url']
    source_name = source['name']
    stats = {'source': source_name, 'fetched': 0, 'inserted': 0, 'skipped': 0, 'errors': []}
    headers = get_browser_headers(source_url)
    is_json = _is_json_url(source_url)
    print(f'[RSS] {source_name}')
    print(f'      {source_url}')
    try:
        # Tier 1: curl_cffi with a rotating Chrome TLS fingerprint.
        try:
            response = _curl_get(source_url, headers, session=session)
        except cffi_exc.SSLError as ssl_err:
            log.warning(f"[RSS] SSL error for {source_name}, retrying with verify=False: {ssl_err}")
            response = _curl_get(source_url, headers, session=session, verify=False)
        except cffi_exc.Timeout:
            # Tier 2: hand off to the browser service.
            log.info(f"[RSS] Browser fallback for {source_name} (timeout)")
            return _browser_fallback(source, is_json, stats)

        # Tier 2: bot-block status codes → browser service.
        if response.status_code in (403, 429):
            log.info(f"[RSS] Browser fallback for {source_name} (HTTP {response.status_code})")
            return _browser_fallback(source, is_json, stats)

        response.raise_for_status()
        # Trust the JSON content-type even if the URL didn't end in .json.
        return _process_body(
            response.text,
            is_json or _is_json_response(response),
            source_id,
            source_name,
            stats,
        )
    except Exception as e:
        stats['errors'].append(str(e)[:100])
        record_source_failure(source_id, source_name)
    return stats


def run_rss_ingestion(sources):
    total = {'fetched': 0, 'inserted': 0, 'skipped': 0, 'errors': [], 'sources_processed': 0, 'sources_failed': 0}
    session = create_session()
    for source in sources:
        result = fetch_source(source, session=session)
        total['fetched'] += result['fetched']
        total['inserted'] += result['inserted']
        total['skipped'] += result['skipped']
        total['errors'].extend(result['errors'])
        total['sources_processed'] += 1
        if result['errors']:
            total['sources_failed'] += 1
        # Random delay between feed fetches to mimic human browsing.
        time.sleep(random.uniform(1, 3))
    return total
