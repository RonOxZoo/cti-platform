import time
import random
import logging
import feedparser
import requests
from urllib.parse import urlparse
from datetime import datetime, timezone, timedelta
from utils.hashing import compute_hash
from database.supabase_client import hash_exists, insert_raw_item, insert_processing_job, update_source_last_polled

log = logging.getLogger(__name__)

LOOKBACK_HOURS = 24
FEED_TIMEOUT = 25

# Real-world Chrome/Firefox User-Agent strings used for browser fingerprinting.
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


def create_session() -> requests.Session:
    """Return a requests.Session pre-configured with browser headers."""
    session = requests.Session()
    # Seed with generic headers; per-request Referer is set in fetch_source.
    session.headers.update(get_browser_headers(""))
    return session


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


def fetch_source(source, session=None):
    source_id = source['id']
    source_url = source['url']
    source_name = source['name']
    stats = {'source': source_name, 'fetched': 0, 'inserted': 0, 'skipped': 0, 'errors': []}
    if session is None:
        session = create_session()
    headers = get_browser_headers(source_url)
    print(f'[RSS] {source_name}')
    print(f'      {source_url}')
    try:
        try:
            response = session.get(source_url, headers=headers, timeout=FEED_TIMEOUT)
        except requests.exceptions.SSLError as ssl_err:
            log.warning(f"[RSS] SSL error for {source_name}, retrying with verify=False: {ssl_err}")
            response = session.get(source_url, headers=headers, timeout=FEED_TIMEOUT, verify=False)
        response.raise_for_status()
        feed = feedparser.parse(response.content)
        if feed.bozo and not feed.entries:
            stats['errors'].append(f'Parse error: {feed.bozo_exception}')
            update_source_last_polled(source_id, error=True)
            return stats
        print(f'      {len(feed.entries)} entries found')
        for entry in feed.entries:
            if not is_recent(entry):
                continue
            stats['fetched'] += 1
            title = entry.get('title', '').strip()
            url = entry.get('link', '').strip()
            content = get_content(entry)
            pub_date = parse_date(entry)
            if not url:
                stats['skipped'] += 1
                continue
            content_hash = compute_hash(title, url, pub_date)
            if hash_exists(content_hash):
                stats['skipped'] += 1
                print(f'      Duplicate: {title[:60]}')
                continue
            raw_item_id = insert_raw_item(source_id, url, title, content, content_hash, pub_date)
            if raw_item_id:
                insert_processing_job(raw_item_id)
                stats['inserted'] += 1
                print(f'      OK: {title[:60]}')
            else:
                stats['errors'].append(f'Insert failed: {title[:60]}')
        update_source_last_polled(source_id)
    except requests.exceptions.Timeout:
        stats['errors'].append(f'Timeout after {FEED_TIMEOUT}s')
        update_source_last_polled(source_id, error=True)
    except Exception as e:
        stats['errors'].append(str(e)[:100])
        update_source_last_polled(source_id, error=True)
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
