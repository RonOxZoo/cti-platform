import feedparser
import requests
from datetime import datetime, timezone, timedelta
from utils.hashing import compute_hash
from database.supabase_client import hash_exists, insert_raw_item, insert_processing_job, update_source_last_polled

LOOKBACK_HOURS = 24
FEED_TIMEOUT = 15
HEADERS = {'User-Agent': 'CTIPlatform/1.0'}

def parse_date(entry):
    for field in ['published_parsed', 'updated_parsed']:
        val = getattr(entry, field, None)
        if val:
            try:
                return datetime(*val[:6], tzinfo=timezone.utc).isoformat()
            except:
                pass
    return datetime.now(timezone.utc).isoformat()

def is_recent(entry):
    for field in ['published_parsed', 'updated_parsed']:
        val = getattr(entry, field, None)
        if val:
            try:
                dt = datetime(*val[:6], tzinfo=timezone.utc)
                return dt >= datetime.now(timezone.utc) - timedelta(hours=LOOKBACK_HOURS)
            except:
                pass
    return True

def get_content(entry):
    if hasattr(entry, 'content') and entry.content:
        return entry.content[0].get('value', '')
    if hasattr(entry, 'summary'):
        return entry.summary
    return entry.get('title', '')

def fetch_source(source):
    source_id = source['id']
    source_url = source['url']
    source_name = source['name']
    stats = {'source': source_name, 'fetched': 0, 'inserted': 0, 'skipped': 0, 'errors': []}
    print(f'[RSS] {source_name}')
    print(f'      {source_url}')
    try:
        response = requests.get(source_url, headers=HEADERS, timeout=FEED_TIMEOUT)
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
    for source in sources:
        result = fetch_source(source)
        total['fetched'] += result['fetched']
        total['inserted'] += result['inserted']
        total['skipped'] += result['skipped']
        total['errors'].extend(result['errors'])
        total['sources_processed'] += 1
        if result['errors']:
            total['sources_failed'] += 1
    return total
