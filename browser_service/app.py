import os
import time
import random
import socket
import logging
import ipaddress
from collections import deque, defaultdict
from datetime import datetime, timezone
from functools import wraps
from urllib.parse import urlparse

from flask import Flask, request, jsonify
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger(__name__)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # 16 KB request body limit

# --- Configuration ---
API_SECRET_KEY = os.getenv("API_SECRET_KEY")
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

# Same UA strings as the main ingestion service (ingestion/rss.py).
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0",
]

# --- Rate limiting state (in-memory, per-IP rolling window) ---
# Fetches from cti-platform are strictly sequential (one Chromium instance at a
# time, closed before the next), so this isn't protecting against concurrent
# load — it was simply too tight for a single ingestion run, which can need the
# fallback for a dozen-plus sources back-to-back and was self-triggering 429s.
RATE_LIMIT_MAX = 30
RATE_LIMIT_WINDOW = 60  # seconds
_rate_buckets = defaultdict(deque)

MAX_URL_LENGTH = 2048

# Private / loopback networks for SSRF protection.
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
]

# --- Supabase client (lazy) ---
_supabase = None


def get_supabase():
    global _supabase
    if _supabase is None and SUPABASE_URL and SUPABASE_KEY:
        try:
            from supabase import create_client
            _supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
        except Exception as e:
            log.error("[BROWSER] Supabase init failed: %s", e)
            _supabase = None
    return _supabase


def domain_of(url: str) -> str:
    """Return scheme://netloc only — never log full URLs."""
    try:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
    except Exception:
        return "(unparseable)"


def _client_ip() -> str:
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _is_blocked_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in net for net in _BLOCKED_NETWORKS)


def validate_url(url: str):
    """Return (ok, error_message, http_status)."""
    if not url or not isinstance(url, str):
        return False, "Missing url", 400
    if len(url) > MAX_URL_LENGTH:
        return False, "URL too long", 400
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False, "Invalid scheme", 400
    if not parsed.hostname:
        return False, "Missing host", 400
    # Resolve hostname and check all addresses against blocked networks.
    try:
        infos = socket.getaddrinfo(parsed.hostname, None)
    except socket.gaierror:
        return False, "DNS resolution failed", 400
    for info in infos:
        ip_str = info[4][0]
        if _is_blocked_ip(ip_str):
            return False, "SSRF protection", 400
    return True, None, 200


def require_api_key(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        provided = request.headers.get("X-API-Key")
        if not provided or provided != API_SECRET_KEY:
            log.warning("[BROWSER] Unauthorized /fetch attempt from %s", _client_ip())
            return jsonify({"error": "Unauthorized"}), 401
        return fn(*args, **kwargs)
    return wrapper


def check_rate_limit(ip: str):
    """Return (allowed, retry_after_seconds)."""
    now = time.time()
    bucket = _rate_buckets[ip]
    while bucket and now - bucket[0] >= RATE_LIMIT_WINDOW:
        bucket.popleft()
    if len(bucket) >= RATE_LIMIT_MAX:
        retry_after = int(RATE_LIMIT_WINDOW - (now - bucket[0])) + 1
        return False, retry_after
    bucket.append(now)
    return True, 0


def log_to_supabase(source_name: str, domain: str, status: str, error: str = ""):
    sb = get_supabase()
    if not sb:
        return
    try:
        sb.table("ingestion_logs").insert({
            "scenario_name": "browser_service_fetch",
            "started_at": datetime.now(timezone.utc).isoformat(),
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "status": status,
            "items_fetched": 1 if status == "success" else 0,
            "items_inserted": 0,
            "items_skipped_dedup": 0,
            "errors": [error] if error else [],
            "make_execution_id": f"browser:{source_name}:{domain}",
        }).execute()
    except Exception as e:
        log.error("[BROWSER] Failed to write ingestion_log: %s", e)


# ── Playwright optimization (Pillar 2) ───────────────────────
# Resource types that never carry article text — blocked to cut bandwidth, speed
# up load, and let networkidle settle quickly.
_BLOCKED_RESOURCE_TYPES = {"image", "media", "font", "stylesheet"}

# Ad / analytics / tracker hosts — blocked by substring match on the request URL.
_BLOCKED_URL_SUBSTRINGS = (
    "googlesyndication", "doubleclick", "google-analytics", "googletagmanager",
    "googletagservices", "adservice", "adsystem", "/ads/", "/ad/", "adnxs",
    "facebook.net", "connect.facebook", "scorecardresearch", "quantserve",
    "taboola", "outbrain", "criteo", "amazon-adsystem", "hotjar", "mixpanel",
    "segment.io", "cdn.segment", "fullstory", "optimizely", "newrelic",
)

# Semantic containers, in priority order — the article body lives in one of these
# on virtually every news/blog CMS. We return the first that yields real text.
_CONTENT_SELECTORS = (
    "article", "main", "[role='main']", ".post-content", "#entry-content",
    ".entry-content", ".article-content", ".article-body", "#content",
    ".post-body", ".td-post-content",
)

# Hard cap on time spent on a single page (Pillar 2 / Pillar 6).
_NAV_TIMEOUT_MS = 30000


def _should_block(route) -> bool:
    req = route.request
    if req.resource_type in _BLOCKED_RESOURCE_TYPES:
        return True
    u = (req.url or "").lower()
    return any(s in u for s in _BLOCKED_URL_SUBSTRINGS)


def render_page(url: str) -> str:
    """Fetch a URL with a stealth headless Chromium browser (Pillar 2).

    Optimizations:
      - Blocks images/fonts/CSS/media + ad/tracker hosts (less bandwidth, faster
        networkidle).
      - Returns the innerHTML of the first matching SEMANTIC container
        (article/main/.post-content/#entry-content/…) so the downstream
        compressor gets the article body, not nav/footer chrome.
      - Hard 30s navigation timeout; browser always closed in `finally`.
    """
    from playwright.sync_api import sync_playwright

    content = ""
    with sync_playwright() as p:
        browser = None
        try:
            browser = p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-blink-features=AutomationControlled",
                    "--disable-dev-shm-usage",
                ],
            )
            context = browser.new_context(
                ignore_https_errors=True,
                viewport={
                    "width": random.randint(1366, 1920),
                    "height": random.randint(768, 1080),
                },
                user_agent=random.choice(USER_AGENTS),
            )
            # Block all non-content resources before any navigation.
            context.route("**/*", lambda route: route.abort()
                          if _should_block(route) else route.continue_())

            page = context.new_page()
            page.set_default_navigation_timeout(_NAV_TIMEOUT_MS)
            page.add_init_script(
                "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
            )
            page.set_extra_http_headers({
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
            })
            try:
                page.goto(url, wait_until="networkidle", timeout=_NAV_TIMEOUT_MS)
            except Exception:
                # networkidle can time out on chatty pages even with blocking —
                # fall back to DOM-ready content rather than failing the fetch.
                page.goto(url, wait_until="domcontentloaded", timeout=_NAV_TIMEOUT_MS)
            time.sleep(random.uniform(1, 2))

            # Prefer a semantic container; fall back to full page / body text.
            for sel in _CONTENT_SELECTORS:
                try:
                    node = page.query_selector(sel)
                    if node:
                        html = node.inner_html()
                        if html and len(html) > 200:
                            content = html
                            break
                except Exception:
                    continue
            if not content:
                try:
                    content = page.content()
                except Exception:
                    content = page.inner_text("body")
            if not content:
                content = page.inner_text("body")
        finally:
            if browser:
                browser.close()
    return content


@app.route("/fetch", methods=["POST"])
@require_api_key
def fetch():
    ip = _client_ip()
    allowed, retry_after = check_rate_limit(ip)
    if not allowed:
        log.warning("[BROWSER] Rate limit exceeded for %s", ip)
        return jsonify({"error": "Rate limit exceeded", "retry_after": retry_after}), 429

    data = request.get_json(silent=True) or {}
    url = data.get("url", "")
    source_name = data.get("source_name", "unknown")

    ok, err, status_code = validate_url(url)
    if not ok:
        log.warning("[BROWSER] URL validation failed (%s) for %s", err, domain_of(url))
        return jsonify({"error": err, "status": "failed"}), status_code

    domain = domain_of(url)
    log.info("[BROWSER] Fetching %s for source=%s", domain, source_name)

    try:
        content = render_page(url)
        log_to_supabase(source_name, domain, "success")
        return jsonify({
            "content": content,
            "status": "ok",
            "source_name": source_name,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "domain": domain,
        })
    except Exception as e:
        err_msg = str(e)[:300]
        log.error("[BROWSER] Fetch failed for %s: %s", domain, err_msg)
        log_to_supabase(source_name, domain, "failed", err_msg)
        return jsonify({"error": err_msg, "status": "failed"}), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "service": "cti-browser-service",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
