#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CTI Platform - Infrastructure Health Check & Data Validation Tool
Validates: Supabase DB + typo scan | Render service | RSS feed health
"""

import os
import sys

# Force UTF-8 output so non-ASCII chars in DB content don't crash the terminal
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
import re
import json
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional

# ── Dependency imports with graceful fallback messages ───────────────────────
try:
    import requests
except ImportError:
    sys.exit("Missing dependency: pip install requests")

try:
    import feedparser
except ImportError:
    sys.exit("Missing dependency: pip install feedparser")

try:
    from supabase import create_client
except ImportError:
    sys.exit("Missing dependency: pip install supabase")

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

try:
    from colorama import Fore, Style, init as _cinit
    _cinit(autoreset=True)
    _G = Fore.GREEN
    _R = Fore.RED
    _Y = Fore.YELLOW
    _C = Fore.CYAN
    _B = Style.BRIGHT
    _D = Style.DIM
    _X = Style.RESET_ALL
except ImportError:
    _G = _R = _Y = _C = _B = _D = _X = ""

try:
    from spellchecker import SpellChecker
    _spell = SpellChecker()
    HAS_SPELL = True
except ImportError:
    _spell = None
    HAS_SPELL = False

# ── Configuration ─────────────────────────────────────────────────────────────
SUPABASE_URL       = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY       = os.getenv("SUPABASE_KEY", "")
RENDER_SERVICE_URL = os.getenv("RENDER_SERVICE_URL", "https://cti-platform.onrender.com").rstrip("/")
API_SECRET_KEY     = os.getenv("API_SECRET_KEY", "")

TYPO_SCAN_TABLE  = "raw_items"         # table that holds incident summaries
TYPO_SCAN_LIMIT  = 150                 # max rows to scan per run
TYPO_MAX_PER_ROW = 5                   # max reported typos per row
FEED_TIMEOUT     = 15                  # seconds

# ── Security/CTI domain whitelist ─────────────────────────────────────────────
# Words that are valid in CTI content but unknown to a general dictionary.
CTI_WHITELIST: frozenset = frozenset({
    # Malware families & categories
    "malware","ransomware","spyware","adware","rootkit","botnet","backdoor",
    "trojan","worm","keylogger","cryptominer","stealer","dropper","loader",
    "shellcode","payload","implant","stager","implants","stagers",
    # Vulnerability language
    "exploit","exploited","exploiting","exploitation","zero-day","zeroday",
    "unpatched","pre-auth","preauth","post-auth","postauth","unpatch",
    "vulnerability","vulnerabilities","vuln","vulns","cve","nvd","cvss",
    "misconfiguration","misconfigurations","misconfigured",
    # Exfil / intrusion
    "exfiltrate","exfiltrated","exfiltration","exfil",
    "infiltrate","infiltrated","infiltration","pivoting","laterally",
    "persistence","persistency","privilege","escalation","privesc",
    "reconnaissance","reconnoiter","enumeration","enumerated",
    # Attack classes
    "phishing","spearphishing","spear-phishing","vishing","smishing",
    "typosquatting","wateringhole","driveby","clickjacking",
    "sqli","xss","csrf","idor","ssrf","rce","lfi","rfi","xxe","ssti","rop",
    "obfuscation","obfuscated","deobfuscate","deobfuscation",
    "polymorphic","metamorphic","packer","packed","unpacked","crypter",
    # Standards & taxonomy
    "mitre","attck","ttp","ttps","ioc","iocs","stix","taxii","sigma","yara",
    "osint","cti","nvd","cwe","capec","d3fend",
    # Security tools & platforms
    "cobalt","mimikatz","metasploit","nmap","burpsuite","shodan","censys",
    "virustotal","wireshark","bloodhound","sharphound","rubeus","impacket",
    "seatbelt","powersploit","empyre","covenant","havoc","sliver","brute",
    # Defense / SOC
    "soc","siem","edr","xdr","ndr","mdr","waf","dmz","honeypot","sandbox",
    "detonation","telemetry","triage","playbook","runbook","detections",
    # Protocols & formats
    "http","https","ftp","smtp","dns","tcp","udp","ssl","tls","vpn",
    "tor","onion","socks","proxy","ssh","rdp","smb","ldap","kerberos",
    "json","xml","html","csv","pdf","exe","dll","elf","bat","ps1","vbs",
    # Crypto & hashing
    "sha256","sha1","md5","aes","rsa","base64","hmac","pbkdf2","bcrypt",
    "bitcoin","monero","ethereum","cryptocurrency","blockchain","btc","xmr",
    # Cloud / infra
    "aws","azure","gcp","cloudflare","github","gitlab","kubernetes","docker",
    "terraform","ansible","serverless","microservices",
    # Threat actors (generic)
    "lazarus","carbanak","apt","ta","cozy","fancy","charming","sandworm",
    "mandiant","crowdstrike","sentinelone","recordedfuture","threatconnect",
    # News sources (proper nouns that appear in content)
    "threatpost","bleepingcomputer","krebs","hackernews","securityweek",
    "darkreading","infosecurity",
    # Action words specific to security writing
    "breached","compromised","patched","remediated","disclosed","detected",
    "mitigated","attributed","weaponized","weaponization","leveraged","abused",
    "chained","bypassed","hardcoded","hardcode","backdoored","trojanized",
    "re-used","reused","re-compiled","recompiled","decompiled","decompile",
    # Misc tech
    "poc","cybersecurity","infosec","devsecops","opsec","pentest","pentesting",
    "redteam","blueteam","purpleteam","ctf","dfir","forensics","forensic",
    "malanalysis","threatintel","threatactor","threatactors",
})

# Token-level skip patterns — these tokens are never spell-checked
_SKIP_PAT: List[re.Pattern] = [
    re.compile(r'^cve-\d{4}-\d+$', re.I),                       # CVE-2024-1234
    re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}(?:/\d+)?$'),          # IPv4 + CIDR
    re.compile(r'^[0-9a-f]{16,}$', re.I),                       # Hashes
    re.compile(r'^[A-Z]{2,12}$'),                                # ALL-CAPS acronyms
    re.compile(r'^\d+$'),                                        # Pure numbers
    re.compile(r'^https?://'),                                   # URLs
    re.compile(r'^[\w.+%-]+@[\w.-]+\.\w{2,}$'),                 # Email addresses
    re.compile(r'^v?\d+\.\d+'),                                  # Version strings
    re.compile(r'[/\\#@$%^*_]'),                                 # Path/code symbols
    re.compile(r'^-+$'),                                         # Separator lines
    re.compile(r'&(?:amp|lt|gt|quot|nbsp|apos);', re.I),        # HTML entities
]

_HTML_TAG = re.compile(r'<[^>]+>')
_STRIP_CHARS = ".,;:!?'()[]{}/-\\"


def _clean_html(text: str) -> str:
    return _HTML_TAG.sub(" ", text)


def _should_skip(token: str) -> bool:
    t = token.strip(".,;:!?\"'()[]{}—–…/\\").lower()
    if not t or len(t) < 3:
        return True
    if t in CTI_WHITELIST:
        return True
    for pat in _SKIP_PAT:
        if pat.search(t):
            return True
    # CamelCase / PascalCase — product names, malware names
    if re.search(r'[A-Z][a-z]+[A-Z]', token):
        return True
    # Mixed alpha-numeric (log4j, win32, sha256...)
    if re.search(r'\d', t):
        return True
    return False


def find_typos(text: str) -> List[str]:
    """Return a list of likely misspelled words in the given text."""
    if not HAS_SPELL or not text:
        return []
    clean = _clean_html(text[:3000])
    tokens = re.split(r'[\s\n\r\t]+', clean)
    candidates = []
    for tok in tokens:
        bare = tok.strip(_STRIP_CHARS)
        if bare and not _should_skip(bare):
            candidates.append(bare.lower())
    if not candidates:
        return []
    misspelled = _spell.unknown(candidates)
    return [w for w in misspelled if w not in CTI_WHITELIST][:TYPO_MAX_PER_ROW]


# ── Terminal helpers ──────────────────────────────────────────────────────────

def _bar(title: str = ""):
    print(f"\n{_B}{_C}{'=' * 64}{_X}")
    if title:
        print(f"{_B}{_C}  {title}{_X}")
        print(f"{_B}{_C}{'=' * 64}{_X}")


def ok(msg: str):    print(f"  {_G}[OK]{_X}    {msg}")
def warn(msg: str):  print(f"  {_Y}[WARN]{_X}  {msg}")
def fail(msg: str):  print(f"  {_R}[FAIL]{_X}  {msg}")
def info(msg: str):  print(f"  {_C}[INFO]{_X}  {msg}")
def sub(msg: str):   print(f"           {_D}{msg}{_X}")


# ═══════════════════════════════════════════════════════════════════════════════
# CHECK 1 — Supabase connectivity & typo scan
# ═══════════════════════════════════════════════════════════════════════════════

def check_supabase(report: dict) -> None:
    _bar("CHECK 1 | Supabase DB Connectivity & Data Validation")
    db = report["supabase"] = {"status": "fail", "tables": {}, "typo_scan": {}}

    if not SUPABASE_URL or not SUPABASE_KEY:
        fail("SUPABASE_URL or SUPABASE_KEY missing from .env — aborting DB check")
        return

    try:
        client = create_client(SUPABASE_URL, SUPABASE_KEY)
        ok(f"Connected  ->  {SUPABASE_URL}")
    except Exception as exc:
        fail(f"Connection failed: {exc}")
        return

    # ── Table row counts ──────────────────────────────────────────────────────
    for tbl in ("rss_sources", "raw_items", "processing_jobs", "ingestion_logs"):
        try:
            r = client.table(tbl).select("id", count="exact").limit(1).execute()
            count = r.count if r.count is not None else len(r.data)
            db["tables"][tbl] = count
            ok(f"  {tbl:<25} {count:>6} rows")
        except Exception as exc:
            db["tables"][tbl] = "error"
            warn(f"  {tbl:<25} query failed: {exc}")

    # ── Typo scan on raw_items (title + raw_content) ──────────────────────────
    print()
    if not HAS_SPELL:
        warn("pyspellchecker not installed — skipping typo scan  (pip install pyspellchecker)")
        db["typo_scan"]["skipped"] = "pyspellchecker not installed"
        db["status"] = "ok"
        return

    info(f"Typo scan: querying {TYPO_SCAN_TABLE} (limit {TYPO_SCAN_LIMIT} rows, newest first)…")

    try:
        r = client.table(TYPO_SCAN_TABLE)\
            .select("id, title, raw_content")\
            .order("published_at", desc=True)\
            .limit(TYPO_SCAN_LIMIT)\
            .execute()
        rows = r.data or []
    except Exception as exc:
        warn(f"Typo scan query failed: {exc}")
        db["status"] = "ok"
        return

    info(f"Scanning {len(rows)} rows…")

    flagged_rows = []
    terminal_shown = 0

    for row in rows:
        issues: Dict[str, List[str]] = {}

        title_typos = find_typos(row.get("title") or "")
        if title_typos:
            issues["title"] = title_typos

        content_typos = find_typos(row.get("raw_content") or "")
        if content_typos:
            issues["content"] = content_typos

        if issues:
            flagged_rows.append({
                "id":            row.get("id"),
                "title_preview": (row.get("title") or "")[:90],
                "issues":        issues,
            })
            if terminal_shown < 8:
                terminal_shown += 1
                preview = (row.get("title") or "untitled")[:65]
                warn(f'Row {row.get("id")} — "{preview}"')
                for col, words in issues.items():
                    sub(f"{col} -> possible typos: {words}")

    db["typo_scan"] = {
        "rows_scanned":  len(rows),
        "rows_flagged":  len(flagged_rows),
        "flagged_detail": flagged_rows,
    }

    print()
    if not flagged_rows:
        ok(f"No typos detected across {len(rows)} records")
    else:
        hidden = len(flagged_rows) - terminal_shown
        if hidden > 0:
            warn(f"…and {hidden} more flagged rows — see health_report.json for full list")
        warn(f"Total flagged: {len(flagged_rows)} / {len(rows)} rows")

    db["status"] = "ok"


# ═══════════════════════════════════════════════════════════════════════════════
# CHECK 2 — Render service connectivity
# ═══════════════════════════════════════════════════════════════════════════════

def check_render(report: dict) -> None:
    _bar("CHECK 2 | Render Service Connectivity")
    rnd = report["render"] = {
        "status": "fail",
        "url":    RENDER_SERVICE_URL,
        "checks": {},
    }

    if not RENDER_SERVICE_URL:
        fail("RENDER_SERVICE_URL not set in .env")
        return

    info(f"Target: {RENDER_SERVICE_URL}")

    def _get(path: str, label: str, timeout: int = 25) -> Optional[requests.Response]:
        url = f"{RENDER_SERVICE_URL}{path}"
        try:
            t0 = time.monotonic()
            resp = requests.get(url, timeout=timeout)
            ms = round((time.monotonic() - t0) * 1000)
            rnd["checks"][label] = {"status": resp.status_code, "latency_ms": ms}
            return resp, ms
        except requests.exceptions.ConnectionError:
            fail(f"{label}: connection refused — service may be down or URL incorrect")
            rnd["checks"][label] = {"status": "connection_error"}
        except requests.exceptions.Timeout:
            warn(f"{label}: timed out after {timeout}s  (Render free tier cold-start may need 30-60s)")
            rnd["checks"][label] = {"status": "timeout"}
        except Exception as exc:
            fail(f"{label}: {exc}")
            rnd["checks"][label] = {"status": "error", "detail": str(exc)}
        return None, 0

    # GET /
    result = _get("/", "root")
    if result[0] is None:
        return
    resp, ms = result
    if resp.status_code == 200:
        ok(f"GET /         ->  HTTP {resp.status_code}  ({ms}ms)")
        try:
            body = resp.json()
            sub(f"service={body.get('service')}  version={body.get('version')}  "
                f"status={body.get('status')}")
            rnd["checks"]["root"]["body"] = body
        except Exception:
            pass
    else:
        warn(f"GET /         ->  HTTP {resp.status_code}  ({ms}ms)")

    # GET /health
    result = _get("/health", "health")
    if result[0] is not None:
        resp, ms = result
        if resp.status_code == 200:
            ok(f"GET /health   ->  HTTP {resp.status_code}  ({ms}ms)")
            try:
                body = resp.json()
                sub(f"service={body.get('service')}  ts={body.get('timestamp')}")
                rnd["checks"]["health"]["body"] = body
            except Exception:
                pass
        else:
            warn(f"GET /health   ->  HTTP {resp.status_code}  ({ms}ms)")

    # POST /ingest — no API key (expect 401, confirms auth guard is working)
    try:
        t0 = time.monotonic()
        resp = requests.post(
            f"{RENDER_SERVICE_URL}/ingest",
            json={},
            timeout=25,
        )
        ms = round((time.monotonic() - t0) * 1000)
        rnd["checks"]["ingest_auth_probe"] = {"status": resp.status_code, "latency_ms": ms}
        if resp.status_code == 401:
            ok(f"POST /ingest  ->  HTTP 401  auth guard is working  ({ms}ms)")
        elif resp.status_code == 200:
            warn(f"POST /ingest  ->  HTTP 200 without an API key — verify auth middleware")
        else:
            info(f"POST /ingest  ->  HTTP {resp.status_code}  ({ms}ms)")
    except Exception as exc:
        warn(f"POST /ingest probe: {exc}")

    # GET /status  (last ingestion log)
    result = _get("/status", "status")
    if result[0] is not None:
        resp, ms = result
        if resp.status_code == 200:
            ok(f"GET /status   ->  HTTP {resp.status_code}  ({ms}ms)")
            try:
                body = resp.json()
                last = body.get("last_run") or {}
                if last:
                    sub(f"last run: {last.get('started_at')}  "
                        f"inserted={last.get('items_inserted')}  "
                        f"status={last.get('status')}")
                else:
                    sub("no ingestion runs recorded yet")
            except Exception:
                pass
        else:
            warn(f"GET /status   ->  HTTP {resp.status_code}  ({ms}ms)")

    rnd["status"] = "ok"


# ═══════════════════════════════════════════════════════════════════════════════
# CHECK 3 — RSS feed validation
# ═══════════════════════════════════════════════════════════════════════════════

def check_rss_feeds(report: dict) -> None:
    _bar("CHECK 3 | RSS Feed Validation")
    rss = report["rss_feeds"] = {
        "status": "fail",
        "feeds":  [],
        "summary": {},
    }

    if not SUPABASE_URL or not SUPABASE_KEY:
        fail("Supabase not configured — cannot load RSS sources")
        return

    try:
        client = create_client(SUPABASE_URL, SUPABASE_KEY)
        r = client.table("rss_sources")\
            .select("id, url, name, category, active, trust_score")\
            .execute()
        sources = r.data or []
    except Exception as exc:
        fail(f"Failed to load rss_sources: {exc}")
        return

    active   = [s for s in sources if s.get("active")]
    inactive = [s for s in sources if not s.get("active")]
    info(f"Sources: {len(sources)} total  |  {len(active)} active  |  {len(inactive)} inactive")

    if not active:
        warn("No active sources found in rss_sources — nothing to validate")
        rss["status"] = "warn"
        return

    HEADERS = {"User-Agent": "CTIPlatform-HealthCheck/1.0"}
    passed, failed_names = 0, []

    for src in active:
        name  = src.get("name", "unnamed")
        url   = src.get("url", "").strip()
        cat   = src.get("category", "—")
        score = src.get("trust_score", "?")
        result = {"name": name, "url": url, "category": cat, "trust_score": score}

        if not url:
            fail(f"  {name}: no URL configured — skipping")
            result["status"] = "no_url"
            rss["feeds"].append(result)
            failed_names.append(name)
            continue

        try:
            t0   = time.monotonic()
            resp = requests.get(url, headers=HEADERS, timeout=FEED_TIMEOUT)
            ms   = round((time.monotonic() - t0) * 1000)
            resp.raise_for_status()

            feed        = feedparser.parse(resp.content)
            entry_count = len(feed.entries)
            is_bozo     = bool(feed.bozo)
            feed_title  = ""
            if hasattr(feed, "feed") and feed.feed:
                feed_title = feed.feed.get("title", "")

            # Validate required feed fields
            warnings = []
            if not feed.entries:
                warnings.append("feed has 0 entries")
            if not feed_title:
                warnings.append("feed has no title element")
            if is_bozo:
                warnings.append(f"parse warning: {getattr(feed, 'bozo_exception', 'unknown')}")

            result.update({
                "status":       "ok",
                "http_status":  resp.status_code,
                "latency_ms":   ms,
                "entry_count":  entry_count,
                "feed_title":   feed_title,
                "bozo":         is_bozo,
                "warnings":     warnings,
            })

            if warnings:
                warn(f"  {name:<35} {entry_count:>4} entries  [{ms}ms]  score={score}")
                for w in warnings:
                    sub(f"[!] {w}")
            else:
                ok(f"  {name:<35} {entry_count:>4} entries  [{ms}ms]  score={score}")
            sub(f"cat={cat}  feed_title={feed_title[:50]}")

            passed += 1

        except requests.exceptions.Timeout:
            fail(f"  {name}: timeout ({FEED_TIMEOUT}s)")
            result["status"] = "timeout"
            failed_names.append(name)
        except requests.exceptions.HTTPError:
            fail(f"  {name}: HTTP {resp.status_code}")
            result["status"] = f"http_{resp.status_code}"
            failed_names.append(name)
        except Exception as exc:
            fail(f"  {name}: {str(exc)[:80]}")
            result["status"] = "error"
            result["error"]  = str(exc)[:150]
            failed_names.append(name)

        rss["feeds"].append(result)

    rss["summary"] = {
        "total_active": len(active),
        "passed":       passed,
        "failed":       len(failed_names),
        "failed_names": failed_names,
    }

    print()
    if failed_names:
        warn(f"Feeds healthy: {passed}/{len(active)}  |  failed: {', '.join(failed_names)}")
    else:
        ok(f"All {passed}/{len(active)} active feeds are reachable and parseable")

    rss["status"] = "ok" if not failed_names else "partial"


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    started = datetime.now(timezone.utc)

    _bar()
    print(f"{_B}{_C}  CTI PLATFORM - INFRASTRUCTURE HEALTH CHECK{_X}")
    print(f"{_C}  {started.strftime('%Y-%m-%d %H:%M:%S UTC')}{_X}")
    print(f"{_C}  Supabase: {SUPABASE_URL or '(not set)'}{_X}")
    print(f"{_C}  Render:   {RENDER_SERVICE_URL}{_X}")
    if not HAS_SPELL:
        print(f"\n  {_Y}⚠  pyspellchecker not found — typo scan disabled{_X}")
        print(f"     Run: pip install pyspellchecker")
    _bar()

    report = {
        "tool":         "CTI Platform Health Check",
        "generated_at": started.isoformat(),
        "checks":       {},
    }
    checks = report["checks"]

    check_supabase(checks)
    check_render(checks)
    check_rss_feeds(checks)

    # ── Summary ──────────────────────────────────────────────────────────────
    _bar("SUMMARY")
    statuses = {k: v.get("status", "fail") for k, v in checks.items()}
    colors   = {"ok": _G, "partial": _Y, "warn": _Y, "fail": _R}

    for name, status in statuses.items():
        label = {"ok": "PASS", "partial": "PARTIAL", "warn": "WARN", "fail": "FAIL"}[status]
        clr   = colors.get(status, _R)
        print(f"  {clr}{name.upper():<20}  {label}{_X}")

    all_pass    = all(s == "ok" for s in statuses.values())
    any_fail    = any(s == "fail" for s in statuses.values())
    overall_str = "PASS" if all_pass else ("PARTIAL" if not any_fail else "FAIL")
    overall_clr = _G if all_pass else (_Y if not any_fail else _R)
    print(f"\n  {_B}{overall_clr}Overall: {overall_str}{_X}\n")

    # ── Save report ───────────────────────────────────────────────────────────
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    report["overall"]     = overall_str

    report_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "health_report.json")
    with open(report_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)

    info(f"Full report saved  ->  {report_path}")
    print()


if __name__ == "__main__":
    main()
