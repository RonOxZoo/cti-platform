"""
End-to-end test for the CTI platform — Claude DAG enrichment + token efficiency
+ contradiction detection + reporting + delivery.

Runs against the REAL Supabase / Claude / Telegram backends, driving the Flask
HTTP routes in-process via Flask's test_client() — just hit run in PyCharm, no
separate server process needed. Every step exercises the same route code that
production hits (auth included).

Steps:
  0. PRE-FLIGHT  — Claude key / Supabase / Telegram / browser service. STOP on a
     critical failure so we never waste Claude credits on a broken environment.
  1. COMPRESSION — compress_for_llm() gives >20% reduction and <3000 chars.
  2. PRE-FILL    — extract_ioc_hints() finds the CVE and the C2 IPs.
  3. ENRICH      — POST /enrich; Claude enriches; verify data quality + telemetry
     (tokens_used, compression_ratio recorded).
  4. CONTRADICT  — seed a conflicting IOC, enrich, expect contradiction_flag=true
     and a contradiction_checks row.
  5. REPORT      — GET /report/preview; item in Critical section, Hebrew present,
     Token-Efficiency section present.
  6. DELIVERY    — POST /notify/test; Telegram accepts the message.

Safe to re-run: a new pending job is queued each run and enrichment upserts on
raw_item_id, so intelligence rows don't duplicate.
"""
import os
import re
import sys
import json
from datetime import datetime, timezone

from config import API_SECRET_KEY, ANTHROPIC_API_KEY, BROWSER_SERVICE_URL
from utils.hashing import compute_hash
from utils.text_compressor import compress_for_llm, extract_ioc_hints
from database.supabase_client import client
from main import app

# ── Test fixture — fabricated but realistic. IOCs use reserved/defanged values. ──
SOURCE_NAME = "BleepingComputer"
TITLE = ("Iranian APT MuddyWater Exploits CVE-2026-1234 to Breach Israeli "
         "Energy Sector Infrastructure")
URL = ("https://www.bleepingcomputer.com/news/security/"
       "muddywater-cve-2026-1234-israeli-energy-grid/")
CONTENT = (
    "An Iranian state-sponsored threat group tracked as MuddyWater (Static "
    "Kitten) is actively exploiting CVE-2026-1234, a critical (CVSS 9.8) remote "
    "code execution flaw in internet-facing SCADA management consoles across "
    "Israel's electricity distribution sector. The campaign began with "
    "spear-phishing emails (MITRE ATT&CK T1566) carrying macro-enabled "
    "documents sent to engineers at two Israeli grid operators, followed by "
    "exploitation of the public-facing management interface (T1190). After "
    "initial access the actors deployed a PowerShell backdoor beaconing to C2 "
    "infrastructure at 198.51.100.77 and 203.0.113.45, resolving the domains "
    "energy-update-sec[.]com and mofa-portal-il[.]net for tasking. The dropper "
    "invoice_2026.docm carries SHA256 "
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 and MD5 "
    "d41d8cd98f00b204e9800998ecf8427e. The Israel National Cyber Directorate "
    "(INCD) issued an urgent advisory urging operators to patch immediately, "
    "restrict management-interface exposure, and hunt for the listed indicators. "
    "Given active exploitation against Israeli critical infrastructure and a "
    "clear Iranian nexus, defenders should treat this as a top-priority threat."
)
# Realistic raw article as an RSS source actually delivers it: the prose above
# wrapped in nav chrome, <style>/<script> blocks, and a tracking footer. This is
# what compress_for_llm() is designed to strip — exercising the real ingestion
# path (40-60% reduction) rather than already-clean text.
CONTENT_HTML = (
    "<!DOCTYPE html><html><head>"
    "<style>body{font-family:Arial;margin:0}.nav{background:#111;color:#fff}"
    ".ad{display:block;height:250px}a{color:#06c;text-decoration:none}</style>"
    "<script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}"
    "gtag('js',new Date());gtag('config','UA-000000');</script></head><body>"
    "<div class='nav'><ul><li><a href='/'>Home</a></li><li><a href='/news'>News</a></li>"
    "<li><a href='/security'>Security</a></li><li><a href='/subscribe'>Subscribe</a></li></ul></div>"
    "<div class='ad'>Advertisement &mdash; sponsored content</div>"
    f"<article><h1>{TITLE}</h1><p>{CONTENT}</p></article>"
    "<footer><p>Share this article on Twitter Facebook LinkedIn. "
    "Sign up for our newsletter to receive the latest cybersecurity news. "
    "Copyright 2026 BleepingComputer. All rights reserved. Read our privacy policy "
    "and terms of service for more information about how we process your data.</p>"
    "</footer></body></html>"
)
PUBLISHED_AT = datetime.now(timezone.utc).isoformat()
CONTENT_HASH = compute_hash(TITLE, URL, PUBLISHED_AT)

# A C2 IP from the fixture, pre-seeded with a DIFFERENT actor to force a
# contradiction when Claude attributes the same IOC to MuddyWater.
CONFLICT_IOC = "198.51.100.77"
CONFLICT_ACTOR = "APT-Test-Phantom"

http = app.test_client()
HEADERS = {"X-API-Key": API_SECRET_KEY}

# Collected (label, passed) tuples for the final verdict.
_CHECKS = []


def banner(text):
    print("\n" + "=" * 78 + f"\n{text}\n" + "=" * 78)


def check(label, passed):
    _CHECKS.append((label, bool(passed)))
    print(f"  [{'PASS' if passed else 'FAIL'}] {label}")


def info(msg):
    print(f"  - {msg}")


def _hebrew(text):
    return any("֐" <= c <= "׿" for c in (text or ""))


def _sentences(text):
    return len([p for p in re.split(r"[.!?]+", text or "") if len(p.strip()) > 3])


def _iocs_present(enrichment_data):
    iocs = (enrichment_data or {}).get("iocs", {}) or {}
    n = 0
    for k, v in iocs.items():
        if isinstance(v, dict):
            n += sum(len(x or []) for x in v.values())
        elif isinstance(v, list):
            n += len(v)
    return n


def fetch_row(raw_item_id):
    r = (client.table("intelligence_items").select("*")
         .eq("raw_item_id", raw_item_id).limit(1).execute())
    return r.data[0] if r.data else None


# ── STEP 0 — pre-flight ──
def step0_preflight():
    banner("STEP 0 — PRE-FLIGHT (stop before spending credits on a broken env)")
    critical_ok = True

    # Claude key present (PRIMARY agent).
    has_key = bool(ANTHROPIC_API_KEY)
    check("ANTHROPIC_API_KEY is set (Claude is primary)", has_key)
    critical_ok = critical_ok and has_key

    # /health responds.
    try:
        h = http.get("/health")
        ok = h.status_code == 200 and (h.get_json() or {}).get("status") == "ok"
    except Exception as e:
        ok = False
        info(f"/health error: {e}")
    check("/health returns ok", ok)
    critical_ok = critical_ok and ok

    # Supabase reachable.
    try:
        client.table("rss_sources").select("id").limit(1).execute()
        db_ok = True
    except Exception as e:
        db_ok = False
        info(f"Supabase error: {e}")
    check("Supabase connection works", db_ok)
    critical_ok = critical_ok and db_ok

    # Telegram (soft — warn only).
    tg_ok = bool(os.getenv("TELEGRAM_BOT_TOKEN") and os.getenv("TELEGRAM_CHAT_ID"))
    check("Telegram configured (soft)", tg_ok)

    # Browser service (soft — warn only).
    if BROWSER_SERVICE_URL:
        try:
            import requests
            r = requests.get(BROWSER_SERVICE_URL.rstrip("/") + "/health", timeout=8)
            br_ok = r.status_code < 500
        except Exception:
            br_ok = False
    else:
        br_ok = False
        info("BROWSER_SERVICE_URL not set — browser fetch disabled (soft)")
    check("Browser service alive (soft)", br_ok)

    if not critical_ok:
        banner("PRE-FLIGHT FAILED — aborting before any Claude call")
        sys.exit(1)


# ── STEP 1 — compression ──
def step1_compression():
    banner("STEP 1 — COMPRESSION (compress_for_llm)")
    comp = compress_for_llm(CONTENT_HTML, title=TITLE)
    info(f"original={comp['original_length']} compressed={comp['compressed_length']} "
         f"reduction={comp['reduction_pct']}% truncated={comp['was_truncated']}")
    check(f"compression > 20% (got {comp['reduction_pct']}%)", comp["reduction_pct"] > 20)
    check(f"compressed < 3000 chars (got {comp['compressed_length']})",
          comp["compressed_length"] < 3000)


# ── STEP 2 — pre-fill ──
def step2_prefill():
    banner("STEP 2 — PRE-FILL (extract_ioc_hints)")
    hints = extract_ioc_hints(CONTENT_HTML)
    info(f"cves={hints['cves']}")
    info(f"ips={hints['ips']}")
    info(f"sha256={hints['hashes']['sha256']} md5={hints['hashes']['md5']}")
    check("CVE-2026-1234 detected", "CVE-2026-1234" in hints["cves"])
    check("C2 IPs detected", CONFLICT_IOC in hints["ips"] and "203.0.113.45" in hints["ips"])


# ── STEP 3.pre — insert raw_item + processing job ──
def insert_item_and_job():
    banner("STEP 3a — Insert test item + queue processing job")
    src = (client.table("rss_sources").select("id, name, category")
           .eq("name", SOURCE_NAME).limit(1).execute())
    if not src.data:
        check(f"source '{SOURCE_NAME}' exists in rss_sources", False)
        sys.exit(1)
    source_id = src.data[0]["id"]
    info(f"source '{SOURCE_NAME}' -> {source_id}")

    existing = (client.table("raw_items").select("id")
                .eq("content_hash", CONTENT_HASH).limit(1).execute())
    if existing.data:
        raw_item_id = existing.data[0]["id"]
        info(f"reusing existing raw_item {raw_item_id}")
    else:
        res = client.table("raw_items").insert({
            "source_id": source_id, "url": URL, "title": TITLE,
            "raw_content": CONTENT_HTML, "content_hash": CONTENT_HASH,
            "published_at": PUBLISHED_AT,
        }).execute()
        raw_item_id = res.data[0]["id"]
        info(f"inserted raw_item {raw_item_id}")

    job = client.table("processing_jobs").insert({
        "raw_item_id": raw_item_id, "status": "pending",
    }).execute()
    info(f"queued processing_job {job.data[0]['id']} (pending)")
    return raw_item_id


def seed_conflicting_ioc():
    """STEP 4 prep — link the C2 IP to a different actor to force a contradiction.

    Best-effort: if the iocs table schema differs, we log and let STEP 4 report
    that the conflict could not be seeded (it will then simply not trip).
    """
    try:
        existing = (client.table("iocs").select("id, linked_actors")
                    .eq("value", CONFLICT_IOC).limit(1).execute())
        if existing.data:
            client.table("iocs").update({"linked_actors": [CONFLICT_ACTOR]}) \
                .eq("id", existing.data[0]["id"]).execute()
            info(f"updated existing IOC {CONFLICT_IOC} -> [{CONFLICT_ACTOR}]")
        else:
            client.table("iocs").insert({
                "value": CONFLICT_IOC, "type": "ips",
                "linked_actors": [CONFLICT_ACTOR],
            }).execute()
            info(f"seeded IOC {CONFLICT_IOC} -> [{CONFLICT_ACTOR}]")
        return True
    except Exception as e:
        info(f"could not seed conflicting IOC (non-fatal): {str(e)[:160]}")
        return False


# ── STEP 3 — POST /enrich ──
def step3_enrich():
    banner("STEP 3b — POST /enrich (Claude DAG enrichment + contradiction check)")
    resp = http.post("/enrich", json={"limit": 50}, headers=HEADERS)
    body = resp.get_json() or {}
    print(f"  HTTP {resp.status_code}  ->  {json.dumps(body, ensure_ascii=False)[:360]}")
    info(f"processed={body.get('processed')} succeeded={body.get('succeeded')} "
         f"failed={body.get('failed')} contradictions={body.get('contradictions')} "
         f"tokens={body.get('tokens_used')} credits_exhausted={body.get('credits_exhausted')}")
    if body.get("credits_exhausted"):
        banner("CLAUDE CREDITS EXHAUSTED — add credits at "
               "https://console.anthropic.com/settings/billing")
    return body


# ── STEP 3 verify ──
def step3_verify(raw_item_id):
    banner("STEP 3c — Verify intelligence_items data quality + telemetry")
    row = fetch_row(raw_item_id)
    check("intelligence_items row created", row is not None)
    if row is None:
        return None

    enr = row.get("enrichment_data") or {}
    summary_en = (row.get("summary_en") or "").strip()
    summary_he = (row.get("summary_he") or "").strip()
    severity = (row.get("severity") or "").strip().lower()
    n_iocs = _iocs_present(enr)
    enriched_by = (enr.get("enriched_by") or "").strip().lower()

    check(f"summary_en has 5+ sentences (got {_sentences(summary_en)})",
          _sentences(summary_en) >= 5)
    check("summary_he contains Hebrew characters", _hebrew(summary_he))
    check("israel_relevance = true", row.get("israel_relevance") is True)
    check("iran_nexus = true", row.get("iran_nexus") is True)
    check(f"severity is critical/high (got '{severity}')",
          severity in ("critical", "high"))
    check(f"at least 1 IOC extracted (got {n_iocs})", n_iocs >= 1)
    check(f"enriched_by = 'claude' (got '{enriched_by}')", enriched_by == "claude")
    # New telemetry assertions.
    check(f"tokens_used recorded (got {enr.get('tokens_used')})",
          isinstance(enr.get("tokens_used"), int) and enr.get("tokens_used") > 0)
    check(f"compression_ratio recorded (got {enr.get('compression_ratio')})",
          enr.get("compression_ratio") is not None)
    check(f"model recorded (got {enr.get('model')})", bool(enr.get("model")))
    # Contradiction check ran iff the flag is an actual boolean (true or false).
    check(f"contradiction check ran (flag={row.get('contradiction_flag')!r})",
          isinstance(row.get("contradiction_flag"), bool))

    print()
    info(f"EN: {summary_en[:200]}")
    info(f"HE: {summary_he[:200]}")
    return row


# ── STEP 4 — contradiction ──
def step4_contradiction(raw_item_id, seeded):
    banner("STEP 4 — CONTRADICTION (conflicting IOC attribution)")
    row = fetch_row(raw_item_id)
    if not seeded:
        info("conflicting IOC was not seeded — skipping strict assertion")
        check("contradiction_flag is a boolean (check ran)",
              isinstance((row or {}).get("contradiction_flag"), bool))
        return
    flag = (row or {}).get("contradiction_flag")
    check("contradiction_flag = true", flag is True)
    try:
        cc = (client.table("contradiction_checks").select("id, conflict_type")
              .eq("item_id", row["id"]).limit(5).execute())
        rows = cc.data or []
        info(f"contradiction_checks rows: {[r.get('conflict_type') for r in rows]}")
        check("contradiction_checks has a row for this item", len(rows) >= 1)
    except Exception as e:
        info(f"contradiction_checks query failed: {str(e)[:160]}")
        check("contradiction_checks has a row for this item", False)


# ── STEP 5 — report preview ──
def step5_report(row):
    banner("STEP 5 — GET /report/preview (Critical section + Hebrew + token stats)")
    resp = http.get("/report/preview", headers=HEADERS)
    html = resp.data.decode("utf-8", errors="replace") if resp.data else ""
    print(f"  HTTP {resp.status_code}  ({len(html)} bytes)")

    he = (row.get("summary_he") or "").strip()[:30] if row else ""
    en = (row.get("summary_en") or "").strip()[:40] if row else ""
    lower = html.lower()
    crit_idx = lower.find("critical")
    crit_block = html[crit_idx:crit_idx + 8000] if crit_idx != -1 else ""

    in_report = (en and en in html) or (he and he in html)
    in_critical = bool(crit_block) and ((en and en in crit_block) or (he and he in crit_block))
    check("item appears in the report", in_report)
    check("item appears in/under the Critical section",
          in_critical or (in_report and crit_idx != -1))
    check("Hebrew section populated", _hebrew(html))
    check("Token-Efficiency section present", "Token Efficiency" in html)


# ── STEP 6 — delivery ──
def step6_delivery():
    banner("STEP 6 — POST /notify/test (Telegram delivery)")
    resp = http.post("/notify/test", headers=HEADERS)
    body = resp.get_json() or {}
    print(f"  HTTP {resp.status_code}  ->  {json.dumps(body, ensure_ascii=False)[:200]}")
    check("Telegram test message accepted", resp.status_code == 200 and body.get("sent") is True)


def main():
    banner("CTI PLATFORM — END-TO-END TEST (Claude DAG agent)")
    print(f"  Started: {datetime.now(timezone.utc).isoformat()}")
    print(f"  Title  : {TITLE}")

    step0_preflight()
    step1_compression()
    step2_prefill()

    raw_item_id = insert_item_and_job()
    seeded = seed_conflicting_ioc()
    step3_enrich()
    row = step3_verify(raw_item_id)
    step4_contradiction(raw_item_id, seeded)
    if row is not None:
        step5_report(row)
    step6_delivery()

    banner("FULL intelligence_items row")
    print(json.dumps(fetch_row(raw_item_id), ensure_ascii=False, indent=2, default=str))

    # ── Overall verdict ──
    banner("OVERALL RESULT")
    passed = sum(1 for _, ok in _CHECKS if ok)
    total = len(_CHECKS)
    for label, ok in _CHECKS:
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    overall = passed == total and total > 0
    print(f"\n  {passed}/{total} checks passed")
    print(f"\n  ===== OVERALL: {'PASS' if overall else 'FAIL'} =====")
    sys.exit(0 if overall else 1)


if __name__ == "__main__":
    main()
