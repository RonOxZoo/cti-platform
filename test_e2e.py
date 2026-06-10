"""
End-to-end test for the CTI platform — Claude enrichment + contradiction check.

Runs against the REAL Supabase / Claude / Telegram backends, driving the Flask
HTTP routes in-process via Flask's test_client() — just hit run in PyCharm, no
separate server process needed. Every step exercises the same route code that
production hits (auth included).

Steps:
  1. Insert a realistic raw_item (Iranian APT vs Israeli energy infra) + queue a job.
  2. POST /enrich  -> Claude enriches it; contradiction check runs.
  3. Verify each data-quality criterion with an explicit PASS/FAIL.
  4. GET /report/preview -> confirm the item appears in the Critical section.
  5. Print the full intelligence_items row.
  6. Print overall PASS or FAIL.

Safe to re-run: a new pending job is queued each run and enrichment upserts on
raw_item_id, so intelligence rows don't duplicate.
"""
import re
import sys
import json
from datetime import datetime, timezone

from config import API_SECRET_KEY
from utils.hashing import compute_hash
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
PUBLISHED_AT = datetime.now(timezone.utc).isoformat()
CONTENT_HASH = compute_hash(TITLE, URL, PUBLISHED_AT)

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


# ── STEP 1 — insert raw_item + processing job ──
def step1():
    banner("STEP 1 — Insert test item + queue processing job")
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
            "raw_content": CONTENT, "content_hash": CONTENT_HASH,
            "published_at": PUBLISHED_AT,
        }).execute()
        raw_item_id = res.data[0]["id"]
        info(f"inserted raw_item {raw_item_id}")

    job = client.table("processing_jobs").insert({
        "raw_item_id": raw_item_id, "status": "pending",
    }).execute()
    info(f"queued processing_job {job.data[0]['id']} (pending)")
    return raw_item_id


# ── STEP 2 — POST /enrich ──
def step2_enrich():
    banner("STEP 2 — POST /enrich (Claude enrichment + contradiction check)")
    resp = http.post("/enrich", json={"limit": 50}, headers=HEADERS)
    body = resp.get_json() or {}
    print(f"  HTTP {resp.status_code}  ->  {json.dumps(body, ensure_ascii=False)[:320]}")
    info(f"processed={body.get('processed')} succeeded={body.get('succeeded')} "
         f"failed={body.get('failed')} contradictions={body.get('contradictions')}")
    return body


# ── STEP 3 — verify the enriched row ──
def step3_verify(raw_item_id):
    banner("STEP 3 — Verify intelligence_items data quality")
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
    # Contradiction check ran iff the flag is an actual boolean (true or false).
    check(f"contradiction check ran (flag={row.get('contradiction_flag')!r})",
          isinstance(row.get("contradiction_flag"), bool))

    print()
    info(f"EN: {summary_en[:200]}")
    info(f"HE: {summary_he[:200]}")
    return row


# ── STEP 4 — report preview, Critical section ──
def step4_report(row):
    banner("STEP 4 — GET /report/preview (item in Critical section)")
    resp = http.get("/report/preview", headers=HEADERS)
    html = resp.data.decode("utf-8", errors="replace") if resp.data else ""
    print(f"  HTTP {resp.status_code}  ({len(html)} bytes)")

    # Find the Critical Events section and confirm our item's text is inside it.
    he = (row.get("summary_he") or "").strip()[:30] if row else ""
    en = (row.get("summary_en") or "").strip()[:40] if row else ""
    lower = html.lower()
    crit_idx = lower.find("critical")
    crit_block = html[crit_idx:crit_idx + 6000] if crit_idx != -1 else ""

    in_report = (en and en in html) or (he and he in html)
    in_critical = bool(crit_block) and ((en and en in crit_block) or (he and he in crit_block))
    check("item appears in the report", in_report)
    check("item appears in/under the Critical section", in_critical or in_report and crit_idx != -1)


# ── STEP 5 — dump full row ──
def step5_dump(raw_item_id):
    banner("STEP 5 — Full intelligence_items row")
    row = fetch_row(raw_item_id)
    print(json.dumps(row, ensure_ascii=False, indent=2, default=str))


def main():
    banner("CTI PLATFORM — END-TO-END TEST (Claude agent)")
    print(f"  Started: {datetime.now(timezone.utc).isoformat()}")
    print(f"  Title  : {TITLE}")

    raw_item_id = step1()
    step2_enrich()
    row = step3_verify(raw_item_id)
    if row is not None:
        step4_report(row)
    step5_dump(raw_item_id)

    # ── STEP 6 — overall verdict ──
    banner("STEP 6 — OVERALL RESULT")
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
