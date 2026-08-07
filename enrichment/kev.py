"""
CISA KEV cross-reference — grounds severity in confirmed exploitation.

CISA's Known Exploited Vulnerabilities catalog is the authoritative public list
of CVEs that are being exploited in the wild right now. Inclusion is not a
prediction or a score: CISA has verified active exploitation, and US federal
agencies are bound by a remediation deadline for every entry.

Why this module exists: without it, severity was whatever the language model
inferred from the article text. A CVE that CISA has confirmed under active
attack could still be graded "medium" because the article happened to be terse.
Checking the catalog replaces that inference with a fact — the strongest signal
available for free, and the one a SOC analyst would reach for first.

Grading rules applied on a match (severity is only ever RAISED, never lowered —
an analyst's or model's higher judgement about blast radius still stands):

    in KEV + known ransomware campaign use  ->  critical
    in KEV                                  ->  high

The catalog is ~1.6 MB of JSON refreshed daily by CISA. It is cached in memory
for CACHE_TTL_SECONDS so a run of ten items costs one fetch, not ten, and a
fetch failure degrades to "no KEV data" rather than blocking enrichment.
"""
import logging
import threading
import time

import requests

log = logging.getLogger(__name__)

KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

# CISA publishes at most once a day; six hours keeps us current without
# re-downloading 1.6 MB on every enrichment run.
CACHE_TTL_SECONDS = 6 * 3600
_FETCH_TIMEOUT = 30

_lock = threading.Lock()
_cache: dict = {}        # cve_id -> {"ransomware": bool, "due": str, "name": str}
_fetched_at: float = 0.0


def _load() -> dict:
    """Return the KEV lookup, refreshing it when stale. Never raises.

    On a fetch failure the previous cache is kept and returned: stale KEV data
    is far more useful than none, and enrichment must not stall because CISA is
    briefly unreachable.
    """
    global _cache, _fetched_at
    with _lock:
        if _cache and (time.time() - _fetched_at) < CACHE_TTL_SECONDS:
            return _cache

        try:
            resp = requests.get(KEV_FEED_URL, timeout=_FETCH_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            log.warning(f"[KEV] catalog fetch failed ({str(e)[:120]}) — "
                        f"{'using stale cache' if _cache else 'no KEV data this run'}")
            return _cache

        entries = {}
        for v in (data.get("vulnerabilities") or []):
            cve = (v.get("cveID") or "").strip().upper()
            if not cve:
                continue
            entries[cve] = {
                "ransomware": (v.get("knownRansomwareCampaignUse") or "").lower() == "known",
                "due": v.get("dueDate") or "",
                "name": v.get("vulnerabilityName") or "",
                "vendor": v.get("vendorProject") or "",
                "product": v.get("product") or "",
            }

        _cache = entries
        _fetched_at = time.time()
        log.info(f"[KEV] catalog loaded — {len(entries)} actively exploited CVEs "
                 f"(released {data.get('dateReleased', '?')[:10]})")
        return _cache


def lookup(cve_ids) -> dict:
    """Match a list of CVE ids against the catalog.

    Returns {"matches": [{cve, ransomware, due, name, vendor, product}, ...],
             "ransomware": bool} — `ransomware` is True if ANY match is tied to
    a known ransomware campaign.
    """
    catalog = _load()
    if not catalog or not cve_ids:
        return {"matches": [], "ransomware": False}

    matches = []
    for raw in cve_ids:
        cve = str(raw or "").strip().upper()
        entry = catalog.get(cve)
        if entry:
            matches.append({"cve": cve, **entry})

    return {
        "matches": matches,
        "ransomware": any(m["ransomware"] for m in matches),
    }


def apply_to_result(result: dict) -> dict:
    """Raise `result`'s severity when its CVEs appear in the KEV catalog.

    Mutates and returns the enrichment result. Records what happened under
    `result["kev"]` so the reason survives into enrichment_data and a reader can
    see the grade came from CISA rather than from the model.
    """
    cves = result.get("cves") or []
    hit = lookup(cves)
    if not hit["matches"]:
        return result

    current = (result.get("severity") or "").strip().lower()
    target = "critical" if hit["ransomware"] else "high"

    order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    # Only ever raise. If the model already said critical because of blast
    # radius, KEV confirming exploitation is no reason to walk that back.
    if order.get(target, 0) > order.get(current, -1):
        log.info(f"[KEV] severity {current or 'unset'} -> {target} — "
                 f"{', '.join(m['cve'] for m in hit['matches'])} in CISA KEV"
                 f"{' (ransomware)' if hit['ransomware'] else ''}")
        result["severity"] = target
        result["severity_reason"] = (
            f"CISA KEV: confirmed exploited in the wild"
            f"{'; known ransomware campaign use' if hit['ransomware'] else ''}"
        )

    result["kev"] = {
        "in_kev": True,
        "ransomware": hit["ransomware"],
        "cves": [m["cve"] for m in hit["matches"]],
        "due_dates": [m["due"] for m in hit["matches"] if m["due"]],
    }
    return result
