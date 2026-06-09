"""
One-off migration: switch CISA from its RSS advisories feed to the official
KEV (Known Exploited Vulnerabilities) JSON feed.

What it does (idempotent):
  1. Deactivates any existing CISA RSS advisory source (active=false) so it
     stops being polled. We deactivate rather than delete to preserve the
     foreign-key links from already-ingested raw_items.
  2. Inserts the CISA KEV JSON source if it isn't already present.

Run from the project root:  python -m scripts.migrate_cisa_kev
"""
import logging

from database.supabase_client import client

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("migrate_cisa_kev")

OLD_CISA_RSS_URL = "https://www.cisa.gov/cybersecurity-advisories/all.xml"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_NAME = "CISA KEV (Known Exploited Vulnerabilities)"


def deactivate_old_rss():
    """Disable any CISA RSS advisory sources (matched by the known RSS URL)."""
    existing = client.table("rss_sources").select("id, name, url, active").eq("url", OLD_CISA_RSS_URL).execute()
    rows = existing.data or []
    if not rows:
        log.info("No CISA RSS source found at %s — nothing to deactivate", OLD_CISA_RSS_URL)
        return
    for row in rows:
        if row.get("active") is False:
            log.info("CISA RSS source '%s' already inactive", row.get("name"))
            continue
        client.table("rss_sources").update({"active": False}).eq("id", row["id"]).execute()
        log.info("Deactivated CISA RSS source '%s' (%s)", row.get("name"), row["id"])


def add_kev_source():
    """Insert the CISA KEV JSON source if absent."""
    existing = client.table("rss_sources").select("id, active").eq("url", KEV_URL).execute()
    if existing.data:
        row = existing.data[0]
        if not row.get("active"):
            client.table("rss_sources").update({"active": True}).eq("id", row["id"]).execute()
            log.info("KEV source already existed — re-activated it")
        else:
            log.info("KEV source already present and active — nothing to do")
        return
    client.table("rss_sources").insert({
        "name": KEV_NAME,
        "url": KEV_URL,
        "category": "cves",
        "active": True,
        "trust_score": 0.99,  # CISA KEV is an authoritative, official catalog
        "error_count": 0,
    }).execute()
    log.info("Inserted CISA KEV source: %s", KEV_URL)


def main():
    log.info("Starting CISA → KEV migration")
    deactivate_old_rss()
    add_kev_source()
    log.info("Migration complete")


if __name__ == "__main__":
    main()
