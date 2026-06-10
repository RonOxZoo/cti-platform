"""
Self-checking contradiction detection — TOKEN-FREE (pure database queries).

After Claude enriches an item, cross-check its extracted IOCs / actors / CVEs
against what we already have on record. This is deterministic comparison logic,
so it uses zero AI tokens — only the initial enrichment needs AI reasoning.

Conflicts are written to the `contradiction_checks` table and, if any are found,
`intelligence_items.contradiction_flag` is set to true for the enriched row.

Schema notes (verified against the live PostgREST schema):
  - iocs(value, type, linked_actors[], linked_cves, ...) — actor attribution
    lives in linked_actors (a text[]/jsonb list of actor identifiers).
  - threat_actors(name, aliases[], origin_country, ...).
  - cves(cve_id, severity, cvss_score, ...).
  - contradiction_checks(item_id, ioc_id, actor_id, conflict_type,
    old_value, new_value, analyst_note, resolved, created_at).

These normalized tables are populated by the IOC/actor/CVE extraction pipeline;
until they contain rows, this check simply finds nothing and returns
has_contradictions=False (the flag is still set, to False) — which is the
expected steady state for a fresh database.
"""
import logging

from database.supabase_client import client

log = logging.getLogger(__name__)

# Severity rank for comparing an item's severity against a stored CVE severity.
# A jump of 2+ ranks (e.g. stored "low" vs new "critical") is "significant".
_SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# Origin countries consistent with an Iranian-nexus attribution. Used for the
# (heuristic) actor-origin check: the enrichment has no per-actor origin field,
# so iran_nexus is the only origin signal it carries.
_IRAN_ORIGINS = {"iran", "islamic republic of iran", "ir"}


def _iter_new_iocs(enrichment: dict):
    """Yield (type, value) for every concrete IOC value in the enrichment."""
    iocs = (enrichment or {}).get("iocs", {}) or {}
    for t in ("ips", "domains", "urls", "emails", "c2_servers"):
        for v in iocs.get(t, []) or []:
            if v:
                yield t, str(v).strip()
    hashes = iocs.get("hashes", {}) or {}
    for algo, vals in hashes.items():
        for v in vals or []:
            if v:
                yield f"hash:{algo}", str(v).strip()


def _record_conflict(item_id, conflict_type, old_value, new_value,
                     ioc_id=None, actor_id=None, note=None):
    """Insert one row into contradiction_checks (best-effort)."""
    try:
        client.table("contradiction_checks").insert({
            "item_id": item_id,
            "ioc_id": ioc_id,
            "actor_id": actor_id,
            "conflict_type": conflict_type,
            "old_value": str(old_value)[:500] if old_value is not None else None,
            "new_value": str(new_value)[:500] if new_value is not None else None,
            "analyst_note": note,
            "resolved": False,
        }).execute()
    except Exception as e:
        log.error(f"[CONTRA] failed to write contradiction_checks row: {e}")


def _check_iocs(enrichment, item_id, new_actors_lower):
    """Flag IOCs already linked to a DIFFERENT actor than this item attributes."""
    conflicts = []
    for ioc_type, value in _iter_new_iocs(enrichment):
        try:
            res = (client.table("iocs")
                   .select("id, value, linked_actors")
                   .eq("value", value)
                   .limit(1)
                   .execute())
        except Exception as e:
            log.error(f"[CONTRA] iocs lookup failed for {value}: {e}")
            continue
        if not res.data:
            continue
        row = res.data[0]
        linked = row.get("linked_actors") or []
        if isinstance(linked, str):
            linked = [linked]
        linked_lower = {str(a).strip().lower() for a in linked if a}
        if not linked_lower:
            continue
        # Conflict if the item names actors and NONE of them match the existing
        # attribution for this IOC.
        if new_actors_lower and not (linked_lower & new_actors_lower):
            old_actor = ", ".join(sorted(linked_lower))
            new_actor = ", ".join(sorted(new_actors_lower))
            conflicts.append({
                "type": "ioc_actor_mismatch",
                "ioc": value,
                "old_actor": old_actor,
                "new_actor": new_actor,
            })
            _record_conflict(item_id, "ioc_actor_mismatch", old_actor, new_actor,
                             ioc_id=row.get("id"),
                             note=f"IOC {value} ({ioc_type}) previously linked to "
                                  f"{old_actor}; this item attributes it to {new_actor}.")
    return conflicts


def _check_actors(enrichment, item_id):
    """Flag actors whose stored origin_country contradicts the item's iran_nexus.

    The enrichment carries no explicit per-actor origin, so iran_nexus is the
    only origin signal available — this is a deliberately conservative heuristic.
    """
    conflicts = []
    iran_nexus = bool(enrichment.get("iran_nexus"))
    for actor in enrichment.get("actors", []) or []:
        name = str(actor).strip()
        if not name:
            continue
        try:
            res = (client.table("threat_actors")
                   .select("id, name, origin_country")
                   .ilike("name", name)
                   .limit(1)
                   .execute())
        except Exception as e:
            log.error(f"[CONTRA] threat_actors lookup failed for {name}: {e}")
            continue
        if not res.data:
            continue
        row = res.data[0]
        origin = (row.get("origin_country") or "").strip()
        if not origin:
            continue
        origin_is_iran = origin.lower() in _IRAN_ORIGINS
        if iran_nexus != origin_is_iran:
            implied = "Iran (iran_nexus=true)" if iran_nexus else "non-Iran (iran_nexus=false)"
            conflicts.append({
                "type": "actor_origin_mismatch",
                "actor": name,
                "old_origin": origin,
                "new_origin": implied,
            })
            _record_conflict(item_id, "actor_origin_mismatch", origin, implied,
                             actor_id=row.get("id"),
                             note=f"Actor {name} has stored origin_country={origin}; "
                                  f"this item implies {implied}.")
    return conflicts


def _check_cves(enrichment, item_id):
    """Flag CVEs whose stored severity differs significantly from this item's."""
    conflicts = []
    item_sev = str(enrichment.get("severity") or "").strip().lower()
    item_rank = _SEV_RANK.get(item_sev)
    if item_rank is None:
        return conflicts
    for cve in enrichment.get("cves", []) or []:
        cve_id = str(cve).strip()
        if not cve_id:
            continue
        try:
            res = (client.table("cves")
                   .select("id, cve_id, severity")
                   .eq("cve_id", cve_id)
                   .limit(1)
                   .execute())
        except Exception as e:
            log.error(f"[CONTRA] cves lookup failed for {cve_id}: {e}")
            continue
        if not res.data:
            continue
        stored_sev = str(res.data[0].get("severity") or "").strip().lower()
        stored_rank = _SEV_RANK.get(stored_sev)
        if stored_rank is None:
            continue
        # "Significant" = differs by 2+ severity ranks.
        if abs(stored_rank - item_rank) >= 2:
            conflicts.append({
                "type": "cve_severity_mismatch",
                "cve": cve_id,
                "old_severity": stored_sev,
                "new_severity": item_sev,
            })
            _record_conflict(item_id, "cve_severity_mismatch", stored_sev, item_sev,
                             note=f"CVE {cve_id} stored severity={stored_sev}; "
                                  f"this item rates the event {item_sev}.")
    return conflicts


def _set_flag_and_note(item_id, conflicts):
    """Set contradiction_flag=true and record a note in enrichment_data."""
    try:
        # Read-modify-write enrichment_data so we don't clobber the enrichment.
        existing = (client.table("intelligence_items")
                    .select("enrichment_data")
                    .eq("id", item_id)
                    .limit(1)
                    .execute())
        enr = (existing.data[0].get("enrichment_data") or {}) if existing.data else {}
        if not isinstance(enr, dict):
            enr = {}
        enr["contradictions"] = conflicts
        client.table("intelligence_items").update({
            "contradiction_flag": True,
            "enrichment_data": enr,
        }).eq("id", item_id).execute()
    except Exception as e:
        log.error(f"[CONTRA] failed to set contradiction_flag for {item_id}: {e}")


def check_contradictions(enrichment: dict, item_id: str) -> dict:
    """Cross-check an enrichment against existing DB records. Token-free.

    Returns {"has_contradictions": bool, "conflicts": [...]}. Writes any conflicts
    to contradiction_checks and, when conflicts exist, sets the item's
    contradiction_flag=true and notes the conflicts in enrichment_data.

    Never raises — contradiction detection must not break the enrichment run.
    """
    result = {"has_contradictions": False, "conflicts": []}
    if not item_id or not isinstance(enrichment, dict):
        return result

    try:
        new_actors_lower = {
            str(a).strip().lower() for a in (enrichment.get("actors") or []) if a
        }
        conflicts = []
        conflicts += _check_iocs(enrichment, item_id, new_actors_lower)
        conflicts += _check_actors(enrichment, item_id)
        conflicts += _check_cves(enrichment, item_id)

        if conflicts:
            _set_flag_and_note(item_id, conflicts)
            log.info(f"[CONTRA] {len(conflicts)} contradiction(s) for item {item_id}")

        result["has_contradictions"] = bool(conflicts)
        result["conflicts"] = conflicts
    except Exception as e:
        log.error(f"[CONTRA] check_contradictions failed (non-fatal): {e}")
    return result
