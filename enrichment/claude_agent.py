"""
Claude enrichment agent — the single AI call per intelligence item.

TOKEN BUDGET SUMMARY
====================
# Per item: 1 Claude call only
# Input: ~4000 char content + ~800 char prompt = ~1500 tokens
# Output: max 1500 tokens
# Cost per item at Sonnet pricing: ~$0.015
# Contradiction check: 0 tokens (DB only — see enrichment/contradiction.py)
# Self-validation: 0 tokens (pure Python — see validate_enrichment below)
# 100 items/day = ~$1.50/day = ~$45/month

Token-efficiency measures applied here:
- Article content is truncated to MAX_CONTENT_CHARS (4000) before sending.
- The system prompt is static and marked with cache_control so Anthropic caches
  it across calls (NOT automatic — it requires the explicit cache_control
  breakpoint set in call_claude; without it every call re-bills the full prompt).
- max_tokens is capped at 1500 — enough for the full JSON, no waste.
- temperature=0 for deterministic output (no wasted retries on variance).
- Only the fields Claude needs are sent (title + truncated text), never raw HTML.

NOTE on model/SDK: ANTHROPIC_MODEL defaults to claude-sonnet-4-20250514 (the
snapshot requested for this build; it is deprecated and retires 2026-06-15 —
set ANTHROPIC_MODEL=claude-sonnet-4-6 in the env to move to current Sonnet).
The anthropic 0.39.0 SDK needs httpx<0.28 (see requirements.txt).
"""
import json
import time
import logging

import anthropic

from config import ANTHROPIC_API_KEY, ANTHROPIC_MODEL

log = logging.getLogger(__name__)

MAX_CONTENT_CHARS = 4000
MAX_TOKENS = 1500
TEMPERATURE = 0

# Static system prompt — reused on every call and cached by Anthropic via the
# cache_control breakpoint in call_claude(). Keep it byte-stable: any change
# invalidates the cache and re-bills the full prompt.
SYSTEM_PROMPT = """\
You are a senior CTI analyst for an Israeli SOC. 15 years experience.
Specialties: Middle East threats, Iran-Israel cyber conflict, APT tracking,
critical infrastructure, ransomware.
You are precise and evidence-based. You attribute to actors ONLY with clear
evidence. You flag uncertainty rather than guessing.

Hebrew terms to use correctly:
גורם איום=threat actor, פרצת אבטחה=vulnerability, תוכנת כופר=ransomware,
תקיפת סייבר=cyber attack, מודיעין איומים=threat intelligence,
תשתית קריטית=critical infrastructure, קמפיין תקיפה=campaign,
סממן פשרה=IOC, ניצול פגיעות=exploitation, תוכנה זדונית=malware,
דיוג=phishing, גישה ראשונית=initial access, תנועה רוחבית=lateral movement

Return ONLY valid JSON. No preamble, no markdown fences."""

# Compact, fixed instruction block appended after the per-item content. Kept
# terse on purpose — the analyst persona and Hebrew glossary live in the cached
# system prompt, so we don't repeat them here.
_INSTRUCTIONS = """\
Analyze the intelligence item below and return ONLY this JSON object:
{
  "category": "global_ti|apt|israel|iran_nexus|phishing|cves|ics|research",
  "tags": [],
  "severity": "critical|high|medium|low",
  "severity_reason": "one sentence",
  "confidence": 0,
  "confidence_reason": "one sentence",
  "iocs": {"ips": [], "domains": [], "urls": [],
           "hashes": {"md5": [], "sha1": [], "sha256": []},
           "emails": [], "malware_families": [], "c2_servers": []},
  "cves": [],
  "actors": [],
  "mitre_techniques": [],
  "targeted_sectors": [],
  "targeted_countries": [],
  "campaign_name": null,
  "summary_en": "5-7 sentence professional summary",
  "summary_he": "5-7 sentence professional Hebrew summary",
  "israel_relevance": false,
  "iran_nexus": false,
  "contradiction_note": null
}"""

_VALID_SEVERITIES = ("critical", "high", "medium", "low")

# Empty IOC skeleton used to backfill missing buckets during validation.
_EMPTY_IOCS = {
    "ips": [], "domains": [], "urls": [],
    "hashes": {"md5": [], "sha1": [], "sha256": []},
    "emails": [], "malware_families": [], "c2_servers": [],
}


def _strip_code_fences(text: str) -> str:
    """Remove a leading ```json / ``` fence and trailing ``` if present."""
    t = (text or "").strip()
    if t.startswith("```"):
        lines = t.split("\n")
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        t = "\n".join(lines).strip()
    return t


def _has_hebrew(text: str) -> bool:
    """True if the string contains any Hebrew-range character (U+0590–U+05FF)."""
    return any("֐" <= ch <= "׿" for ch in (text or ""))


def _sentence_count(text: str) -> int:
    """Rough sentence count — splits on . ! ? and counts non-trivial fragments."""
    import re
    parts = [p for p in re.split(r"[.!?]+", text or "") if len(p.strip()) > 3]
    return len(parts)


def build_user_prompt(title, content, source_name, source_category, trust_score) -> str:
    """Build the compact per-item user prompt. Content is truncated to 4000 chars."""
    truncated = (content or "")[:MAX_CONTENT_CHARS]
    return (
        f"{_INSTRUCTIONS}\n\n"
        f"SOURCE: {source_name or 'unknown'} "
        f"(category={source_category or 'n/a'}, trust={trust_score if trust_score is not None else 'n/a'})\n"
        f"TITLE: {title or ''}\n"
        f"CONTENT:\n{truncated}\n"
    )


def call_claude(user_prompt: str) -> str:
    """Call the Anthropic Messages API and return the raw response text.

    Rate-limit handling:
      - 429 (rate limit): exponential backoff 5s, 15s, 45s — up to 3 retries.
      - 529 (overloaded): wait 10s, retry once.
      - any other error: log and raise.

    Anthropic tier 1 allows ~50 requests/min, so the inter-call delay imposed by
    the enrichment loop keeps us well under that and avoids 429s in normal runs;
    this backoff is the safety net for bursts/overlap.
    """
    if not ANTHROPIC_API_KEY:
        raise RuntimeError("ANTHROPIC_API_KEY is not set")

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

    backoff_429 = [5, 15, 45]   # up to 3 retries on rate limit
    attempt_529 = 0             # 529 gets a single 10s retry

    while True:
        try:
            response = client.messages.create(
                model=ANTHROPIC_MODEL,
                max_tokens=MAX_TOKENS,
                temperature=TEMPERATURE,
                # System prompt as a cacheable block — explicit cache_control is
                # what makes Anthropic reuse it across calls (it is NOT automatic).
                system=[{
                    "type": "text",
                    "text": SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},
                }],
                messages=[{"role": "user", "content": user_prompt}],
                # Prompt caching went GA shortly after this SDK; the beta header
                # is a harmless no-op if GA and enables caching on 0.39.0 if not.
                extra_headers={"anthropic-beta": "prompt-caching-2024-07-31"},
            )
        except anthropic.RateLimitError:
            if backoff_429:
                delay = backoff_429.pop(0)
                log.warning(f"[CLAUDE] 429 rate limit — backing off {delay}s")
                time.sleep(delay)
                continue
            log.error("[CLAUDE] 429 rate limit — retries exhausted")
            raise
        except anthropic.APIStatusError as e:
            # 529 overloaded — single 10s retry. Other status errors propagate.
            if getattr(e, "status_code", None) == 529 and attempt_529 < 1:
                attempt_529 += 1
                log.warning("[CLAUDE] 529 overloaded — waiting 10s then retrying once")
                time.sleep(10)
                continue
            log.error(f"[CLAUDE] API error (status={getattr(e, 'status_code', '?')}): {e}")
            raise

        # Log cache + token usage so we can verify the system prompt is caching.
        try:
            u = response.usage
            log.info(
                "[CLAUDE] tokens input=%s output=%s cache_read=%s cache_write=%s",
                u.input_tokens, u.output_tokens,
                getattr(u, "cache_read_input_tokens", "?"),
                getattr(u, "cache_creation_input_tokens", "?"),
            )
        except Exception:
            pass

        text = "".join(b.text for b in response.content if getattr(b, "type", None) == "text")
        if not text:
            raise RuntimeError("Claude returned an empty response")
        return text


def validate_enrichment(data: dict) -> dict:
    """Self-validate and locally repair Claude's output — zero token cost.

    Fixes problems in place rather than re-calling Claude:
      - severity must be one of critical/high/medium/low (else -> medium + log)
      - confidence must be an int 0-100 (else clamp / default 50)
      - summary_en must be non-empty and 3+ sentences (else lower confidence)
      - summary_he must contain Hebrew characters (else log a warning)
      - all IOC buckets must exist (else backfill empty)
    """
    if not isinstance(data, dict):
        raise ValueError("enrichment payload is not a JSON object")

    # severity
    sev = str(data.get("severity") or "").strip().lower()
    if sev not in _VALID_SEVERITIES:
        log.warning(f"[CLAUDE] invalid severity {data.get('severity')!r} -> defaulting to 'medium'")
        sev = "medium"
    data["severity"] = sev

    # confidence — clamp to 0-100 int
    try:
        conf = int(data.get("confidence"))
    except (TypeError, ValueError):
        log.warning("[CLAUDE] confidence missing/non-numeric -> defaulting to 50")
        conf = 50
    conf = max(0, min(100, conf))
    data["confidence"] = conf

    # summary_en — must be present and substantive
    summary_en = str(data.get("summary_en") or "").strip()
    if not summary_en or _sentence_count(summary_en) < 3:
        log.warning("[CLAUDE] summary_en empty or <3 sentences -> lowering confidence")
        data["confidence"] = min(data["confidence"], 40)
    data["summary_en"] = summary_en

    # summary_he — should contain Hebrew
    summary_he = str(data.get("summary_he") or "").strip()
    if not _has_hebrew(summary_he):
        log.warning("[CLAUDE] summary_he has no Hebrew characters")
    data["summary_he"] = summary_he

    # IOC buckets — ensure the full structure exists so downstream code is safe
    iocs = data.get("iocs")
    if not isinstance(iocs, dict):
        iocs = {}
    for key, default in _EMPTY_IOCS.items():
        if key == "hashes":
            h = iocs.get("hashes")
            if not isinstance(h, dict):
                h = {}
            for hk in ("md5", "sha1", "sha256"):
                if not isinstance(h.get(hk), list):
                    h[hk] = []
            iocs["hashes"] = h
        elif not isinstance(iocs.get(key), list):
            iocs[key] = list(default)
    data["iocs"] = iocs

    # List-typed fields default to empty lists
    for k in ("tags", "cves", "actors", "mitre_techniques",
              "targeted_sectors", "targeted_countries"):
        if not isinstance(data.get(k), list):
            data[k] = []

    data["israel_relevance"] = bool(data.get("israel_relevance", False))
    data["iran_nexus"] = bool(data.get("iran_nexus", False))
    return data


def enrich_with_claude(title, content, source_name, source_category, trust_score) -> dict:
    """Enrich a single item with Claude. Returns the validated enrichment dict.

    The content is truncated to 4000 chars, sent in one Claude call, parsed as
    JSON (retried ONCE on a parse failure, per the no-extra-token policy), and
    validated/repaired locally. The returned dict matches the Gemini schema, so
    build_intelligence_payload() can consume it unchanged.
    """
    prompt = build_user_prompt(title, content, source_name, source_category, trust_score)

    raw = call_claude(prompt)
    try:
        data = json.loads(_strip_code_fences(raw))
    except json.JSONDecodeError as e:
        log.warning(f"[CLAUDE] JSON parse failed ({e}); retrying once")
        raw = call_claude(prompt)
        try:
            data = json.loads(_strip_code_fences(raw))
        except json.JSONDecodeError as e2:
            raise RuntimeError(f"Claude returned unparseable JSON twice: {e2}; raw={raw[:300]}")

    data = validate_enrichment(data)
    data["enriched_by"] = "claude"
    return data
