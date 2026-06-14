# ============================================================
# PRIMARY CTI ENRICHMENT AGENT — Claude (Anthropic)
# This is the primary and preferred agent for all CTI analysis.
# Gemini is only used as fallback when this key is not configured.
# To add credits: https://console.anthropic.com/settings/billing
# Current model: claude-sonnet-4-6
# Cost estimate: ~$0.015 per item (3000 token input + 1500 output)
# ============================================================
"""
Claude enrichment agent — ONE AI call per intelligence item (LLM-Compiler DAG).

Per item the pipeline is a 3-node DAG, NOT a ReAct loop:
  Step 1  pre-process   — compress text + regex IOC hints + category cache (0 tokens)
  Step 2  reason        — a SINGLE Claude Messages call (the only token spend)
  Step 3  validate/save — self-validate + locally repair the JSON (0 tokens)

TOKEN BUDGET
============
# Input : compressed content (<=3000 chars) + compact prompt  ≈ 1200-1500 tokens
# Output: capped at 1500 tokens
# Cost  : ~$0.015 / item at Sonnet pricing  (≈ $1.50 / 100 items / day)
# Contradiction check + self-validation: 0 tokens (DB / pure Python).

Token-efficiency measures applied here:
- Content is compressed (utils.text_compressor) BEFORE the call — 40-60% fewer
  input tokens with no CTI-signal loss.
- Obvious IOCs are regex-extracted and injected as [PRE-FILLED] so Claude
  verifies rather than re-derives them.
- Source category / CVE-in-title are deterministically pre-filled (semantic
  cache) so simple routing never reaches the LLM.
- The system prompt is static + cache_control'd so Anthropic reuses it across
  calls (NOT automatic — needs the explicit cache breakpoint set below).
- max_tokens=1500, temperature=0 (deterministic, no variance retries).

Error handling (PRIORITY ZERO):
- 429 rate limit         -> exponential backoff (5s/15s/45s), up to 3 retries.
- 400 insufficient credit-> raise ClaudeCreditsError; the run STOPS and the job
  stays PENDING (never marked failed, never silently handed to Gemini).
- 500 server error       -> retry once after 10s, then fail gracefully.
- 529 overloaded         -> retry once after 10s, then fail gracefully.
- any other error        -> propagate; caller marks the job failed and continues.
"""
import json
import time
import logging

import anthropic

from config import ANTHROPIC_API_KEY, ANTHROPIC_MODEL
from utils.text_compressor import compress_for_llm, extract_ioc_hints, detect_language

log = logging.getLogger(__name__)

MAX_TOKENS = 1500
TEMPERATURE = 0
AGENT_VERSION = "2.0"

# Approx Sonnet input-token price ($/token). Used only for a cost ESTIMATE in
# enrichment_data; not billing-accurate (output tokens cost more).
COST_PER_TOKEN_USD = 0.000003

# Valid platform categories (semantic-cache pre-fill must produce one of these).
_VALID_CATEGORIES = {
    "global_ti", "apt", "israel", "iran_nexus",
    "phishing", "cves", "ics", "research",
}
_VALID_SEVERITIES = ("critical", "high", "medium", "low")

import re as _re
_RE_CVE_TITLE = _re.compile(r"\bCVE-\d{4}-\d{4,7}\b", _re.IGNORECASE)


class ClaudeCreditsError(RuntimeError):
    """Raised on a 400 'insufficient credits' / billing error.

    Signals the orchestrator to STOP the run and leave the job PENDING (so Claude
    picks it up once credits are added) rather than marking it failed or falling
    back to Gemini.
    """


# Static system prompt — identity + output contract only (kept well under 400
# tokens). The analytical steps live in the per-item user prompt. cache_control
# makes Anthropic reuse this across calls; keep it byte-stable.
SYSTEM_PROMPT = """\
You are a senior CTI analyst for an Israeli SOC (15y). Focus: Middle East
threats, Iran-Israel cyber conflict, APT tracking, critical infrastructure,
ransomware. Precise, evidence-based. Attribute to actors ONLY with clear
evidence; flag uncertainty over guessing.

Hebrew glossary: גורם איום=threat actor, פרצת אבטחה=vulnerability,
תוכנת כופר=ransomware, תקיפת סייבר=cyber attack, מודיעין איומים=threat intel,
תשתית קריטית=critical infrastructure, קמפיין תקיפה=campaign, סממן פשרה=IOC,
ניצול פגיעות=exploitation, תוכנה זדונית=malware, דיוג=phishing,
גישה ראשונית=initial access, תנועה רוחבית=lateral movement.

Return ONLY one valid JSON object. No preamble, no markdown fences."""

# The output schema, embedded in the user prompt.
_SCHEMA = """{
  "category": "global_ti|apt|israel|iran_nexus|phishing|cves|ics|research",
  "tags": [],
  "severity": "critical|high|medium|low",
  "severity_reason": "max 20 words, dense technical",
  "confidence": 0,
  "confidence_reason": "max 20 words, dense technical",
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
    """True if the string contains any Hebrew-range character (U+0590-U+05FF)."""
    return any("֐" <= ch <= "׿" for ch in (text or ""))


def _sentence_count(text: str) -> int:
    """Rough sentence count — splits on . ! ? and counts non-trivial fragments."""
    parts = [p for p in _re.split(r"[.!?]+", text or "") if len(p.strip()) > 3]
    return len(parts)


# ── DAG Step 1: pre-process (semantic cache + regex hints, 0 tokens) ──
def _prefill_category(title: str, source_category) -> str:
    """Deterministically pick a category without the LLM where possible.

    - CVE-XXXX-XXXX in the title  -> "cves"
    - source's own category (if a valid platform enum) -> that category
    Returns "" when nothing can be confidently pre-filled.
    """
    if title and _RE_CVE_TITLE.search(title):
        return "cves"
    sc = (str(source_category or "")).strip().lower()
    if sc in _VALID_CATEGORIES:
        return sc
    return ""


def _build_prefilled_block(prefill: dict) -> str:
    """Render the [PRE-FILLED] context block injected into the user prompt."""
    lines = ["[PRE-FILLED] These fields were extracted deterministically. "
             "VERIFY them, fold them into your JSON (dedupe), and DO NOT drop "
             "any valid value:"]
    if prefill.get("category"):
        lines.append(f"- category = {prefill['category']}")
    hints = prefill.get("iocs") or {}
    h = hints.get("hashes", {}) or {}
    flat = {
        "cves": prefill.get("cves") or [],
        "ips": hints.get("ips") or [],
        "domains": hints.get("domains") or [],
        "md5": h.get("md5") or [],
        "sha1": h.get("sha1") or [],
        "sha256": h.get("sha256") or [],
    }
    for label, vals in flat.items():
        if vals:
            lines.append(f"- {label}: {', '.join(vals[:30])}")
    if len(lines) == 1:
        return ""  # nothing pre-filled
    return "\n".join(lines)


def build_user_prompt(title, content, source_name, source_category, trust_score,
                      prefill: dict) -> str:
    """Build the compact per-item user prompt (DAG single-pass instruction)."""
    prefilled_block = _build_prefilled_block(prefill)
    parts = [
        "Analyze the intelligence item and return ONLY this JSON object:",
        _SCHEMA,
        "",
        "Execute all analysis steps in a SINGLE pass. Do not iterate. Return one "
        "complete JSON object covering all fields simultaneously.",
        "Focus ONLY on what needs reasoning: severity + confidence scoring, actor "
        "attribution, MITRE mapping, targeted sectors/countries, and the EN/HE "
        "summaries. Complete every remaining field.",
        "",
    ]
    if prefilled_block:
        parts += [prefilled_block, ""]
    parts += [
        f"SOURCE: {source_name or 'unknown'} "
        f"(category={source_category or 'n/a'}, "
        f"trust={trust_score if trust_score is not None else 'n/a'})",
        f"TITLE: {title or ''}",
        f"CONTENT:\n{content or ''}",
    ]
    return "\n".join(parts) + "\n"


# ── DAG Step 2: the single Claude call ──
def call_claude(user_prompt: str):
    """Call the Anthropic Messages API. Returns (text, usage_dict).

    usage_dict: {"input": int, "output": int, "total": int,
                 "cache_read": int|None, "cache_write": int|None}

    Error handling — see module docstring (429 backoff, 400 credits ->
    ClaudeCreditsError, 500/529 single 10s retry).
    """
    if not ANTHROPIC_API_KEY:
        raise RuntimeError("ANTHROPIC_API_KEY is not set")

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

    backoff_429 = [5, 15, 45]   # up to 3 retries on rate limit
    retry_5xx = {529: 0, 500: 0}  # each gets a single 10s retry

    while True:
        try:
            response = client.messages.create(
                model=ANTHROPIC_MODEL,
                max_tokens=MAX_TOKENS,
                temperature=TEMPERATURE,
                system=[{
                    "type": "text",
                    "text": SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},
                }],
                messages=[{"role": "user", "content": user_prompt}],
                extra_headers={"anthropic-beta": "prompt-caching-2024-07-31"},
            )
        except anthropic.RateLimitError:
            if backoff_429:
                delay = backoff_429.pop(0)
                log.warning(f"[CLAUDE] 429 rate limit — backing off {delay}s")
                time.sleep(delay)
                continue
            log.error("[CLAUDE] 429 rate limit — retries exhausted, failing gracefully")
            raise
        except anthropic.APIStatusError as e:
            status = getattr(e, "status_code", None)
            msg = str(e).lower()
            # 400 insufficient credits / billing — STOP, keep job pending.
            if status == 400 and ("credit" in msg or "insufficient" in msg or "billing" in msg):
                log.error("[CLAUDE] 400 insufficient credits — add credits at "
                          "https://console.anthropic.com/settings/billing. "
                          "Leaving job PENDING for Claude to retry.")
                raise ClaudeCreditsError(str(e)[:300])
            # 500 / 529 — single 10s retry, then fail gracefully.
            if status in (500, 529) and retry_5xx.get(status, 1) < 1:
                retry_5xx[status] += 1
                log.warning(f"[CLAUDE] {status} server/overloaded — waiting 10s then retrying once")
                time.sleep(10)
                continue
            log.error(f"[CLAUDE] API error (status={status}): {str(e)[:200]}")
            raise

        u = response.usage
        usage = {
            "input": getattr(u, "input_tokens", 0) or 0,
            "output": getattr(u, "output_tokens", 0) or 0,
            "cache_read": getattr(u, "cache_read_input_tokens", None),
            "cache_write": getattr(u, "cache_creation_input_tokens", None),
        }
        usage["total"] = usage["input"] + usage["output"]
        log.info(
            "[CLAUDE] tokens input=%s output=%s total=%s cache_read=%s cache_write=%s",
            usage["input"], usage["output"], usage["total"],
            usage["cache_read"], usage["cache_write"],
        )

        text = "".join(b.text for b in response.content if getattr(b, "type", None) == "text")
        if not text:
            raise RuntimeError("Claude returned an empty response")
        return text, usage


# ── DAG Step 3: validate + locally repair (0 tokens) ──
def validate_enrichment(data: dict) -> dict:
    """Self-validate and locally repair Claude's output — zero token cost.

    Repairs in place rather than re-calling Claude:
      - severity must be critical/high/medium/low (else -> medium + log)
      - confidence must be an int 0-100 (else clamp / default 50)
      - category must be a valid enum (else -> global_ti + log)
      - summary_en must be 3+ sentences (else lower confidence)
      - summary_he must contain Hebrew (else log a warning)
      - all IOC buckets must exist (else backfill empty)
      - list-typed fields default to []
    The only condition that warrants a (single) re-call is an EMPTY summary —
    handled by the caller, not here.
    """
    if not isinstance(data, dict):
        raise ValueError("enrichment payload is not a JSON object")

    sev = str(data.get("severity") or "").strip().lower()
    if sev not in _VALID_SEVERITIES:
        log.warning(f"[CLAUDE] invalid severity {data.get('severity')!r} -> 'medium'")
        sev = "medium"
    data["severity"] = sev

    try:
        conf = int(data.get("confidence"))
    except (TypeError, ValueError):
        log.warning("[CLAUDE] confidence missing/non-numeric -> 50")
        conf = 50
    data["confidence"] = max(0, min(100, conf))

    cat = str(data.get("category") or "").strip().lower()
    if cat not in _VALID_CATEGORIES:
        log.warning(f"[CLAUDE] invalid category {data.get('category')!r} -> 'global_ti'")
        cat = "global_ti"
    data["category"] = cat

    summary_en = str(data.get("summary_en") or "").strip()
    if not summary_en or _sentence_count(summary_en) < 3:
        log.warning("[CLAUDE] summary_en empty/<3 sentences -> lowering confidence")
        data["confidence"] = min(data["confidence"], 40)
    data["summary_en"] = summary_en

    summary_he = str(data.get("summary_he") or "").strip()
    if not _has_hebrew(summary_he):
        log.warning("[CLAUDE] summary_he has no Hebrew characters")
    data["summary_he"] = summary_he

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

    for k in ("tags", "cves", "actors", "mitre_techniques",
              "targeted_sectors", "targeted_countries"):
        if not isinstance(data.get(k), list):
            data[k] = []

    data["israel_relevance"] = bool(data.get("israel_relevance", False))
    data["iran_nexus"] = bool(data.get("iran_nexus", False))
    return data


def _summaries_empty(data: dict) -> bool:
    """True if either summary is empty — the only reason to re-call Claude once."""
    return not str(data.get("summary_en") or "").strip() or \
        not str(data.get("summary_he") or "").strip()


def enrich_with_claude(title, content, source_name, source_category, trust_score) -> dict:
    """Enrich a single item with Claude (one DAG pass). Returns the validated dict.

    The returned dict matches the Gemini schema (so build_intelligence_payload()
    consumes it unchanged) and additionally carries token/cost/compression
    telemetry under these keys, surfaced into enrichment_data by the payload
    builder:
      enriched_by, model, agent_version, tokens_used, estimated_cost_usd,
      compression_ratio, processing_time_ms.
    """
    t0 = time.time()
    short_title = str(title or "")[:60]
    log.info(f"[CLAUDE] Processing item: {short_title}")

    # ── Step 1: pre-process (0 tokens) ──
    comp = compress_for_llm(content, title=title or "")
    compressed = comp["compressed"]
    lang = detect_language(compressed)
    hints = extract_ioc_hints(compressed)
    prefill = {
        "category": _prefill_category(title, source_category),
        "cves": hints.get("cves", []),
        "iocs": hints,
    }
    prompt = build_user_prompt(title, compressed, source_name, source_category,
                               trust_score, prefill)

    # ── Step 2: the single Claude call (only token spend) ──
    raw, usage = call_claude(prompt)
    try:
        data = json.loads(_strip_code_fences(raw))
    except json.JSONDecodeError as e:
        log.warning(f"[CLAUDE] JSON parse failed ({e}); retrying once")
        raw, usage2 = call_claude(prompt)
        usage = {k: (usage.get(k) or 0) + (usage2.get(k) or 0)
                 if isinstance(usage.get(k), int) else usage2.get(k)
                 for k in usage2}
        try:
            data = json.loads(_strip_code_fences(raw))
        except json.JSONDecodeError as e2:
            raise RuntimeError(f"Claude returned unparseable JSON twice: {e2}; raw={raw[:300]}")

    # ── Step 3: validate + repair (0 tokens) ──
    data = validate_enrichment(data)

    # The ONE permitted re-call: only when a summary came back empty.
    if _summaries_empty(data):
        log.warning("[CLAUDE] a summary was empty — re-calling once to complete it")
        try:
            raw2, usage3 = call_claude(prompt)
            usage = {k: (usage.get(k) or 0) + (usage3.get(k) or 0)
                     if isinstance(usage.get(k), int) else usage3.get(k)
                     for k in usage3}
            data2 = validate_enrichment(json.loads(_strip_code_fences(raw2)))
            if not _summaries_empty(data2):
                data = data2
        except Exception as e:
            log.warning(f"[CLAUDE] summary re-call failed (non-fatal): {e}")

    elapsed_ms = int((time.time() - t0) * 1000)
    tokens_used = usage.get("total", 0) or 0

    # ── Telemetry (PRIORITY ZERO enriched_by tracking) ──
    data["enriched_by"] = "claude"
    data["model"] = ANTHROPIC_MODEL
    data["agent_version"] = AGENT_VERSION
    data["tokens_used"] = tokens_used
    data["estimated_cost_usd"] = round(tokens_used * COST_PER_TOKEN_USD, 6)
    data["compression_ratio"] = comp["reduction_pct"]
    data["processing_time_ms"] = elapsed_ms
    data["detected_language"] = lang

    log.info(
        "[CLAUDE] Enrichment complete: severity=%s confidence=%s",
        data.get("severity"), data.get("confidence"),
    )
    log.info(
        "[CLAUDE] Tokens used: %s | Cost estimate: $%.4f | compression=%.1f%% | %dms",
        tokens_used, data["estimated_cost_usd"], comp["reduction_pct"], elapsed_ms,
    )
    return data
