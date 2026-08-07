"""
Groq enrichment agent — open-weight models behind an OpenAI-compatible API.

Exists because the Anthropic account ran out of credits and the pipeline stopped
dead with 132 items queued. Groq's free tier serves large open-weight models
(gpt-oss-120b, Llama 3.3 70B) with no card on file, so enrichment keeps running
at zero cost.

Deliberately reuses claude_agent's prompt, parser and validator rather than
duplicating them: the 6-stage schema, the flattening and the repair logic are
the contract the rest of the pipeline reads, and two copies would drift. Only
the HTTP call itself is different.

Model choice (measured, not assumed) on a real Patch Tuesday item:
  gpt-oss-120b   1.8s  valid JSON  severity=critical  clean Hebrew  <- primary
  llama-3.3-70b  2.3s  valid JSON  severity=high      clean Hebrew  <- fallback
  qwen3.6-27b     —    JSON validation failed                       <- rejected
Both survivors are 20-70x faster than Claude was (40-140s per item), which
matters: the enrich call has to finish inside Make's 300s ceiling.

The API is OpenAI-shaped, so pointing GROQ_BASE_URL elsewhere (NVIDIA NIM,
OpenRouter, any OpenAI-compatible host) works without touching this code.
"""
import os
import json
import time
import logging
import re as _re

import requests

from utils.text_compressor import compress_for_llm, detect_language, extract_ioc_hints
from enrichment.claude_agent import (
    AGENT_VERSION,
    MAX_TOKENS,
    MAX_TOKENS_RETRY,
    SYSTEM_PROMPT,
    TEMPERATURE,
    _GENERIC_JSON_SYSTEM,
    _parse_and_flatten,
    _prefill_category,
    _strip_code_fences,
    _summaries_empty,
    build_user_prompt,
    validate_enrichment,
)

log = logging.getLogger(__name__)

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_BASE_URL = os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1")

# Model rotation. Each model carries its OWN free-tier daily token budget
# (100,000 TPD for llama-3.3-70b), so one model alone caps enrichment at ~37
# items/day against an intake of 75-90 — the queue grew to 804 before this was
# found. Rotating across three models roughly triples the daily ceiling at no
# cost, because exhausting one does not touch the others' budgets.
#
# Order is by measured quality on a real Sandworm/wiper item:
#   gpt-oss-120b   1.4s  graded it critical (correct), precise Hebrew terminology
#   llama-3.3-70b  3.9s  solid, the previous primary
#   gpt-oss-20b    0.5s  good Hebrew, slightly softer grading
# Excluded deliberately: qwen3.6-27b fails JSON validation repeatedly, and
# llama-3.1-8b-instant writes noticeably weaker Hebrew ("virus" for "wiper").
GROQ_MODELS = [m.strip() for m in os.getenv(
    "GROQ_MODELS",
    "openai/gpt-oss-120b,llama-3.3-70b-versatile,openai/gpt-oss-20b",
).split(",") if m.strip()]

# Models whose daily budget is spent, mapped to the UTC timestamp they free up
# again. Process-local: a restart just retries and re-learns within one call,
# which is cheaper than persisting state for something that resets daily.
_exhausted_until: dict = {}


# Where the rotation resumes on the next item. Advancing per item — rather than
# only when a model runs dry — is what removes the per-minute stall: each model
# has its own tokens-per-minute allowance (8k/12k/8k), so cycling spreads the
# load across all three instead of draining one and waiting ~20s for it to
# refill while the others sit idle.
_cursor = 0


def _available_models() -> list:
    """Rotation order, starting at the cursor, with exhausted models dropped."""
    now = time.time()
    for model, until in list(_exhausted_until.items()):
        if now >= until:
            del _exhausted_until[model]
            log.info(f"[GROQ] {model} daily budget reset — back in rotation")

    live = [m for m in GROQ_MODELS if m not in _exhausted_until]
    if not live:
        return []
    # Rotate the list so consecutive items start on different models.
    offset = _cursor % len(live)
    return live[offset:] + live[:offset]


def _advance_cursor():
    """Move to the next model for the following item."""
    global _cursor
    _cursor += 1

# Groq's free tier is genuinely free, so cost telemetry stays zero. The field is
# kept because the payload builder and reports read it.
COST_PER_TOKEN_USD = 0.0

_TIMEOUT = 120
_BACKOFF_429 = [5, 15, 45]
# Longest we'll sit waiting out a per-minute limit. The token window is 60s, so
# anything past this is a daily cap wearing a 429's clothing.
_MAX_WAIT_SECONDS = 90

# Groq writes the wait as "8.5s", "250ms" or the combined "1m30s".
_RETRY_COMBINED_RE = _re.compile(r"try again in\s+(\d+)m([0-9.]+)s", _re.I)
_RETRY_RE = _re.compile(r"try again in\s+([0-9.]+)\s*(ms|s|m)\b", _re.I)


class GroqQuotaError(RuntimeError):
    """Every model's budget is spent — stop the run, leave jobs pending."""


class GroqDailyLimit(RuntimeError):
    """One model's daily budget is spent. Internal: the caller rotates onward."""


def _retry_after_seconds(resp, body_lower: str):
    """Seconds to wait before retrying a 429, or None if unknown.

    Prefers the Retry-After header, falling back to the wait Groq embeds in the
    error text ("Please try again in 8.5s").
    """
    header = resp.headers.get("retry-after")
    if header:
        try:
            return float(header)
        except ValueError:
            pass
    m = _RETRY_COMBINED_RE.search(body_lower)
    if m:
        return int(m.group(1)) * 60 + float(m.group(2))
    m = _RETRY_RE.search(body_lower)
    if not m:
        return None
    value, unit = float(m.group(1)), m.group(2)
    return value / 1000 if unit == "ms" else value * 60 if unit == "m" else value


def call_groq(user_prompt: str, max_tokens: int = MAX_TOKENS,
              system_prompt: str = SYSTEM_PROMPT, model: str = None):
    """Call the chat-completions endpoint. Returns (text, usage_dict, finish_reason).

    Mirrors call_claude's return shape so the orchestration below can stay
    identical to the Claude path.
    """
    if not GROQ_API_KEY:
        raise RuntimeError("GROQ_API_KEY is not set")

    # complete_json() and other single-shot callers don't rotate; give them the
    # best model that still has budget today.
    if not model:
        available = _available_models()
        model = available[0] if available else GROQ_MODELS[0]
    backoff = list(_BACKOFF_429)

    while True:
        try:
            resp = requests.post(
                f"{GROQ_BASE_URL}/chat/completions",
                headers={
                    "Authorization": f"Bearer {GROQ_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    "temperature": TEMPERATURE,
                    "max_tokens": max_tokens,
                    # Server-side JSON enforcement. Open-weight models break
                    # format far more often than Claude did, and this is the
                    # cheapest guard available.
                    "response_format": {"type": "json_object"},
                },
                timeout=_TIMEOUT,
            )
        except requests.Timeout:
            raise RuntimeError(f"Groq request timed out after {_TIMEOUT}s")

        if resp.status_code == 429:
            # Two very different things arrive as 429 and must not be conflated:
            #   per-MINUTE limits  -> transient; wait the stated time and retry
            #   per-DAY  limits    -> this model is done until it resets; the
            #                         caller moves to the next model instead
            # Groq states the wait explicitly ("Please try again in 28m18s"), so
            # trust that over guessing from the wording.
            body = resp.text
            low = body.lower()
            daily = ("per day" in low or "tpd" in low or "rpd" in low)
            wait = _retry_after_seconds(resp, low)

            if daily:
                # Park this model until its budget resets so the rotation skips
                # it instead of burning a request on it every single item.
                until = time.time() + (wait if wait else 3600)
                _exhausted_until[model] = until
                mins = (until - time.time()) / 60
                log.warning(f"[GROQ] {model} daily budget spent — out of rotation for {mins:.0f}m")
                raise GroqDailyLimit(f"{model}: {body[:200]}")

            if wait is not None and wait <= _MAX_WAIT_SECONDS:
                log.warning(f"[GROQ] 429 token-rate limit — waiting {wait:.0f}s then retrying")
                time.sleep(wait + 1)
                continue
            if backoff:
                delay = backoff.pop(0)
                log.warning(f"[GROQ] 429 rate limit — backing off {delay}s")
                time.sleep(delay)
                continue
            raise GroqQuotaError(body[:300])

        if resp.status_code >= 400:
            raise RuntimeError(f"Groq HTTP {resp.status_code}: {resp.text[:250]}")

        payload = resp.json()
        choice = (payload.get("choices") or [{}])[0]
        text = (choice.get("message") or {}).get("content") or ""
        usage_raw = payload.get("usage") or {}
        usage = {
            "input": usage_raw.get("prompt_tokens", 0),
            "output": usage_raw.get("completion_tokens", 0),
            "total": usage_raw.get("total_tokens", 0),
        }
        return text, usage, choice.get("finish_reason")


def complete_json(user_prompt: str, max_tokens: int = 2500) -> dict:
    """Single Groq call for a free-form JSON task (e.g. a report narrative).

    The Groq-side twin of claude_agent.complete_json, reusing that module's
    generic system prompt so narratives keep the same voice regardless of which
    engine produced them. Raises GroqQuotaError on quota exhaustion and
    json.JSONDecodeError on unparseable output — reporting/narrative.py catches
    both and falls through to its next option.
    """
    raw, _usage, _finish = call_groq(user_prompt, max_tokens=max_tokens,
                                     system_prompt=_GENERIC_JSON_SYSTEM)
    return json.loads(_strip_code_fences(raw))


def _merge(a: dict, b: dict) -> dict:
    return {k: (a.get(k, 0) or 0) + (b.get(k, 0) or 0) for k in ("input", "output", "total")}


def enrich_with_groq(title, content, source_name, source_category, trust_score) -> dict:
    """Enrich one item via Groq. Returns the same validated dict as the Claude path."""
    t0 = time.time()
    log.info(f"[GROQ] Processing item: {str(title or '')[:60]}")

    # Step 1 — pre-process locally (no tokens spent).
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
                               trust_score, prefill, lang)

    # Step 2 — the model call, walking the rotation.
    candidates = _available_models()
    if not candidates:
        raise GroqQuotaError("every model's daily budget is spent")

    raw = usage = finish = model_used = None
    last_error = None
    for candidate in candidates:
        try:
            raw, usage, finish = call_groq(prompt, model=candidate)
            model_used = candidate
            break
        except GroqDailyLimit as e:
            # That model is out for the day; the next one has its own budget.
            last_error = e
            continue
        except Exception as e:
            # A transient fault on this model shouldn't stall the queue when
            # another is available.
            log.warning(f"[GROQ] {candidate} failed ({str(e)[:120]}); trying next model")
            last_error = e
            continue

    if model_used is None:
        raise GroqQuotaError(f"all models unavailable: {str(last_error)[:200]}")

    # Next item starts on a different model, so no single per-minute allowance
    # is drained while the others go unused.
    _advance_cursor()

    data = None
    try:
        data = _parse_and_flatten(raw)
    except json.JSONDecodeError as e:
        bump = finish == "length"
        log.warning(f"[GROQ] JSON parse failed ({e}); retrying once"
                    f"{' with a larger token budget' if bump else ''}")
        raw, usage2, finish = call_groq(
            prompt,
            max_tokens=MAX_TOKENS_RETRY if bump else MAX_TOKENS,
            model=model_used,
        )
        usage = _merge(usage, usage2)
        try:
            data = _parse_and_flatten(raw)
        except json.JSONDecodeError as e2:
            raise RuntimeError(f"Groq returned unparseable JSON twice: {e2}; raw={raw[:300]}")

    # Step 3 — validate and repair locally (no tokens spent).
    data = validate_enrichment(data)

    # One permitted re-call, only when a summary came back empty.
    if _summaries_empty(data):
        log.warning("[GROQ] a summary was empty — re-calling once to complete it")
        try:
            raw2, usage3, _ = call_groq(prompt, model=model_used)
            usage = _merge(usage, usage3)
            data2 = validate_enrichment(_parse_and_flatten(raw2))
            if not _summaries_empty(data2):
                data = data2
        except Exception as e:
            log.warning(f"[GROQ] summary re-call failed (non-fatal): {e}")

    elapsed_ms = int((time.time() - t0) * 1000)
    tokens_used = usage.get("total", 0) or 0

    data["enriched_by"] = "groq"
    data["model"] = model_used
    data["agent_version"] = AGENT_VERSION
    data["tokens_used"] = tokens_used
    data["estimated_cost_usd"] = 0.0
    data["compression_ratio"] = comp["reduction_pct"]
    data["processing_time_ms"] = elapsed_ms
    data["detected_language"] = lang

    log.info("[GROQ] Enrichment complete: severity=%s confidence=%s model=%s",
             data.get("severity"), data.get("confidence"), model_used)
    log.info("[GROQ] Tokens: %s | compression=%.1f%% | %dms",
             tokens_used, comp["reduction_pct"], elapsed_ms)
    return data
