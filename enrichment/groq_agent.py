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
    _parse_and_flatten,
    _prefill_category,
    _summaries_empty,
    build_user_prompt,
    validate_enrichment,
)

log = logging.getLogger(__name__)

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_BASE_URL = os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
# llama-3.3-70b leads on throughput, not quality. Measured free-tier ceilings:
#   llama-3.3-70b-versatile   12,000 tokens/minute
#   openai/gpt-oss-120b        8,000 tokens/minute
# An enriched item costs ~5,000 tokens, so 8k/min allows barely one item per
# minute and the run stalls immediately; 12k/min sustains the real workload.
# gpt-oss-120b did score the sample item slightly better (critical vs high), so
# it stays as the fallback and is worth revisiting if limits ever rise.
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
GROQ_FALLBACK_MODEL = os.getenv("GROQ_FALLBACK_MODEL", "openai/gpt-oss-120b")

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
    """Free-tier daily/token quota exhausted — stop the run, leave jobs pending."""


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

    model = model or GROQ_MODEL
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
            #   per-DAY  limits    -> waiting is pointless; stop, requeue the job
            # Groq states the wait explicitly ("Please try again in 8.5s"), so
            # trust that over guessing from the wording.
            body = resp.text
            low = body.lower()
            daily = ("per day" in low or "tpd" in low or "rpd" in low)
            wait = _retry_after_seconds(resp, low)

            if not daily and wait is not None and wait <= _MAX_WAIT_SECONDS:
                log.warning(f"[GROQ] 429 token-rate limit — waiting {wait:.0f}s then retrying")
                time.sleep(wait + 1)
                continue
            if not daily and backoff:
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

    # Step 2 — the model call.
    model_used = GROQ_MODEL
    try:
        raw, usage, finish = call_groq(prompt)
    except GroqQuotaError:
        raise
    except Exception as e:
        # Primary model unavailable — try the fallback before giving up, since
        # a stalled queue is worse than a slightly weaker analysis.
        log.warning(f"[GROQ] {GROQ_MODEL} failed ({str(e)[:120]}); trying {GROQ_FALLBACK_MODEL}")
        model_used = GROQ_FALLBACK_MODEL
        raw, usage, finish = call_groq(prompt, model=GROQ_FALLBACK_MODEL)

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
