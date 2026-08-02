"""
Report-narrative LLM router — Groq PRIMARY, then Claude, then Gemini.

Weekly and monthly reports need free-form JSON narrative sections. This module
mirrors the enrichment path's engine order so a report is never written by a
different model than the items it summarises:

  1. Groq   (groq_agent.complete_json)   when GROQ_API_KEY is set.
  2. Claude (claude_agent.complete_json) when ANTHROPIC_API_KEY is set.
  3. Gemini (enrichment.gemini.call_gemini) as a last LLM attempt.
  4. None -> the caller uses its own deterministic narrative.

Groq leads because the Anthropic account has no credits; without this the
weekly and monthly reports were the last place still calling a dead API, and
every run silently degraded to the deterministic text.

Unlike enrichment, a narrative is non-critical: any failure here — including
quota or billing errors — is logged and falls through to the next option, so a
report is ALWAYS produced. Returns a dict on success or None for the caller's
fallback.
"""
import os
import logging

log = logging.getLogger(__name__)


def generate_narrative(prompt: str) -> dict:
    """Produce a narrative JSON dict via Groq, then Claude, then Gemini. None if all fail."""
    # 1. Groq primary.
    if os.getenv("GROQ_API_KEY"):
        try:
            from enrichment.groq_agent import complete_json as groq_complete_json
            result = groq_complete_json(prompt)
            if isinstance(result, dict) and result:
                log.info("[NARRATIVE] generated via groq (primary)")
                return result
        except Exception as e:
            log.warning(f"[NARRATIVE] Groq narrative failed, trying Claude: {str(e)[:160]}")

    # 2. Claude.
    if os.getenv("ANTHROPIC_API_KEY"):
        try:
            from enrichment.claude_agent import complete_json
            result = complete_json(prompt)
            if isinstance(result, dict) and result:
                log.info("[NARRATIVE] generated via claude")
                return result
        except Exception as e:
            # Non-critical: log and fall through to Gemini (a report must ship).
            log.warning(f"[NARRATIVE] Claude narrative failed, falling back to Gemini: {str(e)[:160]}")

    # 2. Gemini fallback.
    try:
        from enrichment.gemini import call_gemini
        result = call_gemini(prompt)
        if isinstance(result, dict) and result:
            log.info("[NARRATIVE] generated via gemini (fallback)")
            return result
    except Exception as e:
        from enrichment.gemini import _is_rate_limit_error
        if _is_rate_limit_error(e):
            log.warning("[NARRATIVE] Gemini quota reached — caller will use deterministic narrative.")
        else:
            log.error(f"[NARRATIVE] Gemini narrative failed: {str(e)[:160]}")

    # 3. Signal the caller to use its deterministic fallback.
    return None
