"""
Report-narrative LLM router — Claude PRIMARY, Gemini FALLBACK (PRIORITY ZERO).

Weekly and monthly reports need free-form JSON narrative sections. This module
keeps the agent priority consistent with enrichment:

  1. Claude (claude_agent.complete_json) when ANTHROPIC_API_KEY is set.
  2. Gemini (enrichment.gemini.call_gemini) as fallback.
  3. None -> the caller uses its own deterministic narrative.

Unlike the enrichment path, a narrative is non-critical: a Claude failure here
(including a credits/billing error) is logged and falls through to Gemini, then
to the deterministic fallback — a report is ALWAYS produced. Returns a dict on
success or None so the caller can apply its fallback.
"""
import os
import logging

log = logging.getLogger(__name__)


def generate_narrative(prompt: str) -> dict:
    """Produce a narrative JSON dict via Claude (primary) then Gemini. None if both fail."""
    # 1. Claude primary.
    if os.getenv("ANTHROPIC_API_KEY"):
        try:
            from enrichment.claude_agent import complete_json
            result = complete_json(prompt)
            if isinstance(result, dict) and result:
                log.info("[NARRATIVE] generated via claude (primary)")
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
