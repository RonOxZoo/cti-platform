"""
RAG question-answering over the collected intelligence.

Pipeline: full-text search intelligence_items for context, format the top
results, send them with the question to Gemini, and return a grounded answer
in English and Hebrew.

Reuses enrichment/gemini.py's Gemini plumbing (same model, JSON parsing, and
429 detection) and the free-tier rate-limit discipline: a minimum delay
between calls and graceful handling of quota exhaustion.
"""
import logging
import time

from enrichment.gemini import GEMINI_MODEL, call_gemini, _is_rate_limit_error
from rag.search import _run_text_search, log_rag_query

log = logging.getLogger(__name__)

# Free-tier rate-limit protection — minimum spacing between Gemini calls.
CALL_DELAY_SECONDS = 2
_last_call_ts = 0.0

# How many retrieved items to put in the context window.
CONTEXT_ITEMS = 10

RAG_SYSTEM_PROMPT = """You are a Cyber Threat Intelligence analyst with access to
a real-time intelligence database. Answer questions based ONLY on the provided
intelligence context. If the answer is not in the context, say so clearly.
Always provide:
- Direct answer based on the intelligence data
- Key IOCs if relevant
- Confidence level (High/Medium/Low) based on source quality
- Hebrew translation of the answer

OUTPUT: Return ONLY valid JSON with these fields:
{
  "answer_en": "",
  "answer_he": "",
  "key_iocs": [],
  "confidence": "High|Medium|Low"
}
No preamble. No markdown. Pure JSON only."""


def _throttle():
    """Enforce a minimum delay between consecutive Gemini calls (free tier)."""
    global _last_call_ts
    elapsed = time.time() - _last_call_ts
    if elapsed < CALL_DELAY_SECONDS:
        time.sleep(CALL_DELAY_SECONDS - elapsed)
    _last_call_ts = time.time()


def _format_context(items: list) -> str:
    """Render retrieved intelligence items as a numbered context block."""
    blocks = []
    for i, it in enumerate(items, 1):
        ed_iocs = it.get("iocs") or {}
        ioc_flat = []
        if isinstance(ed_iocs, dict):
            for bucket in ed_iocs.values():
                if isinstance(bucket, list):
                    ioc_flat.extend(str(v) for v in bucket if v)
        blocks.append(
            f"[{i}] Title: {it.get('title_en') or '(untitled)'}\n"
            f"    Severity: {it.get('severity')} | Confidence: {it.get('confidence_score')}\n"
            f"    Categories: {', '.join(it.get('categories') or []) or 'n/a'}\n"
            f"    Summary: {it.get('summary_en') or ''}\n"
            f"    CVEs: {', '.join(str(c) for c in (it.get('cves') or [])) or 'none'}\n"
            f"    Actors: {', '.join(str(a) for a in (it.get('actors') or [])) or 'none'}\n"
            f"    IOCs: {', '.join(ioc_flat) or 'none'}"
        )
    return "\n\n".join(blocks)


def _no_data_response(question: str) -> dict:
    """Uniform response when no supporting intelligence was found."""
    return {
        "answer_en": "No relevant intelligence was found in the database for this question.",
        "answer_he": "לא נמצא מידע מודיעיני רלוונטי במסד הנתונים עבור שאלה זו.",
        "sources": [],
        "confidence": "Low",
    }


def ask_intelligence(question: str) -> dict:
    """RAG pipeline — answer a question grounded in the collected intelligence.

    Returns: {answer_en, answer_he, sources, confidence}. Always returns a
    well-formed dict; on no data or rate-limit it degrades gracefully.
    """
    if not question or not question.strip():
        return {
            "answer_en": "Please provide a question.",
            "answer_he": "אנא ספק שאלה.",
            "sources": [],
            "confidence": "Low",
        }
    question = question.strip()

    # 1. Retrieve supporting context.
    items = _run_text_search(question, limit=CONTEXT_ITEMS)
    if not items:
        log_rag_query("ask", question, 0)
        return _no_data_response(question)

    # Compact source references returned to the caller (no raw rows).
    sources = [
        {
            "id": it.get("id"),
            "title": it.get("title_en"),
            "severity": it.get("severity"),
            "source_category": it.get("source_category"),
            "processed_at": it.get("processed_at"),
        }
        for it in items
    ]

    # 2. Format context + 3. ask Gemini.
    context = _format_context(items)
    prompt = (
        f"{RAG_SYSTEM_PROMPT}\n\n"
        f"=== INTELLIGENCE CONTEXT ===\n{context}\n\n"
        f"=== QUESTION ===\n{question}\n"
    )

    try:
        _throttle()
        log.info(f"[RAG] Asking Gemini ({GEMINI_MODEL}) over {len(items)} item(s)")
        result = call_gemini(prompt)
    except Exception as e:
        if _is_rate_limit_error(e):
            log.warning("[RAG] Gemini quota reached, returning graceful response.")
            log_rag_query("ask", question, len(items), error="rate_limited")
            return {
                "answer_en": "The intelligence assistant is rate-limited right now. Please try again shortly.",
                "answer_he": "עוזר המודיעין מוגבל כעת בקצב הבקשות. אנא נסה שוב בעוד מספר רגעים.",
                "sources": sources,
                "confidence": "Low",
            }
        log.error(f"[RAG] ask_intelligence Gemini call failed: {e}")
        log_rag_query("ask", question, len(items), error=str(e)[:200])
        return {
            "answer_en": "An error occurred while generating the answer.",
            "answer_he": "אירעה שגיאה בעת יצירת התשובה.",
            "sources": sources,
            "confidence": "Low",
        }

    # 4. Assemble the response.
    log_rag_query("ask", question, len(items))
    return {
        "answer_en": result.get("answer_en", ""),
        "answer_he": result.get("answer_he", ""),
        "key_iocs": result.get("key_iocs", []),
        "sources": sources,
        "confidence": result.get("confidence", "Medium"),
    }
