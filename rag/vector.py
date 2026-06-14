"""
Vector (semantic) retrieval engine for RAG — Pillar 3.

pgvector store + Gemini embeddings. Policy (all enforced here):
  - chunk size  : <= 500 tokens, ~10% overlap
  - similarity  : cosine >= 0.82 (SIM_THRESHOLD)
  - retrieval   : top 3 chunks (TOP_K), deduplicated before use
  - never run unbounded full-text scans for historical lookups (callers fall
    back to bounded FTS in rag/search.py only when vector search is unavailable)

Embeddings use Gemini `text-embedding-004` (768-dim). Note: this does NOT violate
PRIORITY ZERO — that rule governs the *enrichment* agent (Claude); Anthropic has
no embeddings API, so Gemini is the embeddings provider. Everything degrades
gracefully: if GEMINI_API_KEY is absent or the pgvector schema
(sql/enable_pgvector.sql) hasn't been applied, the public functions return
empty / False and callers transparently fall back to keyword search.
"""
import os
import logging
import hashlib

from database.supabase_client import client

log = logging.getLogger(__name__)

# gemini-embedding-001 defaults to 3072 dims; we request 768 via
# output_dimensionality (3072 exceeds pgvector ivfflat's 2000-dim ceiling, and
# 768 keeps the index compact). Cosine similarity is scale-invariant, so the
# non-3072 truncation needs no extra normalization for our distance metric.
EMBED_MODEL = "gemini-embedding-001"
EMBED_DIM = 768

# Chunking. Tokens are approximated as words * ~1.33; 375 words ≈ 500 tokens.
CHUNK_MAX_TOKENS = 500
CHUNK_OVERLAP_PCT = 0.10
_WORDS_PER_CHUNK = int(CHUNK_MAX_TOKENS * 0.75)          # ≈ 375
_OVERLAP_WORDS = max(1, int(_WORDS_PER_CHUNK * CHUNK_OVERLAP_PCT))  # ≈ 37

# Retrieval.
SIM_THRESHOLD = 0.82
TOP_K = 3


def is_available() -> bool:
    """True if embeddings can be produced (GEMINI_API_KEY present)."""
    return bool(os.getenv("GEMINI_API_KEY"))


# ── Chunking ─────────────────────────────────────────────────
def chunk_text(text: str, max_tokens: int = CHUNK_MAX_TOKENS,
               overlap_pct: float = CHUNK_OVERLAP_PCT) -> list:
    """Split text into overlapping word-windows (<= max_tokens, ~overlap_pct).

    Deduplicates identical chunks. Returns [] for empty input.
    """
    text = (text or "").strip()
    if not text:
        return []
    words = text.split()
    per = max(1, int(max_tokens * 0.75))
    overlap = max(1, int(per * overlap_pct))
    step = max(1, per - overlap)

    chunks, seen = [], set()
    for start in range(0, len(words), step):
        window = words[start:start + per]
        if not window:
            break
        chunk = " ".join(window).strip()
        key = chunk.lower()
        if chunk and key not in seen:
            seen.add(key)
            chunks.append(chunk)
        if start + per >= len(words):
            break
    return chunks


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


# ── Embeddings (Gemini) ──────────────────────────────────────
def _genai_client():
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY is not set")
    from google import genai
    return genai.Client(api_key=api_key)


def _extract_vector(resp):
    """Pull a 768-float list out of a google-genai embed response (defensive)."""
    embs = getattr(resp, "embeddings", None)
    if embs:
        first = embs[0]
        vals = getattr(first, "values", None) or (first.get("values") if isinstance(first, dict) else None)
        if vals:
            return list(vals)
    # Older shape: resp.embedding.values
    emb = getattr(resp, "embedding", None)
    if emb is not None:
        vals = getattr(emb, "values", None)
        if vals:
            return list(vals)
    return None


def embed_text(text: str):
    """Return the embedding vector for `text`, or None on any failure."""
    text = (text or "").strip()
    if not text:
        return None
    try:
        resp = _genai_client().models.embed_content(
            model=EMBED_MODEL, contents=text,
            config={"output_dimensionality": EMBED_DIM},
        )
        vec = _extract_vector(resp)
        if vec and len(vec) == EMBED_DIM:
            return vec
        log.warning("[VECTOR] unexpected embedding shape (len=%s)", len(vec) if vec else None)
    except Exception as e:
        log.warning(f"[VECTOR] embed_text failed: {str(e)[:160]}")
    return None


# ── Indexing ─────────────────────────────────────────────────
def index_item(item_id: str, text: str, title: str = "") -> int:
    """Chunk + embed `text` and upsert the chunks for `item_id`. Returns count.

    Best-effort: returns 0 (and logs) if embeddings/pgvector aren't available.
    Idempotent per (item_id, chunk_index) via upsert.
    """
    if not item_id or not is_available():
        return 0
    full = f"{title}\n\n{text}".strip() if title else (text or "")
    chunks = chunk_text(full)
    if not chunks:
        return 0
    written = 0
    for idx, chunk in enumerate(chunks):
        vec = embed_text(chunk)
        if not vec:
            continue
        try:
            client.table("intel_chunks").upsert({
                "item_id": item_id,
                "chunk_index": idx,
                "content": chunk[:4000],
                "content_hash": _hash(chunk),
                "embedding": vec,
            }, on_conflict="item_id,chunk_index").execute()
            written += 1
        except Exception as e:
            log.warning(f"[VECTOR] chunk upsert failed (item={item_id} idx={idx}): {str(e)[:160]}")
            # If the table/extension is missing there's no point continuing.
            break
    if written:
        log.info("[VECTOR] indexed %d/%d chunk(s) for item %s", written, len(chunks), item_id)
    return written


# ── Retrieval ────────────────────────────────────────────────
def vector_search(query: str, top_k: int = TOP_K, threshold: float = SIM_THRESHOLD) -> list:
    """Semantic search over intel_chunks. Returns deduped chunk dicts (or []).

    Each result: {"item_id", "content", "similarity", "chunk_index"}. Returns []
    (no raise) when embeddings or the pgvector RPC are unavailable, so the caller
    can fall back to keyword search.
    """
    query = (query or "").strip()
    if not query or not is_available():
        return []
    vec = embed_text(query)
    if not vec:
        return []
    try:
        # Over-fetch a little so post-dedup we can still return top_k distinct items.
        resp = client.rpc("match_intel_chunks", {
            "query_embedding": vec,
            "match_threshold": threshold,
            "match_count": max(top_k * 3, top_k),
        }).execute()
        rows = resp.data or []
    except Exception as e:
        log.warning(f"[VECTOR] match_intel_chunks RPC unavailable: {str(e)[:160]}")
        return []

    # Deduplicate: at most one chunk per item, highest similarity first.
    seen_items, out = set(), []
    for r in sorted(rows, key=lambda x: x.get("similarity", 0), reverse=True):
        iid = r.get("item_id")
        if iid in seen_items:
            continue
        seen_items.add(iid)
        out.append({
            "item_id": iid,
            "content": r.get("content"),
            "similarity": round(float(r.get("similarity") or 0), 4),
            "chunk_index": r.get("chunk_index"),
        })
        if len(out) >= top_k:
            break
    log.info("[VECTOR] semantic search '%s' -> %d chunk(s)", query[:60], len(out))
    return out
