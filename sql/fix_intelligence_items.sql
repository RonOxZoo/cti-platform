-- ============================================================================
-- intelligence_items schema fix for Gemini enrichment.
-- Apply in the Supabase SQL editor.
-- ============================================================================

-- ── Block A — EXACTLY as provided in the request ────────────────────────────
-- NOTE: the rewritten enrichment/gemini.py maps Gemini output onto the EXISTING
-- columns (categories, severity_rationale, confidence_score, confidence_rationale,
-- enrichment_data, gemini_processed, processed_at, ...). It does NOT write to the
-- columns added below, so Block A is OPTIONAL for the fix to work. Only
-- contradiction_flag / discovery_notes are net-new (reserved for future use).
ALTER TABLE intelligence_items
ADD COLUMN IF NOT EXISTS category text,
ADD COLUMN IF NOT EXISTS severity_reason text,
ADD COLUMN IF NOT EXISTS confidence integer,
ADD COLUMN IF NOT EXISTS iocs jsonb,
ADD COLUMN IF NOT EXISTS cves text[],
ADD COLUMN IF NOT EXISTS actors text[],
ADD COLUMN IF NOT EXISTS mitre text[],
ADD COLUMN IF NOT EXISTS enriched_at timestamptz,
ADD COLUMN IF NOT EXISTS contradiction_flag boolean DEFAULT false,
ADD COLUMN IF NOT EXISTS discovery_notes text;

-- ── Block B — REQUIRED for the ON CONFLICT (raw_item_id) upsert (STEP 3) ─────
-- Added beyond the pasted SQL: the upsert in gemini.py needs a unique key on
-- raw_item_id, otherwise PostgREST/Postgres raises:
--   "there is no unique or exclusion constraint matching the ON CONFLICT spec".
-- A unique index satisfies the conflict target and is idempotent to create.
CREATE UNIQUE INDEX IF NOT EXISTS intelligence_items_raw_item_id_key
  ON intelligence_items (raw_item_id);
