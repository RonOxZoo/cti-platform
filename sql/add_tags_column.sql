-- ============================================================================
-- intelligence_items — columns for the richer Gemini CTI extraction.
-- Apply in the Supabase SQL editor BEFORE deploying the upgraded
-- enrichment/gemini.py (otherwise the upsert falls back to writing without
-- these columns and logs a warning).
-- ============================================================================

ALTER TABLE intelligence_items ADD COLUMN IF NOT EXISTS tags text[];
ALTER TABLE intelligence_items ADD COLUMN IF NOT EXISTS targeted_sectors text[];
ALTER TABLE intelligence_items ADD COLUMN IF NOT EXISTS targeted_countries text[];
ALTER TABLE intelligence_items ADD COLUMN IF NOT EXISTS campaign_name text;
ALTER TABLE intelligence_items ADD COLUMN IF NOT EXISTS malware_families text[];
