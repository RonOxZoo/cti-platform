-- ============================================================================
-- Reset ALL processing jobs back to pending for a full re-enrichment with the
-- upgraded Gemini prompt. Run in the Supabase SQL editor.
--
-- WARNING: this re-queues every job (done + failed). The upgraded enrichment
-- run will re-score them with priority ordering (CRITICAL/HIGH first). Make
-- sure sql/add_tags_column.sql has been applied first so the new columns exist.
-- ============================================================================

UPDATE processing_jobs
SET status = 'pending', retries = 0, error_message = null;
