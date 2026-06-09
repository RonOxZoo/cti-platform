-- ============================================================================
-- Data retention: rolling 2-month window.
-- Keep the current month + the previous full month; delete anything before the
-- 1st day of the previous month.
--   e.g. on 2026-06-09 the cutoff is 2026-05-01 (keep >= May 1, delete < May 1).
--
-- Apply this in the Supabase SQL editor (DDL + pg_cron can't go through the
-- REST/PostgREST API that the app uses).
--
-- NOTE — two corrections vs. the original spec, made to match the live schema:
--   1. intelligence_items has no `archived` column yet -> added below.
--   2. processing_jobs has no `created_at` (and started_at/finished_at are
--      unused/NULL), so a job's age is derived from its linked raw_item's
--      ingested_at instead.
-- ============================================================================

-- intelligence_items needs an `archived` flag for the archive step and for the
-- /status "archived items" count.
ALTER TABLE intelligence_items
  ADD COLUMN IF NOT EXISTS archived boolean NOT NULL DEFAULT false;

CREATE OR REPLACE FUNCTION cleanup_old_data()
RETURNS jsonb AS $$
DECLARE
  cutoff_date timestamptz;
  deleted_raw integer;
  deleted_jobs integer;
  deleted_logs integer;
  deleted_daily integer;
  deleted_weekly integer;
  archived_intel integer;
BEGIN
  -- Cutoff = first day of the previous month
  cutoff_date := date_trunc('month', NOW()) - INTERVAL '1 month';

  -- Delete old processing jobs.
  -- processing_jobs has no creation timestamp of its own, so age is taken from
  -- the linked raw_item's ingested_at. Only done/failed jobs are removed.
  DELETE FROM processing_jobs pj
  WHERE pj.status IN ('done', 'failed')
    AND EXISTS (
      SELECT 1 FROM raw_items ri
      WHERE ri.id = pj.raw_item_id
        AND ri.ingested_at < cutoff_date
    );
  GET DIAGNOSTICS deleted_jobs = ROW_COUNT;

  -- Delete old ingestion logs
  DELETE FROM ingestion_logs
  WHERE started_at < cutoff_date;
  GET DIAGNOSTICS deleted_logs = ROW_COUNT;

  -- Delete old raw items not linked to intelligence_items
  DELETE FROM raw_items
  WHERE ingested_at < cutoff_date
    AND id NOT IN (
      SELECT raw_item_id FROM intelligence_items
      WHERE raw_item_id IS NOT NULL
    );
  GET DIAGNOSTICS deleted_raw = ROW_COUNT;

  -- Archive old intelligence items (clear heavy JSONB, keep the record)
  UPDATE intelligence_items
  SET enrichment_data = NULL,
      archived = true
  WHERE processed_at < cutoff_date
    AND archived = false;
  GET DIAGNOSTICS archived_intel = ROW_COUNT;

  -- Delete old daily reports
  DELETE FROM daily_reports
  WHERE report_date < cutoff_date;
  GET DIAGNOSTICS deleted_daily = ROW_COUNT;

  -- Delete old weekly reports
  DELETE FROM weekly_reports
  WHERE end_date < cutoff_date;
  GET DIAGNOSTICS deleted_weekly = ROW_COUNT;

  -- Monthly reports: NEVER delete
  -- IOCs, CVEs, threat_actors: NEVER delete
  -- contradiction_checks: NEVER delete
  -- learning_feedback: NEVER delete

  RETURN jsonb_build_object(
    'cutoff_date', cutoff_date,
    'deleted_raw_items', deleted_raw,
    'deleted_processing_jobs', deleted_jobs,
    'deleted_ingestion_logs', deleted_logs,
    'deleted_daily_reports', deleted_daily,
    'deleted_weekly_reports', deleted_weekly,
    'archived_intelligence_items', archived_intel
  );
END;
$$ LANGUAGE plpgsql;

-- Reschedule cron to run at 03:00 UTC on the 1st of every month
SELECT cron.unschedule('daily-cleanup') WHERE EXISTS (
  SELECT 1 FROM cron.job WHERE jobname = 'daily-cleanup'
);

SELECT cron.schedule(
  'monthly-cleanup',
  '0 3 1 * *',
  'SELECT cleanup_old_data();'
);
