-- ============================================================================
-- data_retention_cron.sql  —  rolling 2-month retention, run DAILY at 00:00 UTC.
--
-- Policy (Pillar 4): keep the CURRENT month + the PREVIOUS full month.
--   cutoff = date_trunc('month', NOW()) - INTERVAL '1 month'
-- Anything strictly older than `cutoff` is pruned/archived. This is a ROLLING
-- window (first-of-previous-month), NOT a fixed 60-day count.
--
-- NEVER deleted (permanent intel): iocs, cves, threat_actors, monthly_reports,
-- contradiction_checks.
--
-- Idempotent — safe to re-run in the Supabase SQL Editor.
--
-- IMPORTANT (Postgres): VACUUM cannot run inside a function/transaction, so the
-- deletes live in cleanup_old_data_rolling() (one daily cron job) and the
-- VACUUM ANALYZE is a SEPARATE daily cron job scheduled 15 minutes later.
-- ============================================================================

-- ── Retention function: steps 1-6 (deletes + archive). Returns a jsonb report.
CREATE OR REPLACE FUNCTION cleanup_old_data_rolling()
RETURNS jsonb
LANGUAGE plpgsql
AS $$
DECLARE
    cutoff timestamptz := date_trunc('month', timezone('utc', now())) - INTERVAL '1 month';
    n_jobs    bigint := 0;
    n_logs    bigint := 0;
    n_raw     bigint := 0;
    n_arch    bigint := 0;
    n_daily   bigint := 0;
    n_weekly  bigint := 0;
BEGIN
    -- 1. Old finished processing_jobs. finished_at is often NULL (never set by
    --    the app), so age via the linked raw_item's ingested_at as well.
    DELETE FROM processing_jobs pj
    USING raw_items ri
    WHERE pj.raw_item_id = ri.id
      AND pj.status IN ('done', 'failed')
      AND ri.ingested_at < cutoff;
    GET DIAGNOSTICS n_jobs = ROW_COUNT;

    -- 2. Old ingestion_logs.
    DELETE FROM ingestion_logs WHERE started_at < cutoff;
    GET DIAGNOSTICS n_logs = ROW_COUNT;

    -- 3. Old raw_items that no longer back an intelligence_item.
    DELETE FROM raw_items ri
    WHERE ri.ingested_at < cutoff
      AND NOT EXISTS (
          SELECT 1 FROM intelligence_items ii WHERE ii.raw_item_id = ri.id
      );
    GET DIAGNOSTICS n_raw = ROW_COUNT;

    -- 4. Archive (do NOT delete) old intelligence_items: drop the heavy
    --    enrichment_data jsonb, keep the row + flags for historical reporting.
    UPDATE intelligence_items
    SET enrichment_data = NULL, archived = true
    WHERE processed_at < cutoff AND archived = false;
    GET DIAGNOSTICS n_arch = ROW_COUNT;

    -- 5. Old daily_reports.
    DELETE FROM daily_reports WHERE report_date < cutoff::date;
    GET DIAGNOSTICS n_daily = ROW_COUNT;

    -- 6. Old weekly_reports (keyed on end_date).
    DELETE FROM weekly_reports WHERE end_date < cutoff::date;
    GET DIAGNOSTICS n_weekly = ROW_COUNT;

    -- NOTE: monthly_reports, iocs, cves, threat_actors, contradiction_checks are
    -- intentionally untouched (permanent).

    RETURN jsonb_build_object(
        'cutoff_date', cutoff,
        'processing_jobs_deleted', n_jobs,
        'ingestion_logs_deleted', n_logs,
        'raw_items_deleted', n_raw,
        'intelligence_items_archived', n_arch,
        'daily_reports_deleted', n_daily,
        'weekly_reports_deleted', n_weekly,
        'ran_at', timezone('utc', now())
    );
END;
$$;

-- ── Schedule with pg_cron (idempotent: unschedule existing jobs of these names).
DO $$
BEGIN
    PERFORM 1 FROM pg_extension WHERE extname = 'pg_cron';
    IF NOT FOUND THEN
        RAISE NOTICE 'pg_cron not installed — run: CREATE EXTENSION pg_cron; then re-run this file.';
        RETURN;
    END IF;

    -- Remove any prior versions of our jobs so re-running doesn't duplicate them.
    PERFORM cron.unschedule(jobid)
    FROM cron.job
    WHERE jobname IN ('daily-retention-cleanup', 'daily-retention-vacuum');

    -- 7a. Daily deletes/archive at 00:00 UTC.
    PERFORM cron.schedule(
        'daily-retention-cleanup', '0 0 * * *',
        $cmd$ SELECT cleanup_old_data_rolling(); $cmd$
    );

    -- 7b. Daily VACUUM ANALYZE at 00:15 UTC (separate job — VACUUM can't run in a
    --     function/transaction). Reclaims space + refreshes planner stats.
    PERFORM cron.schedule(
        'daily-retention-vacuum', '15 0 * * *',
        $cmd$ VACUUM ANALYZE raw_items, intelligence_items, processing_jobs, ingestion_logs; $cmd$
    );
END;
$$;

-- Manual run (deletes only; run the VACUUM separately, outside a transaction):
--   SELECT cleanup_old_data_rolling();
--   VACUUM ANALYZE raw_items, intelligence_items, processing_jobs, ingestion_logs;
