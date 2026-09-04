-- Rollback: create_access_baseline_table
-- Created:   2026-09-04 10:54:55 UTC
-- Feature:   docs/features/web-broken-access-control/
-- Purpose:   Drop the per-account access baselines created by the forward migration.
-- Reversible: n/a -- this IS the reversal. Dropping the table discards every learned baseline,
--             which means every account returns to cold start and IDOR detection reports
--             "baseline immature" until the history is relearned.

DROP INDEX IF EXISTS idx_access_baseline_updated_at;
DROP TABLE IF EXISTS access_baseline;
