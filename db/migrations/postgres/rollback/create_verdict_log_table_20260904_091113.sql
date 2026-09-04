-- Rollback: create_verdict_log_table
-- Created:   2026-09-04 09:11:13 UTC
-- Feature:   docs/features/incident-aggregation/
-- Purpose:   Drop the PostgreSQL incident audit trail created by the forward migration.
-- Reversible: n/a -- this IS the reversal. Dropping the table discards recorded incidents.

DROP INDEX IF EXISTS idx_verdict_log_report_json;
DROP INDEX IF EXISTS idx_verdict_log_created_at;
DROP TABLE IF EXISTS verdict_log;
