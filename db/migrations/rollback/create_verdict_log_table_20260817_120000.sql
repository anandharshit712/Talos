-- Rollback: create_verdict_log_table
-- Created:   2026-08-17 12:00:00 UTC
-- Feature:   docs/features/incident-aggregation/
-- Purpose:   Drop the incident audit trail created by the forward migration.
-- Reversible: n/a -- this IS the reversal. Dropping the table discards recorded incidents.

DROP INDEX IF EXISTS idx_verdict_log_created_at;
DROP TABLE IF EXISTS verdict_log;
