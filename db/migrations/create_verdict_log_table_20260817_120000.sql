-- Migration: create_verdict_log_table
-- Created:   2026-08-17 12:00:00 UTC
-- Feature:   docs/features/incident-aggregation/
-- Purpose:   Persistent audit trail of incident reports for replay and report retrieval.
-- Reversible: yes -> db/migrations/rollback/create_verdict_log_table_20260817_120000.sql

CREATE TABLE verdict_log (
    incident_id   TEXT    PRIMARY KEY,
    created_at    TEXT    NOT NULL,
    domain        TEXT    NOT NULL,
    category      TEXT    NOT NULL,
    severity      TEXT    NOT NULL,
    confidence    REAL    NOT NULL,
    summary       TEXT    NOT NULL,
    verdict_count INTEGER NOT NULL,
    -- The report verbatim. The columns above exist to query on; this is the record itself,
    -- so a stored incident survives any later change to the columns.
    report_json   TEXT    NOT NULL
);

-- Listing is always newest-first (report API, P7).
CREATE INDEX idx_verdict_log_created_at ON verdict_log (created_at DESC);
