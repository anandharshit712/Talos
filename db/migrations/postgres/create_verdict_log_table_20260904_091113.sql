-- Migration: create_verdict_log_table
-- Created:   2026-09-04 09:11:13 UTC
-- Feature:   docs/features/incident-aggregation/
-- Purpose:   PostgreSQL baseline for the incident audit trail. Engine change only -- the
--            columns match the SQLite set, in the engine's own types (standards 4.3).
-- Reversible: yes -> db/migrations/postgres/rollback/create_verdict_log_table_20260904_091113.sql

CREATE TABLE verdict_log (
    incident_id   TEXT             PRIMARY KEY,
    -- timestamptz, not timestamp: an incident stamp that loses its offset cannot be ordered
    -- against one recorded in another zone, and DESC ordering is the whole point of the index.
    created_at    TIMESTAMPTZ      NOT NULL,
    domain        TEXT             NOT NULL,
    category      TEXT             NOT NULL,
    severity      TEXT             NOT NULL,
    confidence    DOUBLE PRECISION NOT NULL,
    summary       TEXT             NOT NULL,
    verdict_count INTEGER          NOT NULL,
    -- The report verbatim. The columns above exist to query on; this is the record itself,
    -- so a stored incident survives any later change to the columns. jsonb rather than json
    -- so evidence and scope stay queryable without parsing every row.
    report_json   JSONB            NOT NULL
);

-- Listing is always newest-first (report API, P7).
CREATE INDEX idx_verdict_log_created_at ON verdict_log (created_at DESC);

-- Reaching into the stored report -- "which incidents scoped this account" -- without a
-- sequential scan. GIN is the index jsonb containment (@>) can actually use.
CREATE INDEX idx_verdict_log_report_json ON verdict_log USING GIN (report_json);
