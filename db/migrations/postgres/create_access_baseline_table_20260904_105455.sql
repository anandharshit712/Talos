-- Migration: create_access_baseline_table
-- Created:   2026-09-04 10:54:55 UTC
-- Feature:   docs/features/web-broken-access-control/
-- Purpose:   Per-account learned access patterns, so IDOR detection survives a restart.
-- Reversible: yes -> db/migrations/postgres/rollback/create_access_baseline_table_20260904_105455.sql

CREATE TABLE access_baseline (
    -- One row per account, so the primary key IS the lookup index. No second index is
    -- created on this column: the PK already provides one.
    account         TEXT        PRIMARY KEY,

    -- The observed id range, kept as columns rather than inside the JSON because range
    -- comparison is the one deviation feature worth asking the database about.
    numeric_min     BIGINT,
    numeric_max     BIGINT,

    -- What maturity is measured against. Not derivable from the bounded collections below:
    -- summing them would undercount a busy account back below its own threshold.
    observations    INTEGER     NOT NULL DEFAULT 0 CHECK (observations >= 0),

    -- Bounded collections, written whole. jsonb rather than an array or a child table: they
    -- are read and replaced as one value under the account's lock, never queried element-wise.
    seen_object_ids JSONB       NOT NULL DEFAULT '[]'::jsonb,
    endpoints       JSONB       NOT NULL DEFAULT '{}'::jsonb,

    updated_at      TIMESTAMPTZ NOT NULL
);

-- Finding baselines that have gone stale (an account that stopped appearing) is a maintenance
-- question, not a hot-path one, but it is the only query here that is not by primary key.
CREATE INDEX idx_access_baseline_updated_at ON access_baseline (updated_at);
