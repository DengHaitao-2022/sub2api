SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '10min';

CREATE TABLE IF NOT EXISTS gateway_audit_indexer_offsets (
    file_path       TEXT PRIMARY KEY,
    next_offset     BIGINT NOT NULL DEFAULT 0,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_indexed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_gateway_audit_indexer_offsets_updated_at
    ON gateway_audit_indexer_offsets (updated_at DESC);
