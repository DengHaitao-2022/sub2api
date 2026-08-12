SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '10min';

CREATE TABLE IF NOT EXISTS gateway_audit_index (
    audit_id          VARCHAR(64) PRIMARY KEY,
    request_id        VARCHAR(128),
    client_request_id VARCHAR(128),
    user_id           BIGINT,
    api_key_id        BIGINT,
    account_id        BIGINT,
    group_id          BIGINT,
    platform          VARCHAR(64),
    model             VARCHAR(255),
    inbound_endpoint  VARCHAR(255),
    upstream_endpoint VARCHAR(255),
    method            VARCHAR(16),
    path              VARCHAR(512),
    status_code       INTEGER,
    error_type        VARCHAR(255),
    input_hash        VARCHAR(128),
    output_hash       VARCHAR(128),
    input_size        BIGINT NOT NULL DEFAULT 0,
    output_size       BIGINT NOT NULL DEFAULT 0,
    input_truncated   BOOLEAN NOT NULL DEFAULT FALSE,
    output_truncated  BOOLEAN NOT NULL DEFAULT FALSE,
    duration_ms       BIGINT NOT NULL DEFAULT 0,
    time_to_first_token_ms BIGINT NOT NULL DEFAULT 0,
    capture_mode      VARCHAR(64),
    sampled           BOOLEAN NOT NULL DEFAULT TRUE,
    file_path         TEXT,
    file_offset       BIGINT NOT NULL DEFAULT 0,
    line_bytes        BIGINT NOT NULL DEFAULT 0,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_gateway_audit_created_at
    ON gateway_audit_index (created_at DESC, audit_id DESC);
CREATE INDEX IF NOT EXISTS idx_gateway_audit_request
    ON gateway_audit_index (request_id, api_key_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_gateway_audit_client_request
    ON gateway_audit_index (client_request_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_gateway_audit_user_time
    ON gateway_audit_index (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_gateway_audit_api_key_time
    ON gateway_audit_index (api_key_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_gateway_audit_account_time
    ON gateway_audit_index (account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_gateway_audit_group_time
    ON gateway_audit_index (group_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_gateway_audit_status_time
    ON gateway_audit_index (status_code, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_gateway_audit_platform_model_time
    ON gateway_audit_index (platform, model, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_gateway_audit_duration_time
    ON gateway_audit_index (duration_ms DESC, created_at DESC);

CREATE TABLE IF NOT EXISTS admin_audit_access_logs (
    id            BIGSERIAL PRIMARY KEY,
    operator_id   BIGINT NOT NULL,
    audit_id      VARCHAR(64) NOT NULL,
    action        VARCHAR(64) NOT NULL DEFAULT 'view_detail',
    viewed_fields TEXT[] NOT NULL DEFAULT '{}',
    ip_address    INET,
    user_agent    TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_admin_audit_access_audit_time
    ON admin_audit_access_logs (audit_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_admin_audit_access_operator_time
    ON admin_audit_access_logs (operator_id, created_at DESC);
