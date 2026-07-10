CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(64) NOT NULL,
    key_hash VARCHAR(64) NOT NULL,  -- SHA-256 hex (64 chars)
    status INT2 NOT NULL DEFAULT 1, -- 1: active, 0: revoked
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,  -- NULL = no expiration
    last_used_at TIMESTAMP WITH TIME ZONE,

    -- Constraints
    CONSTRAINT api_keys_key_hash_unique UNIQUE (key_hash)
);

-- Partial unique index: name uniqueness only among active keys per user
CREATE UNIQUE INDEX idx_api_keys_name_unique
    ON api_keys(user_id, name)
    WHERE status = 1;

-- Index for fast hash lookup (O(log n))
CREATE INDEX idx_api_keys_key_hash ON api_keys(key_hash);

-- Index for listing user's keys
CREATE INDEX idx_api_keys_user_id ON api_keys(user_id, created_at DESC);

-- Index for counting active keys
CREATE INDEX idx_api_keys_user_active ON api_keys(user_id, status)
    WHERE status = 1;
