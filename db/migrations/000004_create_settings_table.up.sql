CREATE TABLE IF NOT EXISTS system_settings (
    key VARCHAR(255) PRIMARY KEY,
    value JSONB NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Insert default settings if they don't exist
INSERT INTO system_settings (key, value) VALUES 
    ('max_free_domains', '"5"'),
    ('max_tunnels_per_user', '"3"'),
    ('allow_registration', '"true"')
ON CONFLICT (key) DO NOTHING;
