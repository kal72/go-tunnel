CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    username VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role INT2 NOT NULL DEFAULT 2, -- 1: admin, 2: user
    status INT2 NOT NULL DEFAULT 1, -- 0: inactive, 1: active
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Insert default admin user if not exists
INSERT INTO users (id, username, password, role, status)
VALUES ('019ee551-702c-73ff-b047-0cc7569fd575', 'admin', '$2a$10$hWH/RchoycVaOtlQzVp2A..cMEtcD86TxQdr3avbi5Mrh6mxW5J8S', 1, 1),
       ('019ee569-93a1-7d00-ade9-9a3c18af330a', 'user', '$2a$10$h1fY56wT/WnCv9YvN2cd8Oz5VthYz2Gl95GoYzy9nnkhCLLWn6V2u', 2, 1)
ON CONFLICT (username) DO NOTHING;
