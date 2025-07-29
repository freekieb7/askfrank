-- Create users table
CREATE TABLE IF NOT EXISTS tbl_user (
    id UUID PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    is_email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    role VARCHAR(20) NOT NULL DEFAULT 'user',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Create user registration table for email verification
CREATE TABLE IF NOT EXISTS tbl_user_registration (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES tbl_user(id) ON DELETE CASCADE,
    activation_code VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Create sessions table for session storage
CREATE TABLE IF NOT EXISTS sessions (
    k VARCHAR(255) PRIMARY KEY,
    v BYTEA,
    e BIGINT
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_user_email ON tbl_user(email);
CREATE INDEX IF NOT EXISTS idx_user_role ON tbl_user(role);
CREATE INDEX IF NOT EXISTS idx_user_registration_user_id ON tbl_user_registration(user_id);
CREATE INDEX IF NOT EXISTS idx_user_registration_activation_code ON tbl_user_registration(activation_code);
CREATE INDEX IF NOT EXISTS idx_sessions_expire ON sessions(e);
