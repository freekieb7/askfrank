-- Migration: add users (UP)
-- Created: 2025-08-02 21:13:05
-- Version: 20250802211305

CREATE TABLE tbl_user (
    id UUID PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash bytea NOT NULL,
    is_email_verified BOOLEAN,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);

CREATE INDEX idx_user_email ON tbl_user (email);