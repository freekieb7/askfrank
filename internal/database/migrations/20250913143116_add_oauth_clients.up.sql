-- Migration: add external clients (UP)
-- Created: 2025-09-13 14:31:16
-- Version: 20250913143116

CREATE TABLE tbl_oauth_client (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    redirect_uris TEXT[] NOT NULL,
    public BOOLEAN NOT NULL DEFAULT FALSE,
    secret TEXT NULL,
    allowed_scopes TEXT[] NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

CREATE TABLE tbl_oauth_auth_code (
    code TEXT PRIMARY KEY,
    data JSONB NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL
);

CREATE TABLE tbl_oauth_access_token (
    token TEXT PRIMARY KEY,
    clientID UUID NOT NULL REFERENCES tbl_oauth_client(id) ON DELETE CASCADE,
    data JSONB NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL
);

CREATE TABLE tbl_oauth_refresh_token (
    token TEXT PRIMARY KEY,
    clientID UUID NOT NULL REFERENCES tbl_oauth_client(id) ON DELETE CASCADE,
    data JSONB NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL
);