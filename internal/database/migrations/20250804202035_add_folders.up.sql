-- Migration: add folders (UP)
-- Created: 2025-08-04 20:20:35
-- Version: 20250804202035

CREATE TABLE tbl_file (
    id UUID PRIMARY KEY,
    owner_id UUID NOT NULL REFERENCES tbl_user(id) ON DELETE CASCADE,
    parent_id UUID REFERENCES tbl_file(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    s3_key TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    is_folder BOOLEAN NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

CREATE INDEX idx_file_owner ON tbl_file (owner_id);
CREATE INDEX idx_file_parent ON tbl_file (parent_id);
CREATE INDEX idx_file_s3_key ON tbl_file (s3_key);
CREATE UNIQUE INDEX idx_file_parent_name ON tbl_file (parent_id, name);
