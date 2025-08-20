-- Migration: add_shared_files (UP)
-- Created: 2025-08-22 12:26:41
-- Version: 20250822122641

CREATE TABLE tbl_shared_files (
	file_id UUID REFERENCES tbl_file(id) ON DELETE CASCADE,
	sharing_user_id UUID REFERENCES tbl_user(id) ON DELETE CASCADE,
	receiving_user_id UUID REFERENCES tbl_user(id) ON DELETE CASCADE,
	granted_at TIMESTAMP NOT NULL,
    PRIMARY KEY (file_id, sharing_user_id, receiving_user_id)
);
