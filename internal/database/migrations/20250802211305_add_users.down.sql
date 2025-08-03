-- Migration: add users (DOWN)
-- Created: 2025-08-02 21:13:05
-- Version: 20250802211305

DROP INDEX idx_user_email;
DROP TABLE tbl_user;