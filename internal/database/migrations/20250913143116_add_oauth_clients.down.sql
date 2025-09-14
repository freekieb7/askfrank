-- Migration: add external clients (DOWN)
-- Created: 2025-09-13 14:31:16
-- Version: 20250913143116

DROP TABLE tbl_oauth_refresh_token;

DROP TABLE tbl_oauth_access_token;

DROP TABLE tbl_oauth_auth_code;

DROP TABLE tbl_oauth_client;
