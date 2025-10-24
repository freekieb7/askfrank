-- Migration: add users (DOWN)
-- Created: 2025-08-02 21:13:05
-- Version: 20250802211305

-- Migration: add users (UP)
-- Created: 2025-08-02 21:13:05
-- Version: 20250802211305

DROP TABLE tbl_oauth_refresh_token;
DROP TABLE tbl_oauth_refresh_token_chain;
DROP TABLE tbl_oauth_auth_code;
DROP TABLE tbl_oauth_access_token;
DROP TABLE tbl_oauth_client;
-- DROP TABLE tbl_notification;
-- DROP TABLE tbl_calendar_event_attendee;
-- DROP TABLE tbl_calendar_event;
-- DROP TABLE tbl_webhook_delivery;
-- DROP TABLE tbl_webhook_event;
-- DROP TABLE tbl_webhook_subscription;
-- DROP TABLE tbl_audit_log_event;
-- DROP TABLE tbl_file_share;
-- DROP TABLE tbl_file;
DROP TABLE tbl_group_invite;
DROP TABLE tbl_group_member;
DROP TABLE tbl_group;
DROP TABLE tbl_password_reset;
DROP TABLE tbl_session;
DROP TABLE tbl_user;