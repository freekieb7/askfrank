-- Drop indexes
DROP INDEX IF EXISTS idx_audit_log_session_id;
DROP INDEX IF EXISTS idx_audit_log_action;
DROP INDEX IF EXISTS idx_audit_log_created_at;
DROP INDEX IF EXISTS idx_audit_log_entity;
DROP INDEX IF EXISTS idx_audit_log_user_id;

-- Drop table
DROP TABLE IF EXISTS tbl_audit_log;
