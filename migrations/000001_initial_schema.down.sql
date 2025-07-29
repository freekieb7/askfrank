-- Drop indexes
DROP INDEX IF EXISTS idx_sessions_expire;
DROP INDEX IF EXISTS idx_user_registration_activation_code;
DROP INDEX IF EXISTS idx_user_registration_user_id;
DROP INDEX IF EXISTS idx_user_role;
DROP INDEX IF EXISTS idx_user_email;

-- Drop tables in reverse order (due to foreign key constraints)
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS tbl_user_registration;
DROP TABLE IF EXISTS tbl_user;
