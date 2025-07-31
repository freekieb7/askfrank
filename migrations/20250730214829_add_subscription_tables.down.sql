-- Migration down
-- Drop subscription tables in reverse order
DROP TABLE IF EXISTS tbl_subscription_invoice;
DROP TABLE IF EXISTS tbl_user_subscription;
DROP TABLE IF EXISTS tbl_subscription_plan;

