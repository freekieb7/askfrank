-- Migration: extend notifications table (DOWN)
-- Created: 2025-09-26 14:00:00
-- Version: 20250926140000

-- Remove the added columns
ALTER TABLE tbl_notification 
DROP COLUMN IF EXISTS title,
DROP COLUMN IF EXISTS action_url;