-- Migration: extend notifications table (UP)
-- Created: 2025-09-26 14:00:00
-- Version: 20250926140000

-- Add title and action_url columns to notifications table
ALTER TABLE tbl_notification 
ADD COLUMN title TEXT,
ADD COLUMN action_url TEXT;

-- Update existing notifications to have a default title
UPDATE tbl_notification SET title = 'Notification' WHERE title IS NULL;

-- Make title NOT NULL after setting default values
ALTER TABLE tbl_notification ALTER COLUMN title SET NOT NULL;