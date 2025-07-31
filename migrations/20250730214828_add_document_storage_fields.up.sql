-- Migration up
-- Add storage-related fields to the documents table
ALTER TABLE tbl_document 
ADD COLUMN content_type VARCHAR(255) NOT NULL DEFAULT 'application/octet-stream',
ADD COLUMN storage_key VARCHAR(500) NOT NULL DEFAULT '';

-- Create index on storage_key for lookups
CREATE INDEX IF NOT EXISTS idx_document_storage_key ON tbl_document(storage_key);

