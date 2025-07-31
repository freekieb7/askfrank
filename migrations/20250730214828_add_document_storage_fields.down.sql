-- Migration down
-- Remove storage-related fields from the documents table
DROP INDEX IF EXISTS idx_document_storage_key;
ALTER TABLE tbl_document 
DROP COLUMN IF EXISTS content_type,
DROP COLUMN IF EXISTS storage_key;

