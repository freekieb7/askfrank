-- Drop indexes
DROP INDEX IF EXISTS idx_document_last_modified;
DROP INDEX IF EXISTS idx_document_name;
DROP INDEX IF EXISTS idx_document_folder_id;
DROP INDEX IF EXISTS idx_document_owner_id;
DROP INDEX IF EXISTS idx_folder_last_modified;  
DROP INDEX IF EXISTS idx_folder_name;
DROP INDEX IF EXISTS idx_folder_owner_id;

-- Drop tables
DROP TABLE IF EXISTS tbl_document;
DROP TABLE IF EXISTS tbl_folder;
