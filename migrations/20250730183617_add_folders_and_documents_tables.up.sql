-- Create folders table
CREATE TABLE IF NOT EXISTS tbl_folder (
    id UUID PRIMARY KEY,
    owner_id UUID NOT NULL REFERENCES tbl_user(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    last_modified TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Create documents table
CREATE TABLE IF NOT EXISTS tbl_document (
    id UUID PRIMARY KEY,
    owner_id UUID NOT NULL REFERENCES tbl_user(id) ON DELETE CASCADE,
    folder_id UUID REFERENCES tbl_folder(id) ON DELETE SET NULL,
    name VARCHAR(255) NOT NULL,
    size BIGINT NOT NULL DEFAULT 0,
    last_modified TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_folder_owner_id ON tbl_folder(owner_id);
CREATE INDEX IF NOT EXISTS idx_folder_name ON tbl_folder(name);
CREATE INDEX IF NOT EXISTS idx_folder_last_modified ON tbl_folder(last_modified);
CREATE INDEX IF NOT EXISTS idx_document_owner_id ON tbl_document(owner_id);
CREATE INDEX IF NOT EXISTS idx_document_folder_id ON tbl_document(folder_id);
CREATE INDEX IF NOT EXISTS idx_document_name ON tbl_document(name);
CREATE INDEX IF NOT EXISTS idx_document_last_modified ON tbl_document(last_modified);
