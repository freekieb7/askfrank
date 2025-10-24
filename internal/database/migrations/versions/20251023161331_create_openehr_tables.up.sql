-- Migration: create_openehr_tables (UP)
-- Created: 2025-10-23 16:13:31
-- Version: 20251023161331

CREATE TABLE tbl_openehr_ehr (
    id UUID PRIMARY KEY,
    data JSONB NOT NULL,
    created_at TIMESTAMP NOT NULL
);

CREATE INDEX idx_openehr_ehr_data ON tbl_openehr_ehr USING GIN (data);

CREATE TABLE tbl_openehr_contribution (
    id UUID PRIMARY KEY,
    ehr_id UUID REFERENCES tbl_openehr_ehr(id) ON DELETE CASCADE,
    data JSONB NOT NULL,
    created_at TIMESTAMP NOT NULL
);

CREATE INDEX idx_openehr_contribution_ehr_id ON tbl_openehr_contribution(ehr_id);
CREATE INDEX idx_openehr_contribution_data ON tbl_openehr_contribution USING GIN (data);

CREATE TABLE tbl_openehr_contribution_version (
    contribution_id UUID REFERENCES tbl_openehr_contribution(id) ON DELETE CASCADE,
    object_id TEXT NOT NULL
);

CREATE INDEX idx_openehr_contribution_version_contribution_id ON tbl_openehr_contribution_version(contribution_id);
CREATE INDEX idx_openehr_contribution_version_object_id ON tbl_openehr_contribution_version(object_id);

CREATE TABLE tbl_openehr_versioned_object (
    id UUID PRIMARY KEY,
    ehr_id UUID REFERENCES tbl_openehr_ehr(id) ON DELETE CASCADE,
    data JSONB NOT NULL,
    created_at TIMESTAMP NOT NULL
);

CREATE INDEX idx_openehr_versioned_object_ehr_id ON tbl_openehr_versioned_object(ehr_id);
CREATE INDEX idx_openehr_versioned_object_data ON tbl_openehr_versioned_object USING GIN (data);

CREATE TABLE tbl_openehr_ehr_status (
    id TEXT PRIMARY KEY,
    versioned_object_id UUID NOT NULL REFERENCES tbl_openehr_versioned_object(id) ON DELETE CASCADE,
    system_id TEXT NOT NULL,
    version_tree_id TEXT NOT NULL,
    ehr_id UUID NOT NULL REFERENCES tbl_openehr_ehr(id) ON DELETE CASCADE,
    data JSONB NOT NULL,
    created_at TIMESTAMP NOT NULL
);

CREATE INDEX idx_openehr_ehr_status_versioned_object_id ON tbl_openehr_ehr_status(versioned_object_id);
CREATE INDEX idx_openehr_ehr_status_ehr_id ON tbl_openehr_ehr_status(ehr_id);
CREATE INDEX idx_openehr_ehr_status_data ON tbl_openehr_ehr_status USING GIN (data);

CREATE TABLE tbl_openehr_ehr_access (
    id TEXT PRIMARY KEY,
    versioned_object_id UUID NOT NULL REFERENCES tbl_openehr_versioned_object(id) ON DELETE CASCADE,
    system_id TEXT NOT NULL,
    version_tree_id TEXT NOT NULL,
    ehr_id UUID NOT NULL REFERENCES tbl_openehr_ehr(id) ON DELETE CASCADE,
    data JSONB NOT NULL,
    created_at TIMESTAMP NOT NULL
);

CREATE INDEX idx_openehr_ehr_access_versioned_object_id ON tbl_openehr_ehr_access(versioned_object_id);
CREATE INDEX idx_openehr_ehr_access_ehr_id ON tbl_openehr_ehr_access(ehr_id);
CREATE INDEX idx_openehr_ehr_access_data ON tbl_openehr_ehr_access USING GIN (data);

CREATE TABLE tbl_openehr_composition (
    id TEXT PRIMARY KEY,
    versioned_object_id UUID NOT NULL REFERENCES tbl_openehr_versioned_object(id) ON DELETE CASCADE,
    system_id TEXT NOT NULL,
    version_tree_id TEXT NOT NULL,
    ehr_id UUID NOT NULL REFERENCES tbl_openehr_ehr(id) ON DELETE CASCADE,
    data JSONB NOT NULL,
    created_at TIMESTAMP NOT NULL
);

CREATE INDEX idx_openehr_composition_versioned_object_id ON tbl_openehr_composition(versioned_object_id);
CREATE INDEX idx_openehr_composition_ehr_id ON tbl_openehr_composition(ehr_id);
CREATE INDEX idx_openehr_composition_data ON tbl_openehr_composition USING GIN (data);

CREATE TABLE tbl_openehr_folder (
    id TEXT PRIMARY KEY,
    versioned_object_id UUID NOT NULL REFERENCES tbl_openehr_versioned_object(id) ON DELETE CASCADE,
    system_id TEXT NOT NULL,
    version_tree_id TEXT NOT NULL,
    ehr_id UUID NOT NULL REFERENCES tbl_openehr_ehr(id) ON DELETE CASCADE,
    data JSONB NOT NULL,
    created_at TIMESTAMP NOT NULL
);

CREATE INDEX idx_openehr_folder_versioned_object_id ON tbl_openehr_folder(versioned_object_id);
CREATE INDEX idx_openehr_folder_ehr_id ON tbl_openehr_folder(ehr_id);
CREATE INDEX idx_openehr_folder_data ON tbl_openehr_folder USING GIN (data);

CREATE TABLE tbl_openehr_folder_item (
    folder_id TEXT NOT NULL REFERENCES tbl_openehr_folder(id) ON DELETE CASCADE,
    object_id TEXT NOT NULL
);

CREATE INDEX idx_openehr_folder_item_folder_id ON tbl_openehr_folder_item(folder_id);
CREATE INDEX idx_openehr_folder_item_object_id ON tbl_openehr_folder_item(object_id);

CREATE TABLE tbl_openehr_role (
    id TEXT PRIMARY KEY,
    versioned_object_id UUID NOT NULL REFERENCES tbl_openehr_versioned_object(id) ON DELETE CASCADE,
    system_id TEXT NOT NULL,
    version_tree_id TEXT NOT NULL,
    data JSONB NOT NULL,
    created_at TIMESTAMP NOT NULL
);

CREATE INDEX idx_openehr_role_versioned_object_id ON tbl_openehr_role(versioned_object_id);
CREATE INDEX idx_openehr_role_data ON tbl_openehr_role USING GIN (data);

CREATE TABLE tbl_openehr_person (
    id TEXT PRIMARY KEY,
    versioned_object_id UUID NOT NULL REFERENCES tbl_openehr_versioned_object(id) ON DELETE CASCADE,
    system_id TEXT NOT NULL,
    version_tree_id TEXT NOT NULL,
    data JSONB NOT NULL,
    created_at TIMESTAMP NOT NULL
);

CREATE INDEX idx_openehr_person_versioned_object_id ON tbl_openehr_person(versioned_object_id);
CREATE INDEX idx_openehr_person_data ON tbl_openehr_person USING GIN (data);

CREATE TABLE tbl_openehr_agent (
    id TEXT PRIMARY KEY,
    versioned_object_id UUID NOT NULL REFERENCES tbl_openehr_versioned_object(id) ON DELETE CASCADE,
    system_id TEXT NOT NULL,
    version_tree_id TEXT NOT NULL,
    data JSONB NOT NULL,
    created_at TIMESTAMP NOT NULL
);

CREATE INDEX idx_openehr_agent_versioned_object_id ON tbl_openehr_agent(versioned_object_id);
CREATE INDEX idx_openehr_agent_data ON tbl_openehr_agent USING GIN (data);

CREATE TABLE tbl_openehr_group (
    id TEXT PRIMARY KEY,
    versioned_object_id UUID NOT NULL REFERENCES tbl_openehr_versioned_object(id) ON DELETE CASCADE,
    system_id TEXT NOT NULL,
    version_tree_id TEXT NOT NULL,
    data JSONB NOT NULL,
    created_at TIMESTAMP NOT NULL
);

CREATE INDEX idx_openehr_group_versioned_object_id ON tbl_openehr_group(versioned_object_id);
CREATE INDEX idx_openehr_group_data ON tbl_openehr_group USING GIN (data);

CREATE TABLE tbl_openehr_organisation (
    id TEXT PRIMARY KEY,
    versioned_object_id UUID NOT NULL REFERENCES tbl_openehr_versioned_object(id) ON DELETE CASCADE,
    system_id TEXT NOT NULL,
    version_tree_id TEXT NOT NULL,
    data JSONB NOT NULL,
    created_at TIMESTAMP NOT NULL
);

CREATE INDEX idx_openehr_organisation_versioned_object_id ON tbl_openehr_organisation(versioned_object_id);
CREATE INDEX idx_openehr_organisation_data ON tbl_openehr_organisation USING GIN (data);