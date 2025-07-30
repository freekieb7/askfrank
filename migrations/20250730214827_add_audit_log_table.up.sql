-- Create audit log table
CREATE TABLE IF NOT EXISTS tbl_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES tbl_user(id) ON DELETE SET NULL,
    entity_type VARCHAR(50) NOT NULL, -- 'user', 'document', 'folder', 'session'
    entity_id UUID NOT NULL,
    action VARCHAR(20) NOT NULL, -- 'create', 'read', 'update', 'delete', 'login', 'logout'
    old_values JSONB,
    new_values JSONB,
    ip_address INET,
    user_agent TEXT,
    session_id VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON tbl_audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_entity ON tbl_audit_log(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON tbl_audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON tbl_audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_log_session_id ON tbl_audit_log(session_id);
