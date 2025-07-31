-- Add usage tracking tables for metered billing

-- Plan limits table
CREATE TABLE IF NOT EXISTS tbl_plan_limits (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    plan_id UUID NOT NULL REFERENCES tbl_subscription_plan(id) ON DELETE CASCADE,
    reports_per_month INTEGER NOT NULL DEFAULT 0,
    storage_gb INTEGER NOT NULL DEFAULT 0,
    api_calls_per_month INTEGER NOT NULL DEFAULT 0,
    users_included INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(plan_id)
);

-- Usage records table for tracking actual usage
CREATE TABLE IF NOT EXISTS tbl_usage_record (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES tbl_user(id) ON DELETE CASCADE,
    subscription_id UUID NOT NULL REFERENCES tbl_user_subscription(id) ON DELETE CASCADE,
    usage_type VARCHAR(50) NOT NULL, -- 'reports', 'storage', 'api_calls', 'users'
    quantity INTEGER NOT NULL DEFAULT 0,
    unit_price INTEGER NOT NULL DEFAULT 0, -- in cents
    description TEXT,
    billing_period TIMESTAMP WITH TIME ZONE NOT NULL, -- month/period this usage belongs to
    is_charged BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_plan_limits_plan_id ON tbl_plan_limits(plan_id);
CREATE INDEX IF NOT EXISTS idx_usage_record_user_id ON tbl_usage_record(user_id);
CREATE INDEX IF NOT EXISTS idx_usage_record_subscription_id ON tbl_usage_record(subscription_id);
CREATE INDEX IF NOT EXISTS idx_usage_record_billing_period ON tbl_usage_record(billing_period);
CREATE INDEX IF NOT EXISTS idx_usage_record_usage_type ON tbl_usage_record(usage_type);
CREATE INDEX IF NOT EXISTS idx_usage_record_is_charged ON tbl_usage_record(is_charged);

-- Insert default limits for existing plans
INSERT INTO tbl_plan_limits (plan_id, reports_per_month, storage_gb, api_calls_per_month, users_included)
SELECT 
    id,
    CASE 
        WHEN name = 'Basic' THEN 10
        WHEN name = 'Pro' THEN 100
        ELSE 10
    END as reports_per_month,
    CASE 
        WHEN name = 'Basic' THEN 5
        WHEN name = 'Pro' THEN 50
        ELSE 5
    END as storage_gb,
    CASE 
        WHEN name = 'Basic' THEN 10000
        WHEN name = 'Pro' THEN 100000
        ELSE 10000
    END as api_calls_per_month,
    CASE 
        WHEN name = 'Basic' THEN 1
        WHEN name = 'Pro' THEN 5
        ELSE 1
    END as users_included
FROM tbl_subscription_plan
ON CONFLICT (plan_id) DO NOTHING;
