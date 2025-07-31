-- Migration up
-- Create subscription plans table
CREATE TABLE IF NOT EXISTS tbl_subscription_plan (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL,
    description TEXT,
    stripe_price_id VARCHAR(100) NOT NULL UNIQUE,
    amount_cents INTEGER NOT NULL,
    currency VARCHAR(3) NOT NULL DEFAULT 'EUR',
    interval VARCHAR(20) NOT NULL DEFAULT 'month',
    features JSONB NOT NULL DEFAULT '[]',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create user subscriptions table
CREATE TABLE IF NOT EXISTS tbl_user_subscription (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES tbl_user(id) ON DELETE CASCADE,
    plan_id UUID NOT NULL REFERENCES tbl_subscription_plan(id),
    stripe_customer_id VARCHAR(100) NOT NULL,
    stripe_subscription_id VARCHAR(100) NOT NULL UNIQUE,
    status VARCHAR(50) NOT NULL,
    current_period_start TIMESTAMP WITH TIME ZONE NOT NULL,
    current_period_end TIMESTAMP WITH TIME ZONE NOT NULL,
    trial_end TIMESTAMP WITH TIME ZONE,
    canceled_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create subscription invoices table
CREATE TABLE IF NOT EXISTS tbl_subscription_invoice (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subscription_id UUID NOT NULL REFERENCES tbl_user_subscription(id) ON DELETE CASCADE,
    stripe_invoice_id VARCHAR(100) NOT NULL UNIQUE,
    amount_paid INTEGER NOT NULL,
    currency VARCHAR(3) NOT NULL,
    status VARCHAR(50) NOT NULL,
    invoice_pdf VARCHAR(500),
    hosted_invoice_url VARCHAR(500),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_user_subscription_user_id ON tbl_user_subscription(user_id);
CREATE INDEX IF NOT EXISTS idx_user_subscription_stripe_customer ON tbl_user_subscription(stripe_customer_id);
CREATE INDEX IF NOT EXISTS idx_subscription_invoice_subscription_id ON tbl_subscription_invoice(subscription_id);
CREATE INDEX IF NOT EXISTS idx_subscription_plan_active ON tbl_subscription_plan(is_active) WHERE is_active = true;

-- Insert default subscription plans
INSERT INTO tbl_subscription_plan (name, description, stripe_price_id, amount_cents, features) VALUES
('Basic Plan', 'Essential healthcare IT tools for small practices', 'price_basic_monthly_eur', 2900, '["Patient Management", "Basic Reports", "Email Support"]'),
('Professional Plan', 'Advanced features for growing practices', 'price_pro_monthly_eur', 5900, '["Patient Management", "Advanced Reports", "Appointment Scheduling", "Priority Support"]'),
('Enterprise Plan', 'Complete solution for large healthcare organizations', 'price_enterprise_monthly_eur', 9900, '["All Features", "Multi-location Support", "API Access", "Dedicated Support", "Custom Integrations"]');

