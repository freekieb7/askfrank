-- Migration: add users (UP)
-- Created: 2025-08-02 21:13:05
-- Version: 20250802211305

CREATE TABLE tbl_user (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash bytea NOT NULL,
    is_email_verified BOOLEAN NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
    -- stripe_customer_id TEXT NOT NULL,           
    -- stripe_subscription_id TEXT NOT NULL,       -- Stripe subscription ID
    -- stripe_subscription_status TEXT NOT NULL,    -- Stripe subscription status (e.g., active, past_due, canceled)
    -- stripe_subscription_created_at TIMESTAMP NOT NULL,  -- Stripe subscription creation date
    -- stripe_current_period_start TIMESTAMP NOT NULL,     -- Stripe current period start (e.g., subscription start date)
    -- stripe_current_period_end TIMESTAMP NOT NULL,       -- Stripe current period end (e.g., subscription renewal date)
    -- stripe_price_id TEXT NOT NULL,              -- Stripe price ID (e.g., plan ID)
    -- stripe_cancel_at TIMESTAMP,                         -- Timestamp when the subscription will be canceled
    -- stripe_cancel_at_period_end BOOLEAN                 -- If the user wants to cancel their subscription immediately
);

CREATE INDEX idx_user_email ON tbl_user (email);