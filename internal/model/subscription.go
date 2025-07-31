package model

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type SubscriptionPlan struct {
	ID            uuid.UUID       `json:"id" db:"id"`
	Name          string          `json:"name" db:"name"`
	Description   string          `json:"description" db:"description"`
	StripePriceID string          `json:"stripe_price_id" db:"stripe_price_id"`
	AmountCents   int             `json:"amount_cents" db:"amount_cents"`
	Currency      string          `json:"currency" db:"currency"`
	Interval      string          `json:"interval" db:"interval"`
	Features      json.RawMessage `json:"features" db:"features"`
	IsActive      bool            `json:"is_active" db:"is_active"`
	CreatedAt     time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at" db:"updated_at"`
}

type UserSubscription struct {
	ID                   uuid.UUID         `json:"id" db:"id"`
	UserID               uuid.UUID         `json:"user_id" db:"user_id"`
	PlanID               uuid.UUID         `json:"plan_id" db:"plan_id"`
	StripeCustomerID     string            `json:"stripe_customer_id" db:"stripe_customer_id"`
	StripeSubscriptionID string            `json:"stripe_subscription_id" db:"stripe_subscription_id"`
	Status               string            `json:"status" db:"status"`
	CurrentPeriodStart   time.Time         `json:"current_period_start" db:"current_period_start"`
	CurrentPeriodEnd     time.Time         `json:"current_period_end" db:"current_period_end"`
	TrialEnd             *time.Time        `json:"trial_end,omitempty" db:"trial_end"`
	CanceledAt           *time.Time        `json:"canceled_at,omitempty" db:"canceled_at"`
	CreatedAt            time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt            time.Time         `json:"updated_at" db:"updated_at"`
	Plan                 *SubscriptionPlan `json:"plan,omitempty"`
}

type SubscriptionInvoice struct {
	ID               uuid.UUID `json:"id" db:"id"`
	SubscriptionID   uuid.UUID `json:"subscription_id" db:"subscription_id"`
	StripeInvoiceID  string    `json:"stripe_invoice_id" db:"stripe_invoice_id"`
	AmountPaid       int       `json:"amount_paid" db:"amount_paid"`
	Currency         string    `json:"currency" db:"currency"`
	Status           string    `json:"status" db:"status"`
	InvoicePDF       string    `json:"invoice_pdf" db:"invoice_pdf"`
	HostedInvoiceURL string    `json:"hosted_invoice_url" db:"hosted_invoice_url"`
	CreatedAt        time.Time `json:"created_at" db:"created_at"`
}

// Usage tracking models
type UsageRecord struct {
	ID             uuid.UUID `json:"id" db:"id"`
	UserID         uuid.UUID `json:"user_id" db:"user_id"`
	SubscriptionID uuid.UUID `json:"subscription_id" db:"subscription_id"`
	UsageType      string    `json:"usage_type" db:"usage_type"` // "reports", "storage", "api_calls", etc.
	Quantity       int       `json:"quantity" db:"quantity"`
	UnitPrice      int       `json:"unit_price" db:"unit_price"` // In cents
	Description    string    `json:"description" db:"description"`
	BillingPeriod  time.Time `json:"billing_period" db:"billing_period"` // Month/period this usage belongs to
	IsCharged      bool      `json:"is_charged" db:"is_charged"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
}

type PlanLimits struct {
	ID               uuid.UUID `json:"id" db:"id"`
	PlanID           uuid.UUID `json:"plan_id" db:"plan_id"`
	ReportsPerMonth  int       `json:"reports_per_month" db:"reports_per_month"`
	StorageGB        int       `json:"storage_gb" db:"storage_gb"`
	APICallsPerMonth int       `json:"api_calls_per_month" db:"api_calls_per_month"`
	UsersIncluded    int       `json:"users_included" db:"users_included"`
	CreatedAt        time.Time `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time `json:"updated_at" db:"updated_at"`
}

type UsageSummary struct {
	UserID           uuid.UUID `json:"user_id"`
	BillingPeriod    time.Time `json:"billing_period"`
	ReportsUsed      int       `json:"reports_used"`
	StorageUsedGB    float64   `json:"storage_used_gb"`
	APICallsUsed     int       `json:"api_calls_used"`
	ReportsOverage   int       `json:"reports_overage"`
	StorageOverageGB float64   `json:"storage_overage_gb"`
	APICallsOverage  int       `json:"api_calls_overage"`
	OverageCharges   int       `json:"overage_charges"` // In cents
}

// Usage types constants
const (
	UsageTypeReports  = "reports"
	UsageTypeStorage  = "storage"
	UsageTypeAPICalls = "api_calls"
	UsageTypeUsers    = "users"
)

// Pricing constants (in cents)
const (
	ReportOveragePrice  = 200  // $2.00 per extra report
	StorageOveragePrice = 50   // $0.50 per GB over limit
	APICallOveragePrice = 1    // $0.01 per 1000 API calls over limit
	UserOveragePrice    = 1000 // $10.00 per extra user
)

type SubscriptionStatus string

const (
	SubscriptionStatusActive     SubscriptionStatus = "active"
	SubscriptionStatusPastDue    SubscriptionStatus = "past_due"
	SubscriptionStatusCanceled   SubscriptionStatus = "canceled"
	SubscriptionStatusIncomplete SubscriptionStatus = "incomplete"
	SubscriptionStatusTrialing   SubscriptionStatus = "trialing"
)
