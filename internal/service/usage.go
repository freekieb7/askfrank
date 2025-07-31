package service

import (
	"askfrank/internal/model"
	"askfrank/internal/repository"
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/stripe/stripe-go/v76"
	"github.com/stripe/stripe-go/v76/invoiceitem"
)

type UsageService struct {
	repo   repository.Repository
	logger *slog.Logger
}

func NewUsageService(repo repository.Repository, logger *slog.Logger) *UsageService {
	return &UsageService{
		repo:   repo,
		logger: logger,
	}
}

// TrackReportGeneration records usage when a user generates a report
func (s *UsageService) TrackReportGeneration(ctx context.Context, userID uuid.UUID, reportType string) error {
	return s.trackUsage(ctx, userID, model.UsageTypeReports, 1, model.ReportOveragePrice,
		fmt.Sprintf("Generated %s report", reportType))
}

// TrackStorageUsage records storage usage in MB
func (s *UsageService) TrackStorageUsage(ctx context.Context, userID uuid.UUID, sizeInMB int, description string) error {
	return s.trackUsage(ctx, userID, model.UsageTypeStorage, sizeInMB, model.StorageOveragePrice,
		fmt.Sprintf("Storage usage: %s", description))
}

// TrackAPICall records API call usage
func (s *UsageService) TrackAPICall(ctx context.Context, userID uuid.UUID, endpoint string) error {
	return s.trackUsage(ctx, userID, model.UsageTypeAPICalls, 1, model.APICallOveragePrice,
		fmt.Sprintf("API call: %s", endpoint))
}

// TrackUserAddition records when additional users are added
func (s *UsageService) TrackUserAddition(ctx context.Context, userID uuid.UUID, addedUserEmail string) error {
	return s.trackUsage(ctx, userID, model.UsageTypeUsers, 1, model.UserOveragePrice,
		fmt.Sprintf("Added user: %s", addedUserEmail))
}

// CheckUsageLimits validates if a user can perform an action based on their limits
func (s *UsageService) CheckUsageLimits(ctx context.Context, userID uuid.UUID, usageType string) (bool, error) {
	// Get user's subscription
	subscription, err := s.repo.GetActiveSubscriptionByUserID(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("failed to get subscription: %w", err)
	}

	// Get plan limits
	limits, err := s.repo.GetPlanLimits(ctx, subscription.PlanID)
	if err != nil {
		return false, fmt.Errorf("failed to get plan limits: %w", err)
	}

	// Get current usage
	now := time.Now()
	summary, err := s.repo.GetUsageSummary(ctx, userID, now)
	if err != nil {
		return false, fmt.Errorf("failed to get usage summary: %w", err)
	}

	// Check limits based on usage type
	switch usageType {
	case model.UsageTypeReports:
		return summary.ReportsUsed < limits.ReportsPerMonth, nil
	case model.UsageTypeStorage:
		return summary.StorageUsedGB < float64(limits.StorageGB), nil
	case model.UsageTypeAPICalls:
		return summary.APICallsUsed < limits.APICallsPerMonth, nil
	case model.UsageTypeUsers:
		// This would need to check actual user count vs limits.UsersIncluded
		return true, nil // Simplified for now
	default:
		return false, fmt.Errorf("unknown usage type: %s", usageType)
	}
}

// GetUsageSummary returns usage summary for a user for the current billing period
func (s *UsageService) GetUsageSummary(ctx context.Context, userID uuid.UUID) (model.UsageSummary, error) {
	now := time.Now()
	return s.repo.GetUsageSummary(ctx, userID, now)
}

// ProcessMonthlyOverages creates invoices for usage overages
func (s *UsageService) ProcessMonthlyOverages(ctx context.Context, userID uuid.UUID) error {
	// Get last month's usage
	lastMonth := time.Now().AddDate(0, -1, 0)
	summary, err := s.repo.GetUsageSummary(ctx, userID, lastMonth)
	if err != nil {
		return fmt.Errorf("failed to get usage summary: %w", err)
	}

	// If no overages, nothing to charge
	if summary.OverageCharges == 0 {
		s.logger.InfoContext(ctx, "No overages to charge", "user_id", userID, "period", lastMonth.Format("2006-01"))
		return nil
	}

	// Get user's subscription for Stripe customer ID
	subscription, err := s.repo.GetActiveSubscriptionByUserID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get subscription: %w", err)
	}

	// Create line items for each overage type
	if summary.ReportsOverage > 0 {
		err = s.createStripeInvoiceItem(ctx, subscription.StripeCustomerID,
			summary.ReportsOverage*model.ReportOveragePrice,
			fmt.Sprintf("Report overage for %s (%d extra reports)", lastMonth.Format("January 2006"), summary.ReportsOverage))
		if err != nil {
			return fmt.Errorf("failed to create report overage invoice item: %w", err)
		}
	}

	if summary.StorageOverageGB > 0 {
		err = s.createStripeInvoiceItem(ctx, subscription.StripeCustomerID,
			int(summary.StorageOverageGB*float64(model.StorageOveragePrice)),
			fmt.Sprintf("Storage overage for %s (%.2f GB extra)", lastMonth.Format("January 2006"), summary.StorageOverageGB))
		if err != nil {
			return fmt.Errorf("failed to create storage overage invoice item: %w", err)
		}
	}

	if summary.APICallsOverage > 0 {
		err = s.createStripeInvoiceItem(ctx, subscription.StripeCustomerID,
			(summary.APICallsOverage/1000)*model.APICallOveragePrice,
			fmt.Sprintf("API calls overage for %s (%d extra calls)", lastMonth.Format("January 2006"), summary.APICallsOverage))
		if err != nil {
			return fmt.Errorf("failed to create API overage invoice item: %w", err)
		}
	}

	// Mark usage as charged
	unchargedUsage, err := s.repo.GetUnchargedUsage(ctx, userID, lastMonth)
	if err != nil {
		return fmt.Errorf("failed to get uncharged usage: %w", err)
	}

	usageIDs := make([]uuid.UUID, len(unchargedUsage))
	for i, usage := range unchargedUsage {
		usageIDs[i] = usage.ID
	}

	err = s.repo.MarkUsageAsCharged(ctx, usageIDs)
	if err != nil {
		return fmt.Errorf("failed to mark usage as charged: %w", err)
	}

	s.logger.InfoContext(ctx, "Processed monthly overages",
		"user_id", userID,
		"period", lastMonth.Format("2006-01"),
		"total_charges_cents", summary.OverageCharges,
		"reports_overage", summary.ReportsOverage,
		"storage_overage_gb", summary.StorageOverageGB,
		"api_calls_overage", summary.APICallsOverage)

	return nil
}

// trackUsage is a helper method to record usage
func (s *UsageService) trackUsage(ctx context.Context, userID uuid.UUID, usageType string, quantity int, unitPrice int, description string) error {
	// Get user's subscription
	subscription, err := s.repo.GetActiveSubscriptionByUserID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get subscription: %w", err)
	}

	// Create usage record
	record := model.UsageRecord{
		ID:             uuid.New(),
		UserID:         userID,
		SubscriptionID: subscription.ID,
		UsageType:      usageType,
		Quantity:       quantity,
		UnitPrice:      unitPrice,
		Description:    description,
		BillingPeriod:  time.Now().Truncate(24 * time.Hour), // Start of current day
		IsCharged:      false,
		CreatedAt:      time.Now(),
	}

	err = s.repo.CreateUsageRecord(ctx, record)
	if err != nil {
		return fmt.Errorf("failed to create usage record: %w", err)
	}

	s.logger.InfoContext(ctx, "Usage tracked",
		"user_id", userID,
		"usage_type", usageType,
		"quantity", quantity,
		"description", description)

	return nil
}

// createStripeInvoiceItem creates a one-time charge in Stripe
func (s *UsageService) createStripeInvoiceItem(ctx context.Context, customerID string, amountCents int, description string) error {
	params := &stripe.InvoiceItemParams{
		Customer:    stripe.String(customerID),
		Amount:      stripe.Int64(int64(amountCents)),
		Currency:    stripe.String("usd"),
		Description: stripe.String(description),
	}

	_, err := invoiceitem.New(params)
	if err != nil {
		return fmt.Errorf("failed to create Stripe invoice item: %w", err)
	}

	return nil
}
