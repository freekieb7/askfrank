package service

import (
	"askfrank/internal/config"
	"askfrank/internal/model"
	"askfrank/internal/repository"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/stripe/stripe-go/v76"
	"github.com/stripe/stripe-go/v76/checkout/session"
	"github.com/stripe/stripe-go/v76/customer"
	"github.com/stripe/stripe-go/v76/invoiceitem"
	"github.com/stripe/stripe-go/v76/subscription"
	"github.com/stripe/stripe-go/v76/webhook"
)

type SubscriptionService struct {
	repo   repository.Repository
	config config.StripeConfig
	logger *slog.Logger
}

func NewSubscriptionService(repo repository.Repository, cfg config.StripeConfig, logger *slog.Logger) *SubscriptionService {
	stripe.Key = cfg.SecretKey

	return &SubscriptionService{
		repo:   repo,
		config: cfg,
		logger: logger,
	}
}

func (s *SubscriptionService) CreateCheckoutSession(ctx context.Context, userID uuid.UUID, planID uuid.UUID, successURL, cancelURL string) (*stripe.CheckoutSession, error) {
	// Get user and plan
	user, err := s.repo.GetUserByID(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	plan, err := s.repo.GetSubscriptionPlanByID(ctx, planID)
	if err != nil {
		return nil, fmt.Errorf("failed to get plan: %w", err)
	}

	// Create or get Stripe customer
	customerID, err := s.getOrCreateStripeCustomer(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("failed to create customer: %w", err)
	}

	// Create checkout session
	params := &stripe.CheckoutSessionParams{
		Customer:   stripe.String(customerID),
		SuccessURL: stripe.String(successURL),
		CancelURL:  stripe.String(cancelURL),
		Mode:       stripe.String(string(stripe.CheckoutSessionModeSubscription)),
		LineItems: []*stripe.CheckoutSessionLineItemParams{
			{
				Price:    stripe.String(plan.StripePriceID),
				Quantity: stripe.Int64(1),
			},
		},
		Metadata: map[string]string{
			"user_id": userID.String(),
			"plan_id": planID.String(),
		},
		SubscriptionData: &stripe.CheckoutSessionSubscriptionDataParams{
			TrialPeriodDays: stripe.Int64(14), // 14-day trial
			Metadata: map[string]string{
				"user_id": userID.String(),
				"plan_id": planID.String(),
			},
		},
	}

	session, err := session.New(params)
	if err != nil {
		s.logger.ErrorContext(ctx, "Failed to create checkout session", "error", err, "user_id", userID)
		return nil, fmt.Errorf("failed to create checkout session: %w", err)
	}

	s.logger.InfoContext(ctx, "Created checkout session", "session_id", session.ID, "user_id", userID, "plan_id", planID)
	return session, nil
}

func (s *SubscriptionService) HandleWebhook(ctx context.Context, payload []byte, signature string) error {
	event, err := webhook.ConstructEvent(payload, signature, s.config.WebhookSecret)
	if err != nil {
		return fmt.Errorf("webhook signature verification failed: %w", err)
	}

	switch event.Type {
	case "checkout.session.completed":
		return s.handleCheckoutCompleted(ctx, event)
	case "invoice.payment_succeeded":
		return s.handlePaymentSucceeded(ctx, event)
	case "invoice.payment_failed":
		return s.handlePaymentFailed(ctx, event)
	case "customer.subscription.updated":
		return s.handleSubscriptionUpdated(ctx, event)
	case "customer.subscription.deleted":
		return s.handleSubscriptionDeleted(ctx, event)
	default:
		s.logger.InfoContext(ctx, "Unhandled webhook event", "type", event.Type)
		return nil
	}
}

func (s *SubscriptionService) getOrCreateStripeCustomer(ctx context.Context, user model.User) (string, error) {
	// Check if user already has a Stripe customer ID
	subscription, err := s.repo.GetActiveSubscriptionByUserID(ctx, user.ID)
	if err == nil && subscription.StripeCustomerID != "" {
		return subscription.StripeCustomerID, nil
	}

	// Create new Stripe customer
	params := &stripe.CustomerParams{
		Email: stripe.String(user.Email),
		Name:  stripe.String(user.Name),
		Metadata: map[string]string{
			"user_id": user.ID.String(),
		},
	}

	customer, err := customer.New(params)
	if err != nil {
		return "", fmt.Errorf("failed to create Stripe customer: %w", err)
	}

	return customer.ID, nil
}

func (s *SubscriptionService) handleCheckoutCompleted(ctx context.Context, event stripe.Event) error {
	var session stripe.CheckoutSession
	if err := json.Unmarshal(event.Data.Raw, &session); err != nil {
		return fmt.Errorf("failed to parse checkout session: %w", err)
	}

	userID, err := uuid.Parse(session.Metadata["user_id"])
	if err != nil {
		return fmt.Errorf("invalid user_id in metadata: %w", err)
	}

	planID, err := uuid.Parse(session.Metadata["plan_id"])
	if err != nil {
		return fmt.Errorf("invalid plan_id in metadata: %w", err)
	}

	// Get subscription details from Stripe
	stripeSubscription, err := subscription.Get(session.Subscription.ID, nil)
	if err != nil {
		return fmt.Errorf("failed to get subscription from Stripe: %w", err)
	}

	// Create subscription record
	subscription := model.UserSubscription{
		ID:                   uuid.New(),
		UserID:               userID,
		PlanID:               planID,
		StripeCustomerID:     session.Customer.ID,
		StripeSubscriptionID: stripeSubscription.ID,
		Status:               string(stripeSubscription.Status),
		CurrentPeriodStart:   time.Unix(stripeSubscription.CurrentPeriodStart, 0),
		CurrentPeriodEnd:     time.Unix(stripeSubscription.CurrentPeriodEnd, 0),
		CreatedAt:            time.Now(),
		UpdatedAt:            time.Now(),
	}

	if stripeSubscription.TrialEnd > 0 {
		trialEnd := time.Unix(stripeSubscription.TrialEnd, 0)
		subscription.TrialEnd = &trialEnd
	}

	err = s.repo.CreateUserSubscription(ctx, subscription)
	if err != nil {
		return fmt.Errorf("failed to create subscription: %w", err)
	}

	s.logger.InfoContext(ctx, "Subscription created", "user_id", userID, "subscription_id", subscription.ID)
	return nil
}

func (s *SubscriptionService) handlePaymentSucceeded(ctx context.Context, event stripe.Event) error {
	// Handle successful payment - could trigger usage processing here
	s.logger.InfoContext(ctx, "Payment succeeded", "event_id", event.ID)
	return nil
}

func (s *SubscriptionService) handlePaymentFailed(ctx context.Context, event stripe.Event) error {
	// Handle failed payment - might need to restrict usage
	s.logger.WarnContext(ctx, "Payment failed", "event_id", event.ID)
	return nil
}

func (s *SubscriptionService) handleSubscriptionUpdated(ctx context.Context, event stripe.Event) error {
	// Handle subscription updates
	s.logger.InfoContext(ctx, "Subscription updated", "event_id", event.ID)
	return nil
}

func (s *SubscriptionService) handleSubscriptionDeleted(ctx context.Context, event stripe.Event) error {
	// Handle subscription deletion
	s.logger.InfoContext(ctx, "Subscription deleted", "event_id", event.ID)
	return nil
}

func (s *SubscriptionService) CancelSubscription(ctx context.Context, userID uuid.UUID) error {
	userSubscription, err := s.repo.GetActiveSubscriptionByUserID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get subscription: %w", err)
	}

	// Cancel in Stripe
	params := &stripe.SubscriptionParams{
		CancelAtPeriodEnd: stripe.Bool(true),
	}

	_, err = subscription.Update(userSubscription.StripeSubscriptionID, params)
	if err != nil {
		return fmt.Errorf("failed to cancel subscription in Stripe: %w", err)
	}

	// Update local record
	now := time.Now()
	userSubscription.CanceledAt = &now
	userSubscription.UpdatedAt = now

	err = s.repo.UpdateUserSubscription(ctx, userSubscription)
	if err != nil {
		return fmt.Errorf("failed to update subscription: %w", err)
	}

	s.logger.InfoContext(ctx, "Subscription canceled", "user_id", userID, "subscription_id", userSubscription.ID)
	return nil
}

// CreateUsageCharge creates a one-time charge for usage overages
func (s *SubscriptionService) CreateUsageCharge(ctx context.Context, userID uuid.UUID, amountCents int, description string) error {
	// Get user's subscription for Stripe customer ID
	subscription, err := s.repo.GetActiveSubscriptionByUserID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get subscription: %w", err)
	}

	// Create invoice item in Stripe
	params := &stripe.InvoiceItemParams{
		Customer:    stripe.String(subscription.StripeCustomerID),
		Amount:      stripe.Int64(int64(amountCents)),
		Currency:    stripe.String("usd"),
		Description: stripe.String(description),
		Metadata: map[string]string{
			"user_id":     userID.String(),
			"charge_type": "usage_overage",
		},
	}

	item, err := invoiceitem.New(params)
	if err != nil {
		s.logger.ErrorContext(ctx, "Failed to create usage charge", "error", err, "user_id", userID, "amount", amountCents)
		return fmt.Errorf("failed to create usage charge: %w", err)
	}

	s.logger.InfoContext(ctx, "Created usage charge",
		"user_id", userID,
		"amount_cents", amountCents,
		"description", description,
		"stripe_item_id", item.ID)

	return nil
}

// GetPlanLimits returns the usage limits for a user's current plan
func (s *SubscriptionService) GetPlanLimits(ctx context.Context, userID uuid.UUID) (model.PlanLimits, error) {
	subscription, err := s.repo.GetActiveSubscriptionByUserID(ctx, userID)
	if err != nil {
		return model.PlanLimits{}, fmt.Errorf("failed to get subscription: %w", err)
	}

	return s.repo.GetPlanLimits(ctx, subscription.PlanID)
}
