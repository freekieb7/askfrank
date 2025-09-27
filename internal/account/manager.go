package account

import (
	"context"
	"fmt"
	"hp/internal/audit"
	"hp/internal/database"
	"hp/internal/notifications"
	"hp/internal/stripe"
	"hp/internal/util"
	"hp/internal/webhook"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID               uuid.UUID
	Name             string
	Email            string
	SubscriptionPlan SubscriptionPlan
}

type SubscriptionPlan string

const (
	SubscriptionPlanFree SubscriptionPlan = "Free"
	SubscriptionPlanPro  SubscriptionPlan = "Pro"
)

func (p SubscriptionPlan) IsValid() bool {
	switch p {
	case SubscriptionPlanFree, SubscriptionPlanPro:
		return true
	default:
		return false
	}
}

func (p SubscriptionPlan) String() string {
	return string(p)
}

func ParseSubscriptionPlan(s string) (SubscriptionPlan, error) {
	plan := SubscriptionPlan(s)
	if !plan.IsValid() {
		return "", fmt.Errorf("invalid subscription plan: %s", s)
	}
	return plan, nil
}

var (
	PlanToPriceID = map[SubscriptionPlan]stripe.PriceID{
		SubscriptionPlanFree: stripe.PriceIDFreePlan,
		SubscriptionPlanPro:  stripe.PriceIDProPlan,
	}
	PriceIDToPlan = map[stripe.PriceID]SubscriptionPlan{
		stripe.PriceIDFreePlan: SubscriptionPlanFree,
		stripe.PriceIDProPlan:  SubscriptionPlanPro,
	}
)

type Manager struct {
	logger         *slog.Logger
	db             *database.Database
	auditor        *audit.Auditor
	webhookManager *webhook.Manager
	notifier       *notifications.Notifier
	stripeClient   *stripe.Client
}

func NewManager(logger *slog.Logger, db *database.Database, auditor *audit.Auditor, webhookManager *webhook.Manager, notifier *notifications.Notifier, stripeClient *stripe.Client) Manager {
	return Manager{logger: logger, db: db, auditor: auditor, webhookManager: webhookManager, notifier: notifier, stripeClient: stripeClient}
}

type RegisterParam struct {
	Name     string
	Email    string
	Password string
}

func (m *Manager) Register(ctx context.Context, param RegisterParam) (uuid.UUID, error) {
	var userID uuid.UUID

	// Check if user already exists
	_, err := m.db.GetUserByEmail(ctx, param.Email)
	if err == nil {
		// User already exists
		return userID, ErrEmailAlreadyInUse
	}
	if err != database.ErrUserNotFound {
		return userID, fmt.Errorf("failed to check if user exists: %w", err)
	}

	// Create Stripe customer and subscribe to free plan
	customer, err := m.stripeClient.CreateCustomer(ctx, stripe.CreateCustomerParams{
		Email: param.Email,
	})
	if err != nil {
		return userID, fmt.Errorf("failed to create Stripe customer: %w", err)
	}

	priceID, ok := PlanToPriceID[SubscriptionPlanFree]
	if !ok {
		return userID, fmt.Errorf("unknown price ID for free plan")
	}

	subscriptionID, err := m.stripeClient.AddSubscriptionToCustomer(ctx, customer.ID, priceID)
	if err != nil {
		return userID, fmt.Errorf("failed to create Stripe subscription for customer %s: %w", customer.ID, err)
	}

	// Create user in database
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(param.Password), bcrypt.DefaultCost)
	if err != nil {
		return userID, fmt.Errorf("failed to hash password: %w", err)
	}

	user, err := m.db.CreateUser(ctx, database.CreateUserParams{
		Name:                 param.Name,
		Email:                param.Email,
		PasswordHash:         string(passwordHash),
		IsEmailVerified:      false,
		IsBot:                false,
		StripeCustomerID:     customer.ID,
		StripeSubscriptionID: subscriptionID,
		StripeProductPriceID: string(priceID),
	})
	if err != nil {
		return userID, fmt.Errorf("failed to create user: %w", err)
	}

	// Successful registration
	userID = user.ID

	// Audit log
	if err := m.auditor.LogEvent(ctx, audit.LogEventParam{
		OwnerID: user.ID,
		Type:    audit.AuditLogEventTypeUserRegister,
		Data: map[string]any{
			"user_id": user.ID,
		},
	}); err != nil {
		return userID, fmt.Errorf("failed to log audit event: %w", err)
	}

	// Webhook event
	if err := m.webhookManager.RegisterEvent(ctx, webhook.RegisterEventParam{
		OwnerID: user.ID,
		Type:    webhook.EventTypeUserRegister,
		Data: map[string]any{
			"user_id":   user.ID,
			"timestamp": user.CreatedAt.Format(time.RFC3339),
		},
	}); err != nil {
		return userID, fmt.Errorf("failed to create webhook event: %w", err)
	}

	// Notification
	if err := m.notifier.Notify(ctx, notifications.NotifyParam{
		OwnerID: user.ID,
		Title:   "Signup Successful",
		Message: "Welcome! Your account has been created successfully.",
		Type:    notifications.NotificationTypeInfo,
	}); err != nil {
		return userID, fmt.Errorf("failed to create notification: %w", err)
	}

	return userID, nil
}

func (m *Manager) GetUserByID(ctx context.Context, userID uuid.UUID) (User, error) {
	var user User

	userDB, err := m.db.GetUserByID(ctx, userID)
	if err != nil {
		return user, fmt.Errorf("failed to get user by ID %s: %w", userID, err)
	}

	plan, ok := PriceIDToPlan[stripe.PriceID(userDB.StripeProductPriceID)]
	if !ok {
		return user, fmt.Errorf("unknown price ID %s for user %s", userDB.StripeProductPriceID, userDB.ID)
	}

	user.ID = userDB.ID
	user.Name = userDB.Name
	user.Email = userDB.Email
	user.SubscriptionPlan = plan
	return user, nil
}

type ChangeSubscriptionParam struct {
	UserID           uuid.UUID
	StripeCustomerID string
	NewPlan          SubscriptionPlan
}

func (m *Manager) ChangeSubscription(ctx context.Context, params ChangeSubscriptionParam) error {
	if params.UserID == uuid.Nil && params.StripeCustomerID == "" {
		return fmt.Errorf("either userID or stripeCustomerID must be provided")
	}

	priceID, ok := PlanToPriceID[params.NewPlan]
	if !ok {
		return fmt.Errorf("unknown plan: %s", params.NewPlan)
	}

	var (
		user database.User
		err  error
	)
	if params.StripeCustomerID != "" {
		user, err = m.db.GetUserByStripeCustomerID(ctx, params.StripeCustomerID)
		if err != nil {
			return fmt.Errorf("failed to get user by Stripe customer ID %s: %w", params.StripeCustomerID, err)
		}
	} else {
		user, err = m.db.GetUserByID(ctx, params.UserID)
		if err != nil {
			return fmt.Errorf("failed to get user %s: %w", params.UserID, err)
		}
	}

	if user.StripeProductPriceID == string(priceID) {
		// No change needed
		return nil
	}

	// Don't log here - external service errors should be logged at boundary
	if err := m.stripeClient.SwitchSubscriptionPlan(ctx, user.ID, priceID); err != nil {
		return fmt.Errorf("stripe subscription change failed for user %s to plan %s: %w",
			user.ID, params.NewPlan, err)
	}

	// Update user in database
	if err := m.db.UpdateUserByID(ctx, user.ID, database.UpdateUserParams{
		StripeProductPriceID: util.Some(string(priceID)),
	}); err != nil {
		return fmt.Errorf("failed to update Stripe price ID for user %s: %w", user.ID, err)
	}

	m.logger.Info("Successfully changed user subscription", "user_id", user.ID, "new_plan", params.NewPlan)

	// Audit log
	if err := m.auditor.LogEvent(ctx, audit.LogEventParam{
		OwnerID: user.ID,
		Type:    audit.AuditLogEventTypeSubscriptionChanged,
		Data: map[string]any{
			"user_id":  user.ID,
			"new_plan": params.NewPlan,
		},
	}); err != nil {
		return fmt.Errorf("failed to log audit event: %w", err)
	}

	// Webhook event
	if err := m.webhookManager.RegisterEvent(ctx, webhook.RegisterEventParam{
		OwnerID: user.ID,
		Type:    webhook.EventTypeSubscriptionChanged,
		Data: map[string]any{
			"user_id":  user.ID,
			"new_plan": params.NewPlan,
		},
	}); err != nil {
		return fmt.Errorf("failed to create webhook event: %w", err)
	}

	// Notification
	if err := m.notifier.Notify(ctx, notifications.NotifyParam{
		OwnerID: user.ID,
		Title:   "Subscription Updated",
		Message: fmt.Sprintf("Your subscription has been changed to the %s plan.", params.NewPlan),
		Type:    notifications.NotificationTypeInfo,
	}); err != nil {
		return fmt.Errorf("failed to create notification: %w", err)
	}

	return nil
}

type CreateCheckoutSessionParams struct {
	UserID     uuid.UUID
	Plan       SubscriptionPlan
	SuccessURL string
	CancelURL  string
}

func (m *Manager) CreateCheckoutSession(ctx context.Context, params CreateCheckoutSessionParams) (string, error) {
	priceID, ok := PlanToPriceID[params.Plan]
	if !ok {
		return "", fmt.Errorf("unknown plan: %s", params.Plan)
	}

	user, err := m.db.GetUserByID(ctx, params.UserID)
	if err != nil {
		return "", fmt.Errorf("failed to get user by ID: %w", err)
	}

	if user.StripeProductPriceID == string(priceID) {
		return "", fmt.Errorf("user %s is already on the requested plan", params.UserID)
	}

	sessionURL, err := m.stripeClient.CreateCheckoutSession(ctx, params.UserID, priceID, params.SuccessURL, params.CancelURL)
	if err != nil {
		return "", fmt.Errorf("failed to create checkout session: %w", err)
	}

	return sessionURL, nil
}

func (m *Manager) SyncUserSubscription(ctx context.Context, subscriptionID string) error {
	user, err := m.db.GetUserByStripeSubscriptionID(ctx, subscriptionID)
	if err != nil {
		return fmt.Errorf("failed to get user by subscription ID %s: %w", subscriptionID, err)
	}

	subscription, err := m.stripeClient.GetSubscriptionByCustomerID(ctx, user.StripeCustomerID)
	if err != nil {
		return fmt.Errorf("failed to get subscription for user %s: %w", user.ID, err)
	}

	if len(subscription.Items.Data) != 1 {
		return fmt.Errorf("unexpected number of subscription items for user %s: %d", user.ID, len(subscription.Items.Data))
	}
	priceID := string(stripe.PriceID(subscription.Items.Data[0].Price.ID))

	plan, ok := PriceIDToPlan[stripe.PriceID(priceID)]
	if !ok {
		return fmt.Errorf("unknown price ID %s for user %s", priceID, user.ID)
	}

	if err := m.ChangeSubscription(ctx, ChangeSubscriptionParam{
		UserID:  user.ID,
		NewPlan: plan,
	}); err != nil {
		return fmt.Errorf("failed to change subscription for user %s: %w", user.ID, err)
	}

	return nil
}
