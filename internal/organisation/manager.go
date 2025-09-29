package organisation

import (
	"context"
	"fmt"
	"hp/internal/audit"
	"hp/internal/database"
	"hp/internal/stripe"
	"hp/internal/util"
	"log/slog"

	"github.com/google/uuid"
)

type Manager struct {
	db      *database.Database
	logger  *slog.Logger
	stripe  *stripe.Client
	auditor *audit.Auditor
}

func NewManager(db *database.Database, logger *slog.Logger) Manager {
	return Manager{
		db:     db,
		logger: logger,
	}
}

type Organisation struct {
	ID   uuid.UUID
	Name string
}

func (m *Manager) GetOrganisation(ctx context.Context, id uuid.UUID) (Organisation, error) {
	var org Organisation
	dbOrg, err := m.db.GetOrganisationByID(ctx, id)
	if err != nil {
		return org, err
	}

	org = Organisation{
		ID:   dbOrg.ID,
		Name: dbOrg.Name,
	}

	return org, nil
}

type ChangeSubscriptionParam struct {
	OrganisationID   uuid.UUID
	StripeCustomerID string
	NewPlan          SubscriptionPlan
}

func (m *Manager) ChangeSubscription(ctx context.Context, params ChangeSubscriptionParam) error {
	if params.OrganisationID == uuid.Nil && params.StripeCustomerID == "" {
		return fmt.Errorf("either organisationID or stripeCustomerID must be provided")
	}

	priceID, ok := PlanToPriceID[params.NewPlan]
	if !ok {
		return fmt.Errorf("unknown plan: %s", params.NewPlan)
	}

	var (
		org database.Organisation
		err error
	)
	if params.StripeCustomerID != "" {
		org, err = m.db.GetOrganisationByStripeCustomerID(ctx, params.StripeCustomerID)
		if err != nil {
			return fmt.Errorf("failed to get organisation by Stripe customer ID %s: %w", params.StripeCustomerID, err)
		}
	} else {
		org, err = m.db.GetOrganisationByID(ctx, params.OrganisationID)
		if err != nil {
			return fmt.Errorf("failed to get organisation %s: %w", params.OrganisationID, err)
		}
	}

	if org.StripeProductPriceID == string(priceID) {
		// No change needed
		return nil
	}

	// Don't log here - external service errors should be logged at boundary
	if err := m.stripe.SwitchSubscriptionPlan(ctx, org.ID, priceID); err != nil {
		return fmt.Errorf("stripe subscription change failed for organisation %s to plan %s: %w",
			org.ID, params.NewPlan, err)
	}

	// Update organisation in database
	if err := m.db.UpdateOrganisationByID(ctx, org.ID, database.UpdateOrganisationParams{
		StripeProductPriceID: util.Some(string(priceID)),
	}); err != nil {
		return fmt.Errorf("failed to update Stripe price ID for organisation %s: %w", org.ID, err)
	}

	m.logger.Info("Successfully changed organisation subscription", "organisation_id", org.ID, "new_plan", params.NewPlan)

	// Audit log
	if err := m.auditor.LogEvent(ctx, audit.LogEventParam{
		OwnerID: org.ID,
		Type:    audit.AuditLogEventTypeSubscriptionChanged,
		Data: map[string]any{
			"organisation_id": org.ID,
			"new_plan":        params.NewPlan,
		},
	}); err != nil {
		return fmt.Errorf("failed to log audit event: %w", err)
	}

	// // Webhook event
	// if err := m.webhookManager.RegisterEvent(ctx, webhook.RegisterEventParam{
	// 	OwnerID: user.ID,
	// 	Type:    webhook.EventTypeSubscriptionChanged,
	// 	Data: map[string]any{
	// 		"user_id":  user.ID,
	// 		"new_plan": params.NewPlan,
	// 	},
	// }); err != nil {
	// 	return fmt.Errorf("failed to create webhook event: %w", err)
	// }

	// // Notification
	// if err := m.notifier.Notify(ctx, notifications.NotifyParam{
	// 	OwnerID: user.ID,
	// 	Title:   "Subscription Updated",
	// 	Message: fmt.Sprintf("Your subscription has been changed to the %s plan.", params.NewPlan),
	// 	Type:    notifications.NotificationTypeInfo,
	// }); err != nil {
	// 	return fmt.Errorf("failed to create notification: %w", err)
	// }

	return nil
}

type CreateCheckoutSessionParams struct {
	OrganisationID uuid.UUID
	Plan           SubscriptionPlan
	SuccessURL     string
	CancelURL      string
}

func (m *Manager) CreateCheckoutSession(ctx context.Context, params CreateCheckoutSessionParams) (string, error) {
	priceID, ok := PlanToPriceID[params.Plan]
	if !ok {
		return "", fmt.Errorf("unknown plan: %s", params.Plan)
	}

	org, err := m.db.GetOrganisationByID(ctx, params.OrganisationID)
	if err != nil {
		return "", fmt.Errorf("failed to get organisation by ID: %w", err)
	}

	if org.StripeProductPriceID == string(priceID) {
		return "", fmt.Errorf("organisation %s is already on the requested plan", params.OrganisationID)
	}

	sessionURL, err := m.stripe.CreateCheckoutSession(ctx, params.OrganisationID, priceID, params.SuccessURL, params.CancelURL)
	if err != nil {
		return "", fmt.Errorf("failed to create checkout session: %w", err)
	}

	return sessionURL, nil
}

func (m *Manager) SyncOrganisationSubscription(ctx context.Context, subscriptionID string) error {
	org, err := m.db.GetOrganisationByStripeSubscriptionID(ctx, subscriptionID)
	if err != nil {
		return fmt.Errorf("failed to get organisation by subscription ID %s: %w", subscriptionID, err)
	}

	subscription, err := m.stripe.GetSubscriptionByCustomerID(ctx, org.StripeCustomerID)
	if err != nil {
		return fmt.Errorf("failed to get subscription for organisation %s: %w", org.ID, err)
	}

	if len(subscription.Items.Data) != 1 {
		return fmt.Errorf("unexpected number of subscription items for organisation %s: %d", org.ID, len(subscription.Items.Data))
	}
	priceID := string(stripe.PriceID(subscription.Items.Data[0].Price.ID))

	plan, ok := PriceIDToPlan[stripe.PriceID(priceID)]
	if !ok {
		return fmt.Errorf("unknown price ID %s for organisation %s", priceID, org.ID)
	}

	if err := m.ChangeSubscription(ctx, ChangeSubscriptionParam{
		OrganisationID: org.ID,
		NewPlan:        plan,
	}); err != nil {
		return fmt.Errorf("failed to change subscription for organisation %s: %w", org.ID, err)
	}

	return nil
}
