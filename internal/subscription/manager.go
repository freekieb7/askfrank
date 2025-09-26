package subscription

import (
	"context"
	"fmt"
	"hp/internal/stripe"
	"log/slog"

	"github.com/google/uuid"
)

type Plan int

const (
	PlanFree Plan = iota
	PlanPro
)

type Manager struct {
	logger       *slog.Logger
	stripeClient *stripe.Client
}

func NewManager(logger *slog.Logger, stripeClient *stripe.Client) Manager {
	return Manager{logger: logger, stripeClient: stripeClient}
}

func (m *Manager) ChangeSubscription(ctx context.Context, userID uuid.UUID, newPlan Plan) error {
	var priceID stripe.PriceID

	switch newPlan {
	case PlanFree:
		priceID = stripe.PriceIDFreePlan
	case PlanPro:
		priceID = stripe.PriceIDProPlan
	default:
		return fmt.Errorf("unknown plan: %d", newPlan)
	}

	// Don't log here - external service errors should be logged at boundary
	if err := m.stripeClient.SwitchSubscriptionPlan(ctx, userID, priceID); err != nil {
		return fmt.Errorf("stripe subscription change failed for user %s to plan %d: %w",
			userID, newPlan, err)
	}

	return nil
}
