package stripe

import (
	"context"
	"fmt"
	"hp/internal/database"
	"log/slog"

	"github.com/google/uuid"
	"github.com/stripe/stripe-go/v82"
	stripeCustomer "github.com/stripe/stripe-go/v82/customer"
	stripeSubscription "github.com/stripe/stripe-go/v82/subscription"
)

type PriceID string

const (
	PriceIDFreePlan PriceID = "price_1S9R9r00bAgI7KzUSjog9IlN"
	PriceIDProPlan  PriceID = "price_1SBfSe00bAgI7KzUfa3n266j"
)

type Client struct {
	logger *slog.Logger
	APIKey string
	db     *database.Database
}

func NewClient(logger *slog.Logger, apiKey string, db *database.Database) Client {
	return Client{
		logger: logger,
		APIKey: apiKey,
		db:     db,
	}
}

type Customer struct {
	ID    string
	Email string
}

type CreateCustomerParams struct {
	Email string
}

func (c *Client) CreateCustomer(ctx context.Context, params CreateCustomerParams) (Customer, error) {
	var customer Customer

	stripe.Key = c.APIKey
	result, err := stripeCustomer.New(&stripe.CustomerParams{
		Email: stripe.String(params.Email),
	})
	if err != nil {
		return customer, err
	}

	customer.ID = result.ID
	customer.Email = result.Email

	if _, err := stripeSubscription.New(&stripe.SubscriptionParams{
		Customer: stripe.String(customer.ID),
		Items: []*stripe.SubscriptionItemsParams{
			{
				Price: stripe.String(string(PriceIDFreePlan)),
			},
		},
	}); err != nil {
		c.logger.Error("Failed to create Stripe subscription", "error", err)
		return customer, fmt.Errorf("failed to create Stripe subscription: %w", err)
	}

	return customer, nil
}

func (c *Client) SwitchSubscriptionPlan(ctx context.Context, userID uuid.UUID, newPriceID PriceID) error {
	stripe.Key = c.APIKey

	user, err := c.db.GetUserByID(ctx, userID)
	if err != nil {
		c.logger.Error("Failed to get user by ID", "error", err, "userID", userID)
		return fmt.Errorf("failed to get user by ID: %w", err)
	}

	// Retrieve the subscription to get the current items
	subscription, err := stripeSubscription.Get(user.StripeSubscriptionID, nil)
	if err != nil {
		return err
	}

	if len(subscription.Items.Data) == 0 {
		return fmt.Errorf("no subscription items found for subscription ID: %s", user.StripeSubscriptionID)
	}

	// Update the first item with the new price ID
	if _, err = stripeSubscription.Update(user.StripeSubscriptionID, &stripe.SubscriptionParams{
		Items: []*stripe.SubscriptionItemsParams{
			{
				ID:    stripe.String(subscription.Items.Data[0].ID),
				Price: stripe.String(string(newPriceID)),
			},
		},
	}); err != nil {
		c.logger.Error("Failed to update Stripe subscription", "error", err)
		return fmt.Errorf("failed to update Stripe subscription: %w", err)
	}
	return nil
}
