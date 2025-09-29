package stripe

import (
	"context"
	"fmt"
	"hp/internal/database"
	"log/slog"

	"github.com/google/uuid"
	"github.com/stripe/stripe-go/v82"
	stripeCheckoutSession "github.com/stripe/stripe-go/v82/checkout/session"
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
		return customer, fmt.Errorf("failed to create Stripe customer: %w", err)
	}

	customer.ID = result.ID
	customer.Email = result.Email

	return customer, nil
}
func (c *Client) GetSubscriptionByCustomerID(ctx context.Context, customerID string) (*stripe.Subscription, error) {
	stripe.Key = c.APIKey

	params := &stripe.SubscriptionListParams{
		Customer: stripe.String(customerID),
	}
	params.Limit = stripe.Int64(1)

	i := stripeSubscription.List(params)
	if i.Next() {
		return i.Subscription(), nil
	}
	if err := i.Err(); err != nil {
		return nil, fmt.Errorf("failed to list subscriptions: %w", err)
	}

	return nil, nil // No subscription found
}

func (c *Client) AddSubscriptionToCustomer(ctx context.Context, customerID string, priceID PriceID) (string, error) {
	stripe.Key = c.APIKey

	subscription, err := stripeSubscription.New(&stripe.SubscriptionParams{
		Customer: stripe.String(customerID),
		Items: []*stripe.SubscriptionItemsParams{
			{
				Price: stripe.String(string(priceID)),
			},
		},
	})
	if err != nil {
		return "", fmt.Errorf("failed to create Stripe subscription: %w", err)
	}
	return subscription.ID, nil
}

func (c *Client) SwitchSubscriptionPlan(ctx context.Context, organisationID uuid.UUID, newPriceID PriceID) error {
	stripe.Key = c.APIKey

	organisation, err := c.db.GetOrganisationByID(ctx, organisationID)
	if err != nil {
		return fmt.Errorf("failed to get organisation by ID: %w", err)
	}

	// Retrieve the subscription to get the current items
	subscription, err := stripeSubscription.Get(organisation.StripeSubscriptionID, nil)
	if err != nil {
		return fmt.Errorf("failed to retrieve Stripe subscription: %w", err)
	}

	if len(subscription.Items.Data) == 0 {
		return fmt.Errorf("no subscription items found for subscription ID: %s", organisation.StripeSubscriptionID)
	}

	// Update the first item with the new price ID
	if _, err = stripeSubscription.Update(organisation.StripeSubscriptionID, &stripe.SubscriptionParams{
		Items: []*stripe.SubscriptionItemsParams{
			{
				ID:    stripe.String(subscription.Items.Data[0].ID),
				Price: stripe.String(string(newPriceID)),
			},
		},
	}); err != nil {
		return fmt.Errorf("failed to update Stripe subscription: %w", err)
	}
	return nil
}

func (c *Client) CreateCheckoutSession(ctx context.Context, organisationID uuid.UUID, priceID PriceID, successURL, cancelURL string) (string, error) {
	stripe.Key = c.APIKey

	organisation, err := c.db.GetOrganisationByID(ctx, organisationID)
	if err != nil {
		return "", fmt.Errorf("failed to get organisation by ID: %w", err)
	}

	params := &stripe.CheckoutSessionParams{
		Customer:                 stripe.String(organisation.StripeCustomerID),
		SuccessURL:               stripe.String(successURL),
		CancelURL:                stripe.String(cancelURL),
		Mode:                     stripe.String(string(stripe.CheckoutSessionModeSubscription)),
		BillingAddressCollection: stripe.String(string(stripe.CheckoutSessionBillingAddressCollectionAuto)),
		LineItems: []*stripe.CheckoutSessionLineItemParams{
			{
				Price:    stripe.String(string(priceID)),
				Quantity: stripe.Int64(1),
			},
		},
	}

	session, err := stripeCheckoutSession.New(params)
	if err != nil {
		return "", fmt.Errorf("failed to create Stripe checkout session: %w", err)
	}

	return session.URL, nil
}
