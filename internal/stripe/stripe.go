package stripe

import (
	"context"

	"github.com/stripe/stripe-go/v82"
	stripeCustomer "github.com/stripe/stripe-go/v82/customer"
	stripeSubscription "github.com/stripe/stripe-go/v82/subscription"
)

type PriceID string

const (
	FreePlanPriceID PriceID = "price_1S9R9r00bAgI7KzUSjog9IlN"
	ProPlanPriceID  PriceID = "price_1S9PEm00bAgI7KzU34BtVhiQ"
)

type Client struct {
	APIKey string
}

func NewClient(apiKey string) Client {
	return Client{
		APIKey: apiKey,
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

	return customer, nil
}

type AddSubscriptionParams struct {
	CustomerID string
	PriceID    PriceID
}

func (c *Client) AddSubscription(ctx context.Context, params AddSubscriptionParams) error {
	stripe.Key = c.APIKey
	_, err := stripeSubscription.New(&stripe.SubscriptionParams{
		Customer: stripe.String(params.CustomerID),
		Items: []*stripe.SubscriptionItemsParams{
			{
				Price: stripe.String(string(params.PriceID)),
			},
		},
	})
	return err
}
