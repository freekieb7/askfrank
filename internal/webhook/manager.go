package webhook

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/freekieb7/askfrank/internal/database"
	"github.com/freekieb7/askfrank/internal/util"

	"github.com/google/uuid"
)

type Manager struct {
	logger *slog.Logger
	db     *database.Database
}

func NewManager(logger *slog.Logger, db *database.Database) Manager {
	return Manager{logger: logger, db: db}
}

type EventType string

const (
	EventTypeFileCreated         EventType = "file.created"
	EventTypeFileDeleted         EventType = "file.deleted"
	EventTypeUserLogin           EventType = "user.login"
	EventTypeUserLogout          EventType = "user.logout"
	EventTypeUserRegister        EventType = "user.register"
	EventTypeSubscriptionChanged EventType = "subscription.changed"
)

func EventTypeFromString(s string) (EventType, error) {
	switch s {
	case string(EventTypeFileCreated):
		return EventTypeFileCreated, nil
	case string(EventTypeFileDeleted):
		return EventTypeFileDeleted, nil
	case string(EventTypeUserLogin):
		return EventTypeUserLogin, nil
	case string(EventTypeUserLogout):
		return EventTypeUserLogout, nil
	case string(EventTypeUserRegister):
		return EventTypeUserRegister, nil
	default:
		return "", fmt.Errorf("unknown webhook event type: %s", s)
	}
}

func (m *Manager) EventTypes() []EventType {
	return []EventType{
		EventTypeFileCreated,
		EventTypeFileDeleted,
		EventTypeUserLogin,
		EventTypeUserLogout,
		EventTypeUserRegister,
	}
}

type Subscription struct {
	ID                  uuid.UUID
	OwnerOrganisationID uuid.UUID
	Name                string
	Description         string
	URL                 string
	Secret              string
	EventTypes          []EventType
	IsActive            bool
	LastDeliveredAt     util.Optional[time.Time]
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

type SubscriptionParams struct {
	OrganisationID uuid.UUID
}

func (m *Manager) Subscriptions(ctx context.Context, params SubscriptionParams) ([]Subscription, error) {
	return make([]Subscription, 0), nil
	// var subscriptions []Subscription

	// dbSubscriptions, err := m.db.ListWebhookSubscriptions(ctx, database.ListWebhookSubscriptionsParams{
	// 	OwnerOrganisationID: util.Some(params.OrganisationID),
	// })
	// if err != nil {
	// 	return subscriptions, fmt.Errorf("failed to list webhook subscriptions: %w", err)
	// }

	// for _, s := range dbSubscriptions {
	// 	eventTypes := make([]EventType, len(s.EventTypes))
	// 	for i, et := range s.EventTypes {
	// 		eventType, err := EventTypeFromString(et)
	// 		if err != nil {
	// 			m.logger.Warn("Unknown webhook event type in subscription", "subscription_id", s.ID, "event_type", et)
	// 			continue
	// 		}
	// 		eventTypes[i] = eventType
	// 	}

	// 	subscriptions = append(subscriptions, Subscription{
	// 		ID:                  s.ID,
	// 		OwnerOrganisationID: s.OwnerOrganisationID,
	// 		Name:                s.Name,
	// 		Description:         s.Description,
	// 		URL:                 s.URL,
	// 		Secret:              s.Secret,
	// 		EventTypes:          eventTypes,
	// 		IsActive:            s.IsActive,
	// 		CreatedAt:           s.CreatedAt,
	// 		UpdatedAt:           s.UpdatedAt,
	// 	})
	// }

	// return subscriptions, nil
}

type SubscribeParams struct {
	OrganisationID uuid.UUID
	Name           string
	Description    string
	URL            string
	EventTypes     []EventType
}

func (m *Manager) Subscribe(ctx context.Context, params SubscribeParams) (uuid.UUID, error) {
	return uuid.New(), nil
	// var subscriptionID uuid.UUID

	// // Convert event types to string slice
	// eventTypeStrs := make([]string, len(params.EventTypes))
	// for i, et := range params.EventTypes {
	// 	eventTypeStrs[i] = string(et)
	// }

	// randomSecret, err := util.GenerateRandomString(32)
	// if err != nil {
	// 	return subscriptionID, fmt.Errorf("failed to generate random string: %w", err)
	// }

	// subscription, err := m.db.CreateWebhookSubscription(ctx, database.CreateWebhookSubscriptionParams{
	// 	OwnerOrganisationID: params.OrganisationID,
	// 	Name:                params.Name,
	// 	Description:         params.Description,
	// 	URL:                 params.URL,
	// 	Secret:              randomSecret,
	// 	EventTypes:          eventTypeStrs,
	// 	IsActive:            true,
	// })
	// if err != nil {
	// 	return subscriptionID, fmt.Errorf("failed to create webhook subscription: %w", err)
	// }

	// return subscription.ID, nil
}

type UnsubscribeParams struct {
	OrganisationID uuid.UUID
	SubscriptionID uuid.UUID
}

func (m *Manager) Unsubscribe(ctx context.Context, params UnsubscribeParams) error {
	return nil
	// if err := m.db.DeleteWebhookSubscriptionByID(ctx, params.SubscriptionID, database.DeleteWebhookSubscriptionParams{
	// 	OwnerOrganisationID: util.Some(params.OrganisationID),
	// }); err != nil {
	// 	return fmt.Errorf("failed to delete webhook subscription: %w", err)
	// }
	// return nil
}

type RegisterEventParams struct {
	OrganisationID uuid.UUID
	Type           EventType
	Data           map[string]any
}

func (m *Manager) RegisterEvent(ctx context.Context, params RegisterEventParams) error {
	return nil
	// data, err := json.Marshal(params.Data)
	// if err != nil {
	// 	return fmt.Errorf("failed to marshal webhook event data: %w", err)
	// }

	// if _, err := m.db.CreateWebhookEvent(ctx, database.CreateWebhookEventParams{
	// 	EventType: string(params.Type),
	// 	Payload:   data,
	// }); err != nil {
	// 	return fmt.Errorf("failed to create webhook event: %w", err)
	// }

	// return nil
}
