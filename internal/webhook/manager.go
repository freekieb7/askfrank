package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"hp/internal/database"
	"hp/internal/util"
	"log/slog"

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

type RegisterEventParam struct {
	OwnerID uuid.UUID
	Type    EventType
	Data    map[string]any
}

func (m *Manager) RegisterEvent(ctx context.Context, params RegisterEventParam) error {
	data, err := json.Marshal(params.Data)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook event data: %w", err)
	}

	if _, err := m.db.CreateWebhookEvent(ctx, database.CreateWebhookEventParams{
		EventType: string(params.Type),
		Payload:   data,
	}); err != nil {
		return fmt.Errorf("failed to create webhook event: %w", err)
	}

	return nil
}

type RegisterSubscriptionParam struct {
	OwnerID     uuid.UUID
	Name        string
	Description string
	URL         string
	EventTypes  []EventType
}

func (m *Manager) RegisterSubscription(ctx context.Context, params RegisterSubscriptionParam) (uuid.UUID, error) {
	var subscriptionID uuid.UUID

	// Convert event types to string slice
	eventTypeStrs := make([]string, len(params.EventTypes))
	for i, et := range params.EventTypes {
		eventTypeStrs[i] = string(et)
	}

	randomSecret, err := util.RandomString(32)
	if err != nil {
		return subscriptionID, fmt.Errorf("failed to generate random string: %w", err)
	}

	subscription, err := m.db.CreateWebhookSubscription(ctx, database.CreateWebhookSubscriptionParams{
		OwnerID:     params.OwnerID,
		Name:        params.Name,
		Description: params.Description,
		URL:         params.URL,
		Secret:      randomSecret,
		EventTypes:  eventTypeStrs,
		IsActive:    true,
	})
	if err != nil {
		return subscriptionID, fmt.Errorf("failed to create webhook subscription: %w", err)
	}

	return subscription.ID, nil
}
