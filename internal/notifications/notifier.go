package notifications

import (
	"context"
	"fmt"
	"hp/internal/database"
	"log/slog"

	"github.com/google/uuid"
)

type Notifier struct {
	logger *slog.Logger
	db     *database.Database
}

func NewNotifier(logger *slog.Logger, db *database.Database) Notifier {
	return Notifier{logger: logger, db: db}
}

type NotificationType string

const (
	NotificationTypeInfo    NotificationType = "info"
	NotificationTypeWarning NotificationType = "warning"
	NotificationTypeError   NotificationType = "error"
)

type NotifyParam struct {
	OwnerID uuid.UUID
	Title   string
	Message string
	Type    NotificationType
}

func (n *Notifier) Notify(ctx context.Context, params NotifyParam) error {
	if _, err := n.db.CreateNotification(ctx, database.CreateNotificationParams{
		OwnerID: params.OwnerID,
		Title:   params.Title,
		Message: params.Message,
		Type:    string(params.Type),
		IsRead:  false,
	}); err != nil {
		return fmt.Errorf("failed to create notification: %w", err)
	}
	return nil
}
