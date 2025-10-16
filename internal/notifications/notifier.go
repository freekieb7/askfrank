package notifications

import (
	"context"
	"hp/internal/database"
	"hp/internal/util"
	"log/slog"
	"time"

	"github.com/google/uuid"
)

type Manager struct {
	logger *slog.Logger
	db     *database.Database
}

func NewManager(logger *slog.Logger, db *database.Database) Manager {
	return Manager{logger: logger, db: db}
}

type Notification struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	Title     string
	Message   string
	Type      NotificationType
	IsRead    bool
	ActionURL string
	CreatedAt time.Time
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

func (n *Manager) Notify(ctx context.Context, params NotifyParam) error {
	// if _, err := n.db.CreateNotification(ctx, database.CreateNotificationParams{
	// 	OwnerID: params.OwnerID,
	// 	Title:   params.Title,
	// 	Message: params.Message,
	// 	Type:    string(params.Type),
	// 	IsRead:  false,
	// }); err != nil {
	// 	return fmt.Errorf("failed to create notification: %w", err)
	// }
	return nil
}

func (n *Manager) Unread(ctx context.Context, userID uuid.UUID) ([]Notification, error) {
	notifications, err := n.db.ListNotifications(ctx, database.ListNotificationsParams{
		OwnerUserID:      util.Some(userID),
		Limit:            util.Some(uint16(10)),
		OrderByCreatedAt: util.Some(database.OrderByDESC),
		Read:             util.Some(false),
	})
	if err != nil {
		return nil, err
	}

	result := make([]Notification, len(notifications))
	for i, notif := range notifications {
		result[i] = Notification{
			ID:        notif.ID,
			UserID:    notif.OwnerUserID,
			Title:     notif.Title,
			Message:   notif.Message,
			Type:      NotificationType(notif.Type),
			IsRead:    notif.IsRead,
			ActionURL: notif.ActionURL,
			CreatedAt: notif.CreatedAt,
		}
	}

	return result, nil
}
