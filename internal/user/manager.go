package user

import (
	"context"
	"fmt"
	"hp/internal/audit"
	"hp/internal/database"
	"hp/internal/notifications"
	"hp/internal/webhook"
	"log/slog"
	"time"

	"github.com/google/uuid"
)

type Manager struct {
	logger         *slog.Logger
	db             *database.Database
	auditor        *audit.Auditor
	webhookManager *webhook.Manager
	notifier       *notifications.Manager
}

func NewManager(logger *slog.Logger, db *database.Database, auditor *audit.Auditor, webhookManager *webhook.Manager, notifier *notifications.Manager) Manager {
	return Manager{logger: logger, db: db, auditor: auditor, webhookManager: webhookManager, notifier: notifier}
}

type User struct {
	ID        uuid.UUID
	Name      string
	Email     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (m *Manager) GetUser(ctx context.Context, userID uuid.UUID) (User, error) {
	var user User

	dbUser, err := m.db.GetUserByID(ctx, userID)
	if err != nil {
		return user, fmt.Errorf("failed to get user by ID: %w", err)
	}

	user = User{
		ID:        dbUser.ID,
		Name:      dbUser.Name,
		Email:     dbUser.Email,
		CreatedAt: dbUser.CreatedAt,
		UpdatedAt: dbUser.UpdatedAt,
	}

	return user, nil
}
