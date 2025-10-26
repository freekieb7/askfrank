package user

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/freekieb7/askfrank/internal/audit"
	"github.com/freekieb7/askfrank/internal/database"
	"github.com/freekieb7/askfrank/internal/notifications"
	"github.com/freekieb7/askfrank/internal/webhook"

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

func (m *Manager) ListUsers(ctx context.Context) ([]User, error) {
	dbUsers, err := m.db.ListUsers(ctx, database.ListUsersParams{
		Limit:  100,
		Offset: 0,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	users := make([]User, len(dbUsers))
	for i, dbUser := range dbUsers {
		users[i] = User{
			ID:        dbUser.ID,
			Name:      dbUser.Name,
			Email:     dbUser.Email,
			CreatedAt: dbUser.CreatedAt,
			UpdatedAt: dbUser.UpdatedAt,
		}
	}

	return users, nil
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
