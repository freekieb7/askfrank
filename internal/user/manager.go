package user

import (
	"context"
	"fmt"
	"hp/internal/audit"
	"hp/internal/database"
	"hp/internal/notifications"
	"hp/internal/stripe"
	"hp/internal/util"
	"hp/internal/webhook"
	"log/slog"
	"time"

	"github.com/google/uuid"
)

type Manager struct {
	logger              *slog.Logger
	db                  *database.Database
	auditor             *audit.Auditor
	webhookManager      *webhook.Manager
	notificationManager *notifications.Manager
	stripeClient        *stripe.Client
}

func NewManager(logger *slog.Logger, db *database.Database, auditor *audit.Auditor, webhookManager *webhook.Manager, notificationManager *notifications.Manager, stripeClient *stripe.Client) Manager {
	return Manager{logger: logger, db: db, auditor: auditor, webhookManager: webhookManager, notificationManager: notificationManager, stripeClient: stripeClient}
}

type User struct {
	ID             uuid.UUID
	OrganisationID util.Optional[uuid.UUID]
	Name           string
	Email          string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

func (m *Manager) GetUser(ctx context.Context, userID uuid.UUID) (User, error) {
	var user User

	dbUser, err := m.db.GetUserByID(ctx, userID)
	if err != nil {
		return user, fmt.Errorf("failed to get user by ID: %w", err)
	}

	user = User{
		ID:             dbUser.ID,
		OrganisationID: dbUser.OrganisationID,
		Name:           dbUser.Name,
		Email:          dbUser.Email,
		CreatedAt:      dbUser.CreatedAt,
		UpdatedAt:      dbUser.UpdatedAt,
	}

	return user, nil
}
