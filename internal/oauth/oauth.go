package oauth

import (
	"context"
	"hp/internal/database"
	"hp/internal/util"
	"log/slog"
	"time"

	"github.com/google/uuid"
)

type Manager struct {
	DB     *database.Database
	Logger *slog.Logger
}

func NewManager(db *database.Database, logger *slog.Logger) Manager {
	return Manager{DB: db, Logger: logger}
}

type Client struct {
	ID           uuid.UUID
	Name         string
	RedirectURIs []string
	ModifiedAt   time.Time
}

func (m *Manager) ListClients(ctx context.Context, organisationID uuid.UUID) ([]Client, error) {
	clients, err := m.DB.ListOAuthClients(ctx, database.ListOAuthClientsParams{
		OwnerOrganisationID: util.Some(organisationID),
	})
	if err != nil {
		return nil, err
	}

	var result []Client
	for _, c := range clients {
		result = append(result, Client{
			ID:           c.ID,
			Name:         c.Name,
			RedirectURIs: c.RedirectURIs,
			ModifiedAt:   c.UpdatedAt,
		})
	}
	return result, nil
}
