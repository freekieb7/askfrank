package oauth

import (
	"context"
	"hp/internal/audit"
	"hp/internal/database"
	"hp/internal/util"
	"log/slog"
	"time"

	"github.com/google/uuid"
)

type Manager struct {
	Logger  *slog.Logger
	DB      *database.Database
	Auditor *audit.Auditor
}

func NewManager(logger *slog.Logger, db *database.Database, auditor *audit.Auditor) Manager {
	return Manager{Logger: logger, DB: db, Auditor: auditor}
}

type Client struct {
	ID            uuid.UUID
	Name          string
	Secret        string
	RedirectURIs  []string
	IsPublic      bool
	AllowedScopes []string
	ModifiedAt    time.Time
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
			ID:            c.ID,
			Name:          c.Name,
			Secret:        c.Secret,
			RedirectURIs:  c.RedirectURIs,
			IsPublic:      c.IsPublic,
			AllowedScopes: c.AllowedScopes,
			ModifiedAt:    c.UpdatedAt,
		})
	}
	return result, nil
}

func (m *Manager) GetClientByID(ctx context.Context, clientID uuid.UUID) (Client, error) {
	c, err := m.DB.GetOAuthClientByID(ctx, clientID)
	if err != nil {
		return Client{}, err
	}

	return Client{
		ID:            c.ID,
		Name:          c.Name,
		Secret:        c.Secret,
		RedirectURIs:  c.RedirectURIs,
		IsPublic:      c.IsPublic,
		AllowedScopes: c.AllowedScopes,
		ModifiedAt:    c.UpdatedAt,
	}, nil
}

type CreateClientParams struct {
	OrganisationID uuid.UUID
	Name           string
	RedirectURIs   []string
	IsPublic       bool
	AllowedScopes  []string
}

func (m *Manager) CreateClient(ctx context.Context, params CreateClientParams) (Client, error) {
	// Generate a secure random secret for confidential clients
	secret, err := util.RandomString(32)
	if err != nil {
		return Client{}, err
	}

	// Ensure standard OpenID Connect scopes are included
	params.AllowedScopes = append(params.AllowedScopes, "openid", "profile", "email")

	// Store the client in the database
	dbClient, err := m.DB.CreateOAuthClient(ctx, database.CreateOAuthClientParams{
		OwnerOrganisationID: params.OrganisationID,
		Name:                params.Name,
		RedirectURIs:        params.RedirectURIs,
		IsPublic:            params.IsPublic,
		AllowedScopes:       params.AllowedScopes,
		Secret:              secret,
	})
	if err != nil {
		return Client{}, err
	}

	return Client{
		ID:            dbClient.ID,
		Name:          dbClient.Name,
		RedirectURIs:  dbClient.RedirectURIs,
		IsPublic:      dbClient.IsPublic,
		AllowedScopes: dbClient.AllowedScopes,
		ModifiedAt:    dbClient.UpdatedAt,
	}, nil
}

func (m *Manager) DeleteClientByID(ctx context.Context, clientID uuid.UUID) error {
	if err := m.DB.DeleteOAuthClientByID(ctx, clientID); err != nil {
		return err
	}
	return nil
}
