package oauth

import (
	"context"
	"errors"
	"hp/internal/audit"
	"hp/internal/database"
	"hp/internal/util"
	"log/slog"
	"slices"
	"time"

	"github.com/google/uuid"
)

type Scope string

const (
	ScopeOpenID        Scope = "openid"
	ScopeProfile       Scope = "profile"
	ScopeEmail         Scope = "email"
	ScopeOfflineAccess Scope = "offline_access"
	ScopeClientsRead   Scope = "clients.read"
)

func ScopeParse(s string) (Scope, error) {
	switch s {
	case string(ScopeOpenID):
		return ScopeOpenID, nil
	case string(ScopeProfile):
		return ScopeProfile, nil
	case string(ScopeEmail):
		return ScopeEmail, nil
	case string(ScopeOfflineAccess):
		return ScopeOfflineAccess, nil
	case string(ScopeClientsRead):
		return ScopeClientsRead, nil
	default:
		return Scope(s), errors.New("unknown scope")
	}
}

func (s Scope) String() string {
	return string(s)
}

type Manager struct {
	Logger  *slog.Logger
	DB      *database.Database
	Auditor *audit.Auditor
}

func NewManager(logger *slog.Logger, db *database.Database, auditor *audit.Auditor) Manager {
	return Manager{Logger: logger, DB: db, Auditor: auditor}
}

type Client struct {
	ID           uuid.UUID
	Name         string
	Secret       string
	RedirectURIs []string
	IsPublic     bool
	Scopes       []string
	ModifiedAt   time.Time
}

func (m *Manager) ListClients(ctx context.Context) ([]Client, error) {
	clients, err := m.DB.ListOAuthClients(ctx, database.ListOAuthClientsParams{})
	if err != nil {
		return nil, err
	}

	var result []Client
	for _, c := range clients {
		result = append(result, Client{
			ID:           c.ID,
			Name:         c.Name,
			Secret:       c.Secret,
			RedirectURIs: c.RedirectURIs,
			IsPublic:     c.IsPublic,
			Scopes:       c.Scopes,
			ModifiedAt:   c.UpdatedAt,
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
		ID:           c.ID,
		Name:         c.Name,
		Secret:       c.Secret,
		RedirectURIs: c.RedirectURIs,
		IsPublic:     c.IsPublic,
		Scopes:       c.Scopes,
		ModifiedAt:   c.UpdatedAt,
	}, nil
}

type CreateClientParams struct {
	Name          string
	RedirectURIs  []string
	IsPublic      bool
	AllowedScopes []string
}

func (m *Manager) CreateClient(ctx context.Context, params CreateClientParams) (Client, error) {
	// Generate a secure random secret for confidential clients
	secret, err := util.GenerateRandomString(32)
	if err != nil {
		return Client{}, err
	}

	// Validate and parse scopes
	scopes := make([]string, len(params.AllowedScopes))
	for idx, scopeStr := range params.AllowedScopes {
		scope, err := ScopeParse(scopeStr)
		if err != nil {
			return Client{}, err
		}
		scopes[idx] = string(scope)
	}

	// Ensure standard OpenID Connect scopes are not included
	if slices.Contains(scopes, string(ScopeOpenID)) || slices.Contains(scopes, string(ScopeProfile)) || slices.Contains(scopes, string(ScopeEmail)) || slices.Contains(scopes, string(ScopeOfflineAccess)) {
		return Client{}, errors.New("standard OpenID Connect scopes cannot be manually assigned to clients")
	}

	// Store the client in the database
	dbClient, err := m.DB.CreateOAuthClient(ctx, database.CreateOAuthClientParams{
		Name:         params.Name,
		RedirectURIs: params.RedirectURIs,
		IsPublic:     params.IsPublic,
		Scopes:       scopes,
		Secret:       secret,
	})
	if err != nil {
		return Client{}, err
	}

	return Client{
		ID:           dbClient.ID,
		Name:         dbClient.Name,
		RedirectURIs: dbClient.RedirectURIs,
		IsPublic:     dbClient.IsPublic,
		Scopes:       dbClient.Scopes,
		ModifiedAt:   dbClient.UpdatedAt,
	}, nil
}

func (m *Manager) DeleteClientByID(ctx context.Context, clientID uuid.UUID) error {
	if err := m.DB.DeleteOAuthClientByID(ctx, clientID); err != nil {
		return err
	}
	return nil
}

func (m *Manager) ListScopes() map[Scope]string {
	return map[Scope]string{
		ScopeClientsRead: "Read access to client information",
	}
}
