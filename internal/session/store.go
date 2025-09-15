package session

import (
	"context"
	"errors"
	"fmt"
	"hp/internal/config"
	"hp/internal/database"
	"hp/internal/util"
	"net/http"
	"time"

	"github.com/google/uuid"
)

type Store struct {
	Database *database.Database
	Config   Config
}

type Config struct {
	CookieName     string
	Domain         string
	Path           string
	ExpiresIn      time.Duration
	CookieHTTPOnly bool
	CookieSecure   bool
	CookieSameSite http.SameSite
	CookieMaxAge   int
}

func New(database *database.Database, config Config) Store {
	return Store{
		Database: database,
		Config:   config,
	}
}

var (
	ErrSessionNotFound = fmt.Errorf("session not found")
)

func (s *Store) Get(ctx context.Context, r *http.Request) (database.Session, error) {
	sessionID, ok := ctx.Value(config.SessionContextKey).(string)
	if !ok {
		return database.Session{}, fmt.Errorf("session id not found in context")
	}

	sess, err := s.Database.GetSessionByToken(ctx, sessionID)
	if err != nil {
		if errors.Is(err, database.ErrSessionNotFound) {
			return database.Session{
				ID:        uuid.Nil,
				Token:     sessionID,
				UserID:    util.Optional[uuid.UUID]{},
				UserAgent: r.UserAgent(),
				IPAddress: r.RemoteAddr,
				Data:      map[string]any{},
				ExpiresAt: time.Now().Add(s.Config.ExpiresIn),
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
				RevokedAt: util.None[time.Time](),
			}, nil
		}

		return sess, fmt.Errorf("failed to get session by token: %w", err)
	}

	return sess, nil
}

func (s *Store) Save(ctx context.Context, w http.ResponseWriter, sess database.Session) error {
	// Create new session
	if sess.ID == uuid.Nil {
		if _, err := s.Database.CreateSession(ctx, database.CreateSessionParams{
			Token:     sess.Token,
			UserID:    sess.UserID,
			UserAgent: sess.UserAgent,
			IPAddress: sess.IPAddress,
			Data:      sess.Data,
			ExpiresAt: sess.ExpiresAt,
			RevokedAt: sess.RevokedAt,
		}); err != nil {
			return fmt.Errorf("failed to create session: %w", err)
		}
		return nil
	}

	// Update existing session
	if err := s.Database.UpdateSessionByID(ctx, sess.ID, database.UpdateSessionParams{
		UserID: sess.UserID,
		Data:   util.Some(sess.Data),
	}); err != nil {
		return fmt.Errorf("failed to update session: %w", err)
	}
	return nil
}

func (s *Store) Destroy(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	id, ok := ctx.Value(config.SessionContextKey).(uuid.UUID)
	if !ok {
		return fmt.Errorf("session id not found in context")
	}

	// Delete session from database
	if err := s.Database.DeleteSessionByID(ctx, id); err != nil {
		err = fmt.Errorf("failed to delete session: %w", err)
		return err
	}

	// Expire session cookie
	http.SetCookie(w, &http.Cookie{
		Name:        s.Config.CookieName,
		Value:       "",
		Path:        s.Config.Path,
		Domain:      s.Config.Domain,
		MaxAge:      -1,
		Expires:     time.Now().Add(-1 * time.Minute),
		Secure:      s.Config.CookieSecure,
		HttpOnly:    s.Config.CookieHTTPOnly,
		SameSite:    s.Config.CookieSameSite,
		Partitioned: s.Config.CookieSecure,
	})

	return nil
}

func (s *Store) Refresh(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	sessionID, ok := ctx.Value(config.SessionContextKey).(uuid.UUID)
	if !ok {
		return fmt.Errorf("session id not found in context")
	}

	sess, err := s.Database.GetSessionByID(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("failed to get session: %w", err)
	}

	newToken, err := util.RandomString(32)
	if err != nil {
		return fmt.Errorf("failed to generate new token: %w", err)
	}

	if err := s.Database.UpdateSessionByID(ctx, sess.ID, database.UpdateSessionParams{
		Token: util.Some(newToken),
	}); err != nil {
		return fmt.Errorf("failed to refresh session: %w", err)
	}

	// Set new session ID in context
	ctx = context.WithValue(ctx, config.SessionContextKey, newToken)
	*r = *r.WithContext(ctx)

	// Set new session cookie
	http.SetCookie(w, &http.Cookie{
		Name:        s.Config.CookieName,
		Value:       newToken,
		Path:        s.Config.Path,
		Domain:      s.Config.Domain,
		Expires:     time.Now().Add(s.Config.ExpiresIn),
		HttpOnly:    s.Config.CookieHTTPOnly,
		Secure:      s.Config.CookieSecure,
		SameSite:    s.Config.CookieSameSite,
		MaxAge:      s.Config.CookieMaxAge,
		Partitioned: s.Config.CookieSecure,
	})

	return nil
}
