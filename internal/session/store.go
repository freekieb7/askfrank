package session

import (
	"context"
	"encoding/json"
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

type Session struct {
	ID        uuid.UUID                `json:"id"`
	Token     string                   `json:"token"`
	UserID    util.Optional[uuid.UUID] `json:"user_id"`
	UserAgent string                   `json:"user_agent"`
	IPAddress string                   `json:"ip_address"`
	Data      SessionData              `json:"data"`
	ExpiresAt time.Time                `json:"expires_at"`
}

type SessionData struct {
	CsrfToken  string `json:"csrf_token"`
	RedirectTo string `json:"redirect_to"`
}

func (s *Store) Get(ctx context.Context, r *http.Request) (Session, error) {
	var session Session

	sessionID, ok := ctx.Value(config.SessionContextKey).(string)
	if !ok {
		return session, fmt.Errorf("session id not found in context")
	}

	sess, err := s.Database.GetSessionByToken(ctx, sessionID)
	if err != nil {
		if errors.Is(err, database.ErrSessionNotFound) {
			return Session{
				ID:        uuid.Nil,
				Token:     sessionID,
				UserID:    util.Optional[uuid.UUID]{},
				UserAgent: r.UserAgent(),
				IPAddress: r.RemoteAddr,
				Data:      SessionData{},
				ExpiresAt: time.Now().Add(s.Config.ExpiresIn),
			}, nil
		}

		return session, fmt.Errorf("failed to get session by token: %w", err)
	}

	session = Session{
		ID:        sess.ID,
		Token:     sess.Token,
		UserID:    sess.UserID,
		UserAgent: sess.UserAgent,
		IPAddress: sess.IPAddress,
		ExpiresAt: sess.ExpiresAt,
	}
	if err := json.Unmarshal(sess.Data, &session.Data); err != nil {
		return session, fmt.Errorf("failed to unmarshal session data: %w", err)
	}

	return session, nil
}

func (s *Store) Save(ctx context.Context, w http.ResponseWriter, sess Session) error {
	// Create new session
	if sess.ID == uuid.Nil {
		if _, err := s.Database.CreateSession(ctx, database.CreateSessionParams{
			Token:     sess.Token,
			UserID:    sess.UserID,
			UserAgent: sess.UserAgent,
			IPAddress: sess.IPAddress,
			Data:      json.RawMessage{},
			ExpiresAt: sess.ExpiresAt,
			RevokedAt: util.None[time.Time](),
		}); err != nil {
			return fmt.Errorf("failed to create session: %w", err)
		}
		return nil
	}

	// Update existing session
	data, err := json.Marshal(sess.Data)
	if err != nil {
		return fmt.Errorf("failed to marshal session data: %w", err)
	}
	if err := s.Database.UpdateSessionByID(ctx, sess.ID, database.UpdateSessionParams{
		UserID: sess.UserID,
		Data:   util.Some(data),
	}); err != nil {
		return fmt.Errorf("failed to update session: %w", err)
	}
	return nil
}

func (s *Store) Destroy(ctx context.Context, w http.ResponseWriter, sess Session) error {
	// Delete session from database
	if err := s.Database.DeleteSessionByID(ctx, sess.ID); err != nil {
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
