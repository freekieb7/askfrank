package session

import (
	"context"
	"encoding/json"
	"fmt"
	"hp/internal/database"
	"hp/internal/i18n"
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
	Language   i18n.Language `json:"language"`
	CsrfToken  string        `json:"csrf_token"`
	RedirectTo string        `json:"redirect_to"`
}

func (s *Store) Get(ctx context.Context, r *http.Request) (Session, error) {
	sessionToken, err := r.Cookie(s.Config.CookieName)
	if err != nil {
		return Session{}, fmt.Errorf("session store: failed to get session cookie: %w", err)
	}

	sess, err := s.Database.GetSessionByToken(ctx, sessionToken.Value)
	if err != nil {
		return Session{}, fmt.Errorf("session store: failed to get session by token: %w", err)
	}

	// Check if session is expired
	if sess.ExpiresAt.Before(time.Now()) {
		return Session{}, fmt.Errorf("session store: session has expired")
	}

	session := Session{
		ID:        sess.ID,
		Token:     sess.Token,
		UserID:    sess.UserID,
		UserAgent: sess.UserAgent,
		IPAddress: sess.IPAddress,
		ExpiresAt: sess.ExpiresAt,
	}
	if err := json.Unmarshal(sess.Data, &session.Data); err != nil {
		return Session{}, fmt.Errorf("session store: failed to unmarshal session data: %w", err)
	}

	return session, nil
}

// GetOrCreate retrieves an existing session or creates a new one if it doesn't exist
// It automatically handles cookie setting for new sessions
func (s *Store) Create(ctx context.Context, w http.ResponseWriter, r *http.Request) (Session, error) {
	token, err := util.GenerateRandomString(32)
	if err != nil {
		return Session{}, fmt.Errorf("session store: failed to generate session token: %w", err)
	}

	data := SessionData{
		Language: i18n.EN,
	}

	dataEncoded, err := json.Marshal(SessionData{
		Language: i18n.EN,
	})
	if err != nil {
		return Session{}, fmt.Errorf("session store: failed to marshal session data: %w", err)
	}

	// Save session to database
	dbSess, err := s.Database.CreateSession(ctx, database.CreateSessionParams{
		ID:        uuid.New(),
		UserID:    util.None[uuid.UUID](),
		Token:     token,
		UserAgent: r.UserAgent(),
		IPAddress: r.RemoteAddr,
		Data:      dataEncoded,
		ExpiresAt: time.Now().Add(s.Config.ExpiresIn),
	})
	if err != nil {
		return Session{}, fmt.Errorf("session store: failed to create session: %w", err)
	}

	sess := Session{
		ID:        dbSess.ID,
		Token:     dbSess.Token,
		UserID:    dbSess.UserID,
		UserAgent: dbSess.UserAgent,
		IPAddress: dbSess.IPAddress,
		Data:      data,
		ExpiresAt: dbSess.ExpiresAt,
	}

	// Set-Cookie
	http.SetCookie(w, &http.Cookie{
		Name:     s.Config.CookieName,
		Value:    sess.Token,
		Path:     s.Config.Path,
		Domain:   s.Config.Domain,
		HttpOnly: s.Config.CookieHTTPOnly,
		Secure:   s.Config.CookieSecure,
		SameSite: s.Config.CookieSameSite,
		MaxAge:   int(s.Config.ExpiresIn.Seconds()),
	})

	return sess, nil
}

func (s *Store) Update(ctx context.Context, sess Session) error {
	// Update existing session
	data, err := json.Marshal(sess.Data)
	if err != nil {
		return fmt.Errorf("session store: failed to marshal session data: %w", err)
	}
	if err := s.Database.UpdateSessionByID(ctx, sess.ID, database.UpdateSessionParams{
		UserID: sess.UserID,
		Data:   util.Some(data),
	}); err != nil {
		return fmt.Errorf("session store: failed to update session: %w", err)
	}
	return nil
}

func (s *Store) Regenerate(ctx context.Context, w http.ResponseWriter, r *http.Request, sess Session) (Session, error) {
	// Generate new session token
	newToken, err := util.GenerateRandomString(32)
	if err != nil {
		return Session{}, fmt.Errorf("session store: failed to generate new token: %w", err)
	}

	// Update session with new token
	if err := s.Database.UpdateSessionByID(ctx, sess.ID, database.UpdateSessionParams{
		Token: util.Some(newToken),
	}); err != nil {
		return Session{}, fmt.Errorf("session store: failed to regenerate session: %w", err)
	}

	// Update the session object
	sess.Token = newToken

	// Set new session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     s.Config.CookieName,
		Value:    newToken,
		Path:     s.Config.Path,
		Domain:   s.Config.Domain,
		HttpOnly: s.Config.CookieHTTPOnly,
		Secure:   s.Config.CookieSecure,
		SameSite: s.Config.CookieSameSite,
		MaxAge:   int(s.Config.ExpiresIn.Seconds()),
	})

	return sess, nil
}
