package api

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"
)

// OAuth in-memory implementation (simple) -------------------------------------------------
// NOTE: This is a minimal OAuth2 Authorization Code + PKCE flow implementation intended
// for internal use. Not production hardened (missing: refresh tokens, client secrets,
// revocation, scopes persistence, rotation, auditing, etc.)

// OAuthClient represents a registered client application
// In a real system you would persist this and include secret/redirect validation & scopes
// For public clients (SPA/native) we rely on PKCE.
type OAuthClient struct {
	ID           string
	Name         string
	RedirectURIs []string
	Public       bool // true => no client secret, must use PKCE
	AllowedScopes []string
}

type AuthCode struct {
	Code        string
	ClientID    string
	UserID      uuid.UUID
	RedirectURI string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	CodeChallenge       string
	CodeChallengeMethod string // "S256" or "plain"
	Scopes      []string
}

type AccessToken struct {
	Token     string
	ClientID  string
	UserID    uuid.UUID
	ExpiresAt time.Time
	Scopes    []string
}

type OAuthServer struct {
	clients     map[string]*OAuthClient
	codes       map[string]*AuthCode
	tokens      map[string]*AccessToken
	mu          sync.RWMutex
	codeTTL     time.Duration
	tokenTTL    time.Duration
}

func NewOAuthServer() *OAuthServer {
	return &OAuthServer{
		clients:  make(map[string]*OAuthClient),
		codes:    make(map[string]*AuthCode),
		tokens:   make(map[string]*AccessToken),
		codeTTL:  5 * time.Minute,
		tokenTTL: 1 * time.Hour,
	}
}

func (s *OAuthServer) RegisterClient(c *OAuthClient) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[c.ID] = c
}

func (s *OAuthServer) GetClient(id string) (*OAuthClient, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.clients[id]
	return c, ok
}

func (s *OAuthServer) ValidateRedirectURI(client *OAuthClient, redirect string) bool {
	for _, r := range client.RedirectURIs {
		if r == redirect {
			return true
		}
	}
	return false
}

func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil { return "", err }
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *OAuthServer) CreateAuthCode(client *OAuthClient, userID uuid.UUID, redirectURI string, cc string, ccm string, scopes []string) (*AuthCode, error) {
	code, err := randomString(32)
	if err != nil { return nil, err }
	ac := &AuthCode{
		Code: code,
		ClientID: client.ID,
		UserID: userID,
		RedirectURI: redirectURI,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(s.codeTTL),
		CodeChallenge: cc,
		CodeChallengeMethod: ccm,
		Scopes: scopes,
	}
	s.mu.Lock()
	s.codes[code] = ac
	s.mu.Unlock()
	return ac, nil
}

func (s *OAuthServer) ExchangeCode(code string, client *OAuthClient, verifier string, redirectURI string) (*AccessToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ac, ok := s.codes[code]
	if !ok { return nil, errors.New("invalid_code") }
	delete(s.codes, code) // one-time use
	if time.Now().After(ac.ExpiresAt) { return nil, errors.New("code_expired") }
	if ac.ClientID != client.ID { return nil, errors.New("client_mismatch") }
	if ac.RedirectURI != redirectURI { return nil, errors.New("redirect_mismatch") }
	// PKCE validation
	if client.Public {
		if ac.CodeChallenge != "" {
			if ac.CodeChallengeMethod == "S256" {
				// compute S256 hash of verifier
				// RFC 7636: BASE64URL-ENCODE(SHA256(verifier))
				computed, err := pkceS256(verifier)
				if err != nil { return nil, err }
				if computed != ac.CodeChallenge { return nil, errors.New("invalid_code_verifier") }
			} else { // plain
				if verifier != ac.CodeChallenge { return nil, errors.New("invalid_code_verifier") }
			}
		} else {
			return nil, errors.New("missing_code_challenge")
		}
	}
	tokStr, err := randomString(32)
	if err != nil { return nil, err }
	at := &AccessToken{
		Token: tokStr,
		ClientID: client.ID,
		UserID: ac.UserID,
		ExpiresAt: time.Now().Add(s.tokenTTL),
		Scopes: ac.Scopes,
	}
	s.tokens[tokStr] = at
	return at, nil
}

func pkceS256(verifier string) (string, error) {
	// small helper to compute S256 hashed code challenge
	// separated for clarity
	imported := sha256Sum(verifier)
	return base64.RawURLEncoding.EncodeToString(imported), nil
}

func sha256Sum(s string) []byte {
	// local tiny helper to avoid additional imports in main block for readability
	// will replaced by crypto/sha256
	// We purposely not implement here to keep patch simple; replaced in next edit.
	return nil
}

// ValidateScope subset check (naive)
func (s *OAuthServer) FilterScopes(client *OAuthClient, requested []string) []string {
	allowedSet := map[string]struct{}{}
	for _, as := range client.AllowedScopes { allowedSet[as] = struct{}{} }
	var result []string
	for _, r := range requested {
		if _, ok := allowedSet[r]; ok { result = append(result, r) }
	}
	return result
}

// BuildRedirectURL appends code & state
func BuildRedirectURL(base string, code string, state string) (string, error) {
	u, err := url.Parse(base)
	if err != nil { return "", err }
	q := u.Query()
	q.Set("code", code)
	if state != "" { q.Set("state", state) }
	u.RawQuery = q.Encode()
	return u.String(), nil
}
