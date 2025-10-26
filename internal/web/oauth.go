package web

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/freekieb7/askfrank/internal/config"
	"github.com/freekieb7/askfrank/internal/database"
	"github.com/freekieb7/askfrank/internal/http"
	"github.com/freekieb7/askfrank/internal/i18n"
	"github.com/freekieb7/askfrank/internal/oauth"
	"github.com/freekieb7/askfrank/internal/session"
	"github.com/freekieb7/askfrank/internal/util"
	"github.com/freekieb7/askfrank/internal/web/ui"
	"github.com/freekieb7/askfrank/internal/web/ui/views"

	"github.com/google/uuid"
)

const (
	codeTTL  = 10 * time.Minute
	tokenTTL = 15 * time.Minute
)

type OAuthHandler struct {
	Logger       *slog.Logger
	DB           *database.Database
	Translator   *i18n.Translator
	SessionStore *session.Store
	OAuthManager *oauth.Manager
}

func NewOAuthHandler(logger *slog.Logger, db *database.Database, translator *i18n.Translator, sessionStore *session.Store, oauthManager *oauth.Manager) *OAuthHandler {
	return &OAuthHandler{
		Logger:       logger,
		DB:           db,
		Translator:   translator,
		SessionStore: sessionStore,
		OAuthManager: oauthManager,
	}
}

func (h *OAuthHandler) ShowAuthorizePage(ctx context.Context, req *http.Request, res *http.Response) error {
	return ui.Render(ctx, res, views.AuthorizePage(views.AuthorizePageProps{
		LayoutProps: ui.LayoutProps(ctx, "Authorize", h.Translator),
	}))
}

type AuthorizeRequestBody struct {
	Authorized bool `json:"authorized"`
}

func (h *OAuthHandler) AuthorizePageAuthorize(ctx context.Context, req *http.Request, res *http.Response) error {
	var reqBody AuthorizeRequestBody
	if err := req.DecodeJSON(&reqBody); err != nil {
		res.SetStatus(http.StatusBadRequest)
		return res.SendJSON(map[string]any{
			"status":  "error",
			"message": "Invalid request payload",
		})
	}

	return res.SendRedirect("/authorize", http.StatusSeeOther)
}

// Authorize implements OAuth2 Authorization Code (with PKCE for public clients)
// GET /api/auth/v1/authorize?response_type=code&client_id=&redirect_uri=&scope=&state=&code_challenge=&code_challenge_method=
func (h *OAuthHandler) Authorize(ctx context.Context, req *http.Request, res *http.Response) error {
	respTypeRaw := req.URLQueryParam("response_type")
	clientIDStrRaw := req.URLQueryParam("client_id")
	redirectURIRaw := req.URLQueryParam("redirect_uri")
	scopeRaw := req.URLQueryParam("scope")
	stateRaw := req.URLQueryParam("state")
	codeChallengeRaw := req.URLQueryParam("code_challenge")
	codeChallengeMethodRaw := req.URLQueryParam("code_challenge_method")

	if respTypeRaw != "code" {
		h.Logger.Info("Unsupported response type", "response_type", respTypeRaw)
		return RedirectOAuthResponse(res, redirectURIRaw, stateRaw, "unsupported_response_type")
	}

	// Validate client
	clientIDRaw, err := uuid.Parse(clientIDStrRaw)
	if err != nil {
		h.Logger.Info("Invalid client ID format", "client_id", clientIDRaw)
		return RedirectOAuthResponse(res, redirectURIRaw, stateRaw, "invalid_client")
	}

	client, err := h.DB.GetOAuthClientByID(ctx, clientIDRaw)
	if err != nil {
		h.Logger.Info("Failed to get OAuth client", "error", err, "client_id", clientIDRaw)
		return RedirectOAuthResponse(res, redirectURIRaw, stateRaw, "invalid_client")
	}

	if !slices.Contains(client.RedirectURIs, redirectURIRaw) {
		h.Logger.Info("Invalid redirect URI", "redirect_uri", redirectURIRaw, "client_id", clientIDRaw)
		return RedirectOAuthResponse(res, redirectURIRaw, stateRaw, "invalid_redirect_uri")
	}

	// Validate PKCE (must provide challenge)
	if codeChallengeRaw == "" {
		h.Logger.Info("Missing code challenge for public client", "client_id", clientIDRaw)
		return RedirectOAuthResponse(res, redirectURIRaw, stateRaw, "invalid_request")
	}

	if codeChallengeMethodRaw != "S256" && codeChallengeMethodRaw != "plain" && codeChallengeMethodRaw != "" {
		h.Logger.Info("Unsupported code challenge method", "method", codeChallengeMethodRaw, "client_id", clientIDRaw)
		return RedirectOAuthResponse(res, redirectURIRaw, stateRaw, "invalid_request") // Changed to redirect
	}

	// Get user ID from session
	sess := ctx.Value(config.SessionContextKey).(session.Session)

	// If user not logged in, redirect to login page
	if !sess.UserID.IsSet {
		return res.SendRedirect("/login?return_to="+url.QueryEscape(req.URL()), http.StatusFound)
	}

	// Scopes
	authorizedAccess, err := h.DB.GetOAuthAuthorizedAccess(ctx, database.GetOAuthAuthorizedAccessParams{
		ClientID: util.Some(client.ID),
		UserID:   util.Some(sess.UserID.Val),
	})
	if err != nil {
		if errors.Is(err, database.ErrOAuthAuthorizedAccessNotFound) {
			return res.SendRedirect("/authorize?return_to="+url.QueryEscape(req.URL()), http.StatusSeeOther)
		}

		h.Logger.Error("Failed to get authorized access", "error", err)
		return RedirectOAuthResponse(res, redirectURIRaw, stateRaw, "server_error")
	}

	var requestedScopes []string
	if scopeRaw != "" {
		requestedScopes = strings.Fields(scopeRaw)
	}

	// Remove unknown scopes
	var grantedScopes []string
	for _, rs := range requestedScopes {
		if slices.Contains(client.Scopes, rs) {
			s, err := oauth.ScopeParse(rs)
			if err != nil {
				h.Logger.Info("Unknown scope", "scope", rs)
				continue
			}
			grantedScopes = append(grantedScopes, s.String())
		}
	}

	// Ensure that the user has authorized the requested scopes
	for _, gs := range grantedScopes {
		if !slices.Contains(authorizedAccess.Scopes, gs) {
			h.Logger.Info("User has not authorized scope", "scope", gs, "user_id", sess.UserID.Val)
			return res.SendRedirect("/authorize?return_to="+url.QueryEscape(req.URL()), http.StatusSeeOther)
		}
	}

	// Create authorization code
	code, err := util.GenerateRandomString(32)
	if err != nil {
		h.Logger.Error("Failed to generate authorization code", "error", err)
		return RedirectOAuthResponse(res, redirectURIRaw, stateRaw, "server_error")
	}

	oauthCode, err := h.DB.CreateOAuthAuthorizationCode(ctx, database.CreateOAuthAuthorizationCodeParams{
		Token:               code,
		ClientID:            client.ID,
		UserID:              sess.UserID.Val,
		RedirectURI:         redirectURIRaw,
		CodeChallenge:       util.Some(codeChallengeRaw),
		CodeChallengeMethod: util.Some(codeChallengeMethodRaw),
		Scopes:              grantedScopes,
		ExpiresAt:           time.Now().Add(codeTTL),
	})

	if err != nil {
		h.Logger.Error("Failed to create OAuth auth code", "error", err)
		return RedirectOAuthResponse(res, redirectURIRaw, stateRaw, "server_error")
	}

	// Build redirect URL
	redirectURI := redirectURIRaw + "?code=" + url.QueryEscape(oauthCode.Token)
	if stateRaw != "" {
		redirectURI += "&state=" + url.QueryEscape(stateRaw)
	}

	return res.SendRedirect(redirectURI, http.StatusFound)
}

// Token issues access token for authorization_code grant with PKCE
// POST form: grant_type=authorization_code&code=&redirect_uri=&client_id=&code_verifier=
func (h *OAuthHandler) Token(ctx context.Context, req *http.Request, res *http.Response) error {
	grantTypeRaw := req.FormValue("grant_type")

	// Refresh token grant
	if grantTypeRaw == "refresh_token" {
		return h.RefreshTokenFlow(ctx, req, res)
	}

	// Client credentials grant
	if grantTypeRaw == "client_credentials" {
		return h.ClientCredentialFlow(ctx, req, res)
	}

	// Authorization code grant
	if grantTypeRaw != "authorization_code" {
		return JSONOAuthErrorResponse(res, http.StatusBadRequest, "unsupported_grant_type", "Unsupported Grant Type")
	}

	codeRaw := req.FormValue("code")
	redirectURIRaw := req.FormValue("redirect_uri")
	clientIDStrRaw, clientSecretRaw, err := ClientCredentialsFromRequest(req)
	if err != nil {
		return JSONOAuthErrorResponse(res, http.StatusBadRequest, "invalid_grant", "Invalid Client Credentials")
	}
	verifierRaw := req.FormValue("code_verifier")

	// Validate client
	clientIDRaw, err := uuid.Parse(clientIDStrRaw)
	if err != nil {
		h.Logger.Error("Invalid client ID format", "client_id", clientIDStrRaw)
		return JSONOAuthErrorResponse(res, http.StatusBadRequest, "invalid_client", "Invalid Client Credentials")
	}

	client, err := h.DB.GetOAuthClientByID(ctx, clientIDRaw)
	if err != nil {
		h.Logger.Error("Failed to get OAuth client", "error", err, "client_id", clientIDRaw)
		return JSONOAuthErrorResponse(res, http.StatusBadRequest, "invalid_client", "Invalid Client Credentials")
	}

	if !slices.Contains(client.RedirectURIs, redirectURIRaw) {
		h.Logger.Info("Invalid redirect URI", "redirect_uri", redirectURIRaw, "client_id", clientIDRaw)
		return JSONOAuthErrorResponse(res, http.StatusBadRequest, "invalid_redirect_uri", "Invalid Redirect URI")
	}

	// Exchange code for access token
	code, err := h.DB.GetOAuthAuthorizationCodeByCode(ctx, codeRaw)
	if err != nil {
		h.Logger.Debug("Failed to get OAuth authorization code", "error", err, "code", codeRaw)
		return JSONOAuthErrorResponse(res, http.StatusBadRequest, "invalid_grant", "Invalid Authorization Code")
	}

	// Mark code as used
	if err := h.DB.UpdateOAuthAuthorizationCode(ctx, code.ID, database.UpdateOAuthAuthorizationCodeParams{
		UsedAt: util.Some(time.Now()),
	}); err != nil {
		h.Logger.Error("Failed to update OAuth authorization code", "error", err, "code", code.Token)
		return JSONOAuthErrorResponse(res, http.StatusInternalServerError, "server_error", "Failed to exchange Authorization Code")
	}

	if code.ClientID != client.ID {
		return JSONOAuthErrorResponse(res, http.StatusBadRequest, "invalid_grant", "Invalid Client Credentials")
	}
	if code.RedirectURI != redirectURIRaw {
		return JSONOAuthErrorResponse(res, http.StatusBadRequest, "invalid_grant", "Invalid Redirect URI")
	}
	if time.Now().After(code.ExpiresAt) {
		return JSONOAuthErrorResponse(res, http.StatusBadRequest, "invalid_grant", "Invalid Authorization Code")
	}

	// PKCE validation
	if !code.CodeChallenge.IsSet {
		return JSONOAuthErrorResponse(res, http.StatusBadRequest, "invalid_grant", "Missing Code Challenge")
	}

	if !code.CodeChallengeMethod.IsSet {
		return JSONOAuthErrorResponse(res, http.StatusBadRequest, "invalid_grant", "Missing Code Challenge Method")
	}

	// Only S256 is supported for now
	if code.CodeChallengeMethod.Val != "S256" {
		return JSONOAuthErrorResponse(res, http.StatusBadRequest, "invalid_grant", "Unsupported Code Challenge Method")
	}

	if verifierRaw == "" {
		return JSONOAuthErrorResponse(res, http.StatusBadRequest, "invalid_grant", "Missing Code Verifier")
	}

	// compute S256 hash of verifier
	imported := sha256.Sum256([]byte(verifierRaw))
	computed := base64.RawURLEncoding.EncodeToString(imported[:])
	if computed != code.CodeChallenge.Val {
		return JSONOAuthErrorResponse(res, http.StatusBadRequest, "invalid_grant", "Code Verifier Mismatch")
	}

	// For confidential clients, validate client secret
	if clientSecretRaw == "" {
		return JSONOAuthErrorResponse(res, http.StatusBadRequest, "invalid_client", "Invalid Client Credentials")
	}

	if client.Secret != clientSecretRaw {
		return JSONOAuthErrorResponse(res, http.StatusBadRequest, "invalid_client", "Invalid Client Credentials")
	}
	// Issue access token
	token, err := util.GenerateRandomString(32)
	if err != nil {
		h.Logger.Error("Failed to generate random string", "error", err)
		return JSONOAuthErrorResponse(res, http.StatusInternalServerError, "server_error", "")
	}

	accessToken, err := h.DB.CreateOAuthAccessToken(ctx, database.CreateOAuthAccessTokenParams{
		Token:     token,
		ClientID:  client.ID,
		Scopes:    code.Scopes,
		ExpiresAt: time.Now().Add(tokenTTL),
		UserID:    util.Some(code.UserID),
	})
	if err != nil {
		h.Logger.Error("Failed to create OAuth access token", "error", err)
		return JSONOAuthErrorResponse(res, http.StatusInternalServerError, "server_error", "Failed to exchange Authorization Code")
	}

	responseBody := map[string]any{
		"access_token": accessToken.Token,
		"token_type":   "Bearer",
		"expires_in":   int(time.Until(accessToken.ExpiresAt).Seconds()),
		"scope":        strings.Join(accessToken.Scopes, " "),
	}

	// If offline_access scope was granted, issue refresh token as well
	if slices.Contains(code.Scopes, oauth.ScopeOfflineAccess.String()) {
		// Issue refresh token as well
		refreshTokenToken, err := util.GenerateRandomString(32)
		if err != nil {
			h.Logger.Error("Failed to generate refresh token", "error", err)
			return JSONOAuthErrorResponse(res, http.StatusInternalServerError, "server_error", "Failed to exchange Authorization Code")
		}
		refreshTokenExpires := time.Now().Add(30 * 24 * time.Hour) // e.g. 30 days

		refreshTokenChain, err := h.DB.CreateOAuthRefreshTokenChain(ctx, database.CreateOAuthRefreshTokenChainParams{
			ClientID: client.ID,
			UserID:   code.UserID,
			Scopes:   code.Scopes,
		})
		if err != nil {
			h.Logger.Error("Failed to create OAuth refresh token chain", "error", err)
			return JSONOAuthErrorResponse(res, http.StatusInternalServerError, "server_error", "Failed to exchange Authorization Code")
		}

		refreshToken, err := h.DB.CreateOAuthRefreshToken(ctx, database.CreateOAuthRefreshTokenParams{
			Token:     refreshTokenToken,
			ChainID:   refreshTokenChain.ID,
			ExpiresAt: refreshTokenExpires,
			UsedAt:    util.None[time.Time](),
		})
		if err != nil {
			h.Logger.Error("Failed to create OAuth refresh token", "error", err)
			return JSONOAuthErrorResponse(res, http.StatusInternalServerError, "server_error", "Failed to exchange Authorization Code")
		}

		responseBody["refresh_token"] = refreshToken.Token
	}

	res.SetHeader("Content-Type", "application/json")
	res.SetHeader("Cache-Control", "no-store")
	res.SetHeader("Pragma", "no-cache")
	if err := res.SendJSON(responseBody); err != nil {
		h.Logger.Error("Failed to encode JSON response", "error", err)
		return JSONOAuthErrorResponse(res, http.StatusInternalServerError, "server_error", "Failed to exchange Authorization Code")
	}
	return nil
}

func (h *OAuthHandler) ClientCredentialFlow(ctx context.Context, req *http.Request, res *http.Response) error {
	grantTypeRaw := req.FormValue("grant_type")
	if grantTypeRaw != "client_credentials" {
		return JSONOAuthErrorResponse(res, http.StatusBadRequest, "unsupported_grant_type", "Unsupported Grant Type")
	}

	clientIDStrRaw, clientSecretRaw, err := ClientCredentialsFromRequest(req)
	if err != nil {
		return JSONOAuthErrorResponse(res, http.StatusBadRequest, "invalid_client", "Invalid Client Credentials")
	}

	scopesRaw := req.FormValue("scope")

	// Validate client
	clientIDRaw, err := uuid.Parse(clientIDStrRaw)
	if err != nil {
		h.Logger.Info("Invalid client ID format", "client_id", clientIDStrRaw)
		return JSONOAuthErrorResponse(res, http.StatusBadRequest, "invalid_grant", "Invalid Client Credentials")
	}

	client, err := h.DB.GetOAuthClientByID(ctx, clientIDRaw)
	if err != nil {
		h.Logger.Error("Failed to get OAuth client", "error", err, "client_id", clientIDRaw)
		return JSONOAuthErrorResponse(res, http.StatusInternalServerError, "server_error", "Failed to refresh token")
	}

	// For confidential clients, validate client secret
	if client.IsPublic {
		return JSONOAuthErrorResponse(res, http.StatusBadRequest, "invalid_client", "Invalid Client Credentials")
	}

	if client.Secret != clientSecretRaw {
		return JSONOAuthErrorResponse(res, http.StatusBadRequest, "invalid_client", "Invalid Client Credentials")
	}

	// Validate scopes
	var scopes []string
	for _, scope := range strings.Split(scopesRaw, " ") {
		if slices.Contains(client.Scopes, scope) {
			scopes = append(scopes, scope)
		}
	}

	// Issue access token
	token, err := util.GenerateRandomString(32)
	if err != nil {
		h.Logger.Error("Failed to generate random string", "error", err)
		return JSONOAuthErrorResponse(res, http.StatusInternalServerError, "server_error", "Failed to refresh token")
	}

	accessToken, err := h.DB.CreateOAuthAccessToken(ctx, database.CreateOAuthAccessTokenParams{
		Token:     token,
		ClientID:  client.ID,
		UserID:    util.None[uuid.UUID](),
		Scopes:    scopes,
		ExpiresAt: time.Now().Add(tokenTTL),
	})
	if err != nil {
		h.Logger.Error("Failed to create OAuth access token", "error", err)
		return JSONOAuthErrorResponse(res, http.StatusInternalServerError, "server_error", "Failed to refresh token")
	}

	responseBody := map[string]any{
		"access_token": accessToken.Token,
		"token_type":   "Bearer",
		"expires_in":   int(time.Until(accessToken.ExpiresAt).Seconds()),
		"scope":        strings.Join(accessToken.Scopes, " "),
	}

	res.SetHeader("Content-Type", "application/json")
	res.SetHeader("Cache-Control", "no-store")
	res.SetHeader("Pragma", "no-cache")
	res.SetStatus(http.StatusOK)
	if err := json.NewEncoder(res).Encode(responseBody); err != nil {
		h.Logger.Error("Failed to encode JSON response", "error", err)
		return JSONOAuthErrorResponse(res, http.StatusInternalServerError, "server_error", "Failed to refresh token")
	}

	return nil
}

func (h *OAuthHandler) RefreshTokenFlow(ctx context.Context, req *http.Request, res *http.Response) error {

	grantTypeRaw := req.FormValue("grant_type")
	if grantTypeRaw != "refresh_token" {
		return JSONOAuthErrorResponse(res, http.StatusBadRequest, "unsupported_grant_type", "Unsupported Grant Type")
	}

	refreshTokenTokenRaw := req.FormValue("refresh_token")
	clientIDRaw, clientSecretRaw, err := ClientCredentialsFromRequest(req)
	if err != nil {
		return JSONOAuthErrorResponse(res, http.StatusBadRequest, "invalid_grant", "Invalid Client Credentials")
	}
	scopeRaw := req.FormValue("scope")

	// Validate refresh token
	refreshToken, err := h.DB.GetOAuthRefreshTokenByToken(ctx, refreshTokenTokenRaw)
	if err != nil {
		if errors.Is(err, database.ErrOAuthRefreshTokenNotFound) {
			return JSONOAuthErrorResponse(res, http.StatusBadRequest, "invalid_grant", "Invalid Token")
		}

		h.Logger.Error("Failed to get OAuth refresh token", "error", err, "refresh_token", refreshTokenTokenRaw)
		return JSONOAuthErrorResponse(res, http.StatusInternalServerError, "server_error", "Failed to refresh token")
	}

	refreshTokenChain, err := h.DB.GetOAuthRefreshTokenChainByID(ctx, refreshToken.ChainID)
	if err != nil {
		h.Logger.Error("Failed to get OAuth refresh token chain", "error", err, "chain_id", refreshToken.ChainID)
		return JSONOAuthErrorResponse(res, http.StatusInternalServerError, "server_error", "Failed to refresh token")
	}

	if refreshToken.UsedAt.IsSet {
		// Refresh token already used (rotation)
		h.Logger.Warn("Refresh token reuse detected", "refresh_token", refreshToken.ID, "user_id", refreshTokenChain.UserID)
		// Notify user via email about possible token theft
		// go func() {
		// 	if err := h.email.SendTokenTheftNotification(refreshToken.UserID); err != nil {
		// 		h.Logger.Error("Failed to send token theft notification", "error", err, "user_id", refreshToken.UserID)
		// 	}
		// }()

		return JSONOAuthErrorResponse(res, http.StatusBadRequest, "invalid_grant", "Invalid Token")
	}

	if time.Now().After(refreshToken.ExpiresAt) {
		h.Logger.Warn("Refresh token expired", "refresh_token", refreshToken.ID, "user_id", refreshTokenChain.UserID)
		return JSONOAuthErrorResponse(res, http.StatusBadRequest, "invalid_grant", "Invalid Token")
	}

	// Ensure the refresh token has offline_access scope
	if !slices.Contains(refreshTokenChain.Scopes, "offline_access") {
		h.Logger.Warn("Refresh token missing offline_access scope", "refresh_token", refreshToken.ID, "user_id", refreshTokenChain.UserID)
		return JSONOAuthErrorResponse(res, http.StatusBadRequest, "invalid_grant", "Invalid Token")
	}

	// Validate client
	clientID, err := uuid.Parse(clientIDRaw)
	if err != nil {
		h.Logger.Info("Invalid client ID format", "client_id", clientIDRaw)
		return JSONOAuthErrorResponse(res, http.StatusBadRequest, "invalid_grant", "Invalid Client Credentials")
	}

	if refreshTokenChain.ClientID != clientID {
		return JSONOAuthErrorResponse(res, http.StatusBadRequest, "invalid_grant", "Invalid Client Credentials")
	}

	client, err := h.DB.GetOAuthClientByID(ctx, clientID)
	if err != nil {
		h.Logger.Error("Failed to get OAuth client", "error", err, "client_id", clientID)
		return JSONOAuthErrorResponse(res, http.StatusBadRequest, "invalid_grant", "Invalid Client Credentials")
	}

	// For confidential clients, validate client secret
	if !client.IsPublic {
		if clientSecretRaw == "" {
			return JSONOAuthErrorResponse(res, http.StatusBadRequest, "invalid_client", "Invalid Client Credentials")
		}

		if client.Secret != clientSecretRaw {
			return JSONOAuthErrorResponse(res, http.StatusBadRequest, "invalid_client", "Invalid Client Credentials")
		}
	}

	// Scopes (todo not doing anything with this for now)
	var grantedScopes []string
	if scopeRaw != "" {
		requestedScopes := strings.FieldsSeq(scopeRaw)
		for rs := range requestedScopes {
			if slices.Contains(refreshTokenChain.Scopes, rs) {
				grantedScopes = append(grantedScopes, rs)
			}
		}
	}

	// Issue new access token
	newAccessTokenToken, err := util.GenerateRandomString(32)
	if err != nil {
		h.Logger.Error("Failed to generate random string", "error", err)
		return JSONOAuthErrorResponse(res, http.StatusInternalServerError, "server_error", "Failed to refresh token")
	}

	newAccessToken, err := h.DB.CreateOAuthAccessToken(ctx, database.CreateOAuthAccessTokenParams{
		Token:     newAccessTokenToken,
		ClientID:  refreshTokenChain.ClientID,
		UserID:    util.Some(refreshTokenChain.UserID),
		ExpiresAt: time.Now().Add(tokenTTL),
	})
	if err != nil {
		h.Logger.Error("Failed to create OAuth access token", "error", err)
		return JSONOAuthErrorResponse(res, http.StatusInternalServerError, "server_error", "Failed to refresh token")
	}

	// Invalidate (delete) the used refresh token for rotation
	if err := h.DB.UpdateOAuthRefreshToken(ctx, refreshToken.ID, database.UpdateOAuthRefreshTokenParams{
		UsedAt: util.Some(time.Now()),
	}); err != nil {
		h.Logger.Error("Failed to update used refresh token", "error", err, "refresh_token", refreshToken.ID)
		return JSONOAuthErrorResponse(res, http.StatusInternalServerError, "server_error", "Failed to refresh token")
	}

	// Issue a new refresh token
	newRefreshTokenToken, err := util.GenerateRandomString(32)
	if err != nil {
		h.Logger.Error("Failed to generate new refresh token", "error", err)
		return JSONOAuthErrorResponse(res, http.StatusInternalServerError, "server_error", "Failed to refresh token")
	}
	refreshTokenExpires := time.Now().Add(30 * 24 * time.Hour) // e.g. 30 days

	newRefreshToken, err := h.DB.CreateOAuthRefreshToken(ctx, database.CreateOAuthRefreshTokenParams{
		Token:     newRefreshTokenToken,
		ExpiresAt: refreshTokenExpires,
	})
	if err != nil {
		h.Logger.Error("Failed to create new refresh token", "error", err)
		return JSONOAuthErrorResponse(res, http.StatusInternalServerError, "server_error", "Failed to refresh token")
	}

	// Return successful response
	data := map[string]any{
		"access_token":  newAccessToken.Token,
		"expires_in":    time.Until(newAccessToken.ExpiresAt).Seconds(),
		"token_type":    "Bearer",
		"scope":         strings.Join(newAccessToken.Scopes, " "),
		"refresh_token": newRefreshToken.Token,
	}

	res.SetNoCacheHeaders()
	if err := res.SendJSON(data); err != nil {
		h.Logger.Error("Failed to encode JSON response", "error", err)
		return JSONOAuthErrorResponse(res, http.StatusInternalServerError, "server_error", "Failed to refresh token")
	}

	return nil
}

func ClientCredentialsFromRequest(r *http.Request) (string, string, error) {
	// Check Authorization header first
	authHeader := r.Header("Authorization")
	if authHeader != "" && strings.HasPrefix(authHeader, "Basic ") {
		encoded := strings.TrimPrefix(authHeader, "Basic ")
		decodedBytes, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return "", "", err
		}
		parts := strings.SplitN(string(decodedBytes), ":", 2)
		if len(parts) != 2 {
			return "", "", errors.New("invalid basic auth format")
		}
		return parts[0], parts[1], nil
	}

	// Fallback to form parameters
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	if clientID == "" || clientSecret == "" {
		return "", "", errors.New("missing client credentials")
	}
	return clientID, clientSecret, nil
}

func RedirectOAuthResponse(res *http.Response, redirectURI string, state string, errCode string) error {
	if redirectURI == "" { // cannot redirect, return JSON
		return JSONOAuthErrorResponse(res, http.StatusBadRequest, errCode, "")
	}

	// best effort build
	redirectURI += "?error=" + url.QueryEscape(errCode)
	if state != "" {
		redirectURI += "&state=" + url.QueryEscape(state)
	}

	res.SetStatus(http.StatusSeeOther)
	res.SetNoCacheHeaders()
	res.SetHeader("Location", redirectURI)
	return nil
}

// Helper functions for OAuth error formatting --------------------------------------------
func JSONOAuthErrorResponse(res *http.Response, code http.StatusCode, status string, description string) error {
	res.SetStatus(code)
	res.SetHeader("Content-Type", "application/json")
	res.SetNoCacheHeaders()
	return res.SendJSON(map[string]any{
		"error":             status,
		"error_description": description,
	})
}
