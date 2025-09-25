package web

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"hp/internal/config"
	"hp/internal/database"
	"hp/internal/session"
	"hp/internal/util"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/stripe/stripe-go/v82/webhook"
)

var (
	codeTTL  = 5 * time.Minute
	tokenTTL = 1 * time.Hour
)

type ApiHandler struct {
	logger       *slog.Logger
	db           *database.Database
	sessionStore *session.Store
}

func NewApiHandler(logger *slog.Logger, db *database.Database, sessionStore *session.Store) *ApiHandler {
	return &ApiHandler{
		logger:       logger,
		db:           db,
		sessionStore: sessionStore,
	}
}

func (h *ApiHandler) Healthy(w http.ResponseWriter, r *http.Request) error {
	// Check database connection
	if err := h.db.Ping(r.Context()); err != nil {
		h.logger.Error("Database connection failed", "error", err)
		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Database connection failed",
		})
	}

	// Additional health checks can be added here

	return JSONResponse(w, http.StatusOK, ApiResponse{
		Status:  APIResponseStatusSuccess,
		Message: "Service is healthy",
	})
}

// Authorize implements OAuth2 Authorization Code (with PKCE for public clients)
// GET /api/auth/v1/authorize?response_type=code&client_id=&redirect_uri=&scope=&state=&code_challenge=&code_challenge_method=
func (h *ApiHandler) Authorize(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	respTypeRaw := r.URL.Query().Get("response_type")
	clientIDStrRaw := r.URL.Query().Get("client_id")
	redirectURIRaw := r.URL.Query().Get("redirect_uri")
	scopeRaw := r.URL.Query().Get("scope")
	stateRaw := r.URL.Query().Get("state")
	codeChallengeRaw := r.URL.Query().Get("code_challenge")
	codeChallengeMethodRaw := r.URL.Query().Get("code_challenge_method")

	if respTypeRaw != "code" {
		h.logger.Info("Unsupported response type", "response_type", respTypeRaw)
		return RedirectOAuthResponse(w, redirectURIRaw, stateRaw, "unsupported_response_type")
	}

	// Validate client
	clientIDRaw, err := uuid.Parse(clientIDStrRaw)
	if err != nil {
		h.logger.Info("Invalid client ID format", "client_id", clientIDRaw)
		return JSONOAuthErrorResponse(w, http.StatusBadRequest, "invalid_client", "")
	}

	client, err := h.db.GetOAuthClientByID(ctx, clientIDRaw)
	if err != nil {
		h.logger.Info("Failed to get OAuth client", "error", err, "client_id", clientIDRaw)
		return JSONOAuthErrorResponse(w, http.StatusBadRequest, "invalid_client", "Unknown client_id")
	}

	if !slices.Contains(client.RedirectURIs, redirectURIRaw) {
		h.logger.Info("Invalid redirect URI", "redirect_uri", redirectURIRaw, "client_id", clientIDRaw)
		return JSONOAuthErrorResponse(w, http.StatusBadRequest, "invalid_redirect_uri", "Redirect not registered")
	}

	// Validate PKCE (must provide challenge)
	if codeChallengeRaw == "" {
		h.logger.Info("Missing code challenge for public client", "client_id", clientIDRaw)
		return JSONOAuthErrorResponse(w, http.StatusBadRequest, "invalid_request", "Missing code challenge")
	}
	if codeChallengeMethodRaw != "S256" && codeChallengeMethodRaw != "plain" && codeChallengeMethodRaw != "" { // allow empty -> treat as plain per RFC leniency
		h.logger.Info("Unsupported code challenge method", "method", codeChallengeMethodRaw, "client_id", clientIDRaw)
		return JSONOAuthErrorResponse(w, http.StatusBadRequest, "invalid_request", "Unsupported code challenge method")
	}

	// Scopes
	var requestedScopes []string
	if scopeRaw != "" {
		requestedScopes = strings.Fields(scopeRaw)
	}

	var grantedScopes []string
	allowedScopes := []string{"offline_access"}
	for _, rs := range requestedScopes {
		if slices.Contains(allowedScopes, rs) {
			grantedScopes = append(grantedScopes, rs)
		}
	}

	// Get user ID from session
	sess, err := h.sessionStore.Get(ctx, r)
	if err != nil {
		return JSONOAuthErrorResponse(w, http.StatusInternalServerError, "server_error", "Session error")
	}

	if !sess.UserID.Some {
		return Redirect(w, r, "/login?return_to="+url.QueryEscape(r.URL.String()), http.StatusFound)
	}

	user, err := h.db.GetUserByID(ctx, sess.UserID.Data)
	if err != nil {
		if errors.Is(err, database.ErrUserNotFound) {
			sess.UserID = util.None[uuid.UUID]()
			if err := h.sessionStore.Save(ctx, w, sess); err != nil {
				h.logger.Error("Failed to save session", "error", err)
			}
			return Redirect(w, r, "/login?return_to="+url.QueryEscape(r.URL.String()), http.StatusFound)
		}
		h.logger.Error("Failed to get user", "error", err, "user_id", sess.UserID.Data)
		return JSONOAuthErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to get user")
	}

	// Create authorization code
	code, err := util.RandomString(32)
	if err != nil {
		h.logger.Error("Failed to generate authorization code", "error", err)
		return oauthErrorRedirect(w, r, redirectURIRaw, stateRaw, "server_error")
	}

	oauthCode, err := h.db.CreateOAuthAuthorizationCode(ctx, database.CreateOAuthAuthorizationCodeParams{
		Token:               code,
		ClientID:            client.ID,
		UserID:              user.ID,
		RedirectURI:         redirectURIRaw,
		CodeChallenge:       util.Some(codeChallengeRaw),
		CodeChallengeMethod: util.Some(codeChallengeMethodRaw),
		Scopes:              grantedScopes,
		ExpiresAt:           time.Now().Add(codeTTL),
	})

	if err != nil {
		h.logger.Error("Failed to create OAuth auth code", "error", err)
		return oauthErrorRedirect(w, r, redirectURIRaw, stateRaw, "server_error")
	}

	// Build redirect URL
	redirectURI := redirectURIRaw + "?code=" + url.QueryEscape(oauthCode.Token)
	if stateRaw != "" {
		redirectURI += "&state=" + url.QueryEscape(stateRaw)
	}

	return Redirect(w, r, redirectURI, http.StatusFound)
}

func oauthErrorRedirect(w http.ResponseWriter, r *http.Request, redirectURI, state, errCode string) error {
	// Build error redirect URL
	errorRedirectURI := redirectURI + "?error=" + url.QueryEscape(errCode)
	if state != "" {
		errorRedirectURI += "&state=" + url.QueryEscape(state)
	}

	return Redirect(w, r, errorRedirectURI, http.StatusFound)
}

// OAuthToken issues access token for authorization_code grant with PKCE
// POST form: grant_type=authorization_code&code=&redirect_uri=&client_id=&code_verifier=
func (h *ApiHandler) OAuthToken(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	grantTypeRaw := r.FormValue("grant_type")

	// Refresh token grant
	if grantTypeRaw == "refresh_token" {
		refreshTokenTokenRaw := r.FormValue("refresh_token")
		clientIDRaw := r.FormValue("client_id")
		scopeRaw := r.FormValue("scope")

		// Validate refresh token
		refreshToken, err := h.db.GetOAuthRefreshTokenByToken(ctx, refreshTokenTokenRaw)
		if err != nil {
			if errors.Is(err, database.ErrOAuthRefreshTokenNotFound) {
				return JSONOAuthErrorResponse(w, http.StatusBadRequest, "invalid_grant", "Invalid refresh token")
			}

			h.logger.Error("Failed to get OAuth refresh token", "error", err, "refresh_token", refreshTokenTokenRaw)
			return JSONOAuthErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to validate refresh token")
		}

		refreshTokenChain, err := h.db.GetOAuthRefreshTokenChainByID(ctx, refreshToken.ChainID)
		if err != nil {
			h.logger.Error("Failed to get OAuth refresh token chain", "error", err, "chain_id", refreshToken.ChainID)
			return JSONOAuthErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to get refresh token chain")
		}

		if refreshToken.UsedAt.Some {
			// Check if refresh token exceeds grace period (e.g. 1 minutes)
			if time.Since(refreshToken.UsedAt.Data) > time.Minute {
				// Refresh token already used (rotation)
				h.logger.Warn("Refresh token reuse detected", "refresh_token", refreshToken.ID, "user_id", refreshTokenChain.UserID)
				// Notify user via email about possible token theft
				// go func() {
				// 	if err := h.email.SendTokenTheftNotification(refreshToken.UserID); err != nil {
				// 		h.logger.Error("Failed to send token theft notification", "error", err, "user_id", refreshToken.UserID)
				// 	}
				// }()

				return JSONOAuthErrorResponse(w, http.StatusBadRequest, "invalid_grant", "Refresh token already used")
			}
		}

		if time.Now().After(refreshToken.ExpiresAt) {
			h.logger.Warn("Refresh token expired", "refresh_token", refreshToken.ID, "user_id", refreshTokenChain.UserID)
			return JSONOAuthErrorResponse(w, http.StatusBadRequest, "invalid_grant", "Refresh token expired")
		}

		// Ensure the refresh token has offline_access scope
		if !slices.Contains(refreshTokenChain.Scopes, "offline_access") {
			return JSONOAuthErrorResponse(w, http.StatusBadRequest, "invalid_grant", "Refresh token missing offline_access scope")
		}

		// Validate client
		clientID, err := uuid.Parse(clientIDRaw)
		if err != nil {
			h.logger.Info("Invalid client ID format", "client_id", clientIDRaw)
			return JSONOAuthErrorResponse(w, http.StatusBadRequest, "invalid_client", "")
		}

		if refreshTokenChain.ClientID != clientID {
			return JSONOAuthErrorResponse(w, http.StatusBadRequest, "invalid_grant", "Client ID mismatch")
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
		newAccessTokenToken, err := util.RandomString(32)
		if err != nil {
			h.logger.Error("Failed to generate random string", "error", err)
			return JSONOAuthErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to generate access token")
		}

		newAccessToken, err := h.db.CreateOAuthAccessToken(ctx, database.CreateOAuthAccessTokenParams{
			Token:     newAccessTokenToken,
			ClientID:  refreshTokenChain.ClientID,
			UserID:    refreshTokenChain.UserID,
			ExpiresAt: time.Now().Add(tokenTTL),
		})
		if err != nil {
			h.logger.Error("Failed to create OAuth access token", "error", err)
			return JSONOAuthErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to create access token")
		}

		// Invalidate (delete) the used refresh token for rotation
		if err := h.db.UpdateOAuthRefreshToken(ctx, refreshToken.ID, database.UpdateOAuthRefreshTokenParams{
			UsedAt: util.Optional[time.Time]{Data: time.Now()},
		}); err != nil {
			h.logger.Error("Failed to update used refresh token", "error", err, "refresh_token", refreshToken.ID)
			return JSONOAuthErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to update refresh token")
		}

		// Issue a new refresh token
		newRefreshTokenToken, err := util.RandomString(32)
		if err != nil {
			h.logger.Error("Failed to generate new refresh token", "error", err)
			return JSONOAuthErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to generate refresh token")
		}
		refreshTokenExpires := time.Now().Add(30 * 24 * time.Hour) // e.g. 30 days

		newRefreshToken, err := h.db.CreateOAuthRefreshToken(ctx, database.CreateOAuthRefreshTokenParams{
			Token:     newRefreshTokenToken,
			ExpiresAt: refreshTokenExpires,
		})
		if err != nil {
			h.logger.Error("Failed to create new refresh token", "error", err)
			return JSONOAuthErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to create refresh token")
		}

		// Return successful response
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")

		data := map[string]any{
			"access_token":  newAccessToken.Token,
			"expires_in":    time.Until(newAccessToken.ExpiresAt).Seconds(),
			"token_type":    "Bearer",
			"scope":         strings.Join(newAccessToken.Data.Scopes, " "),
			"refresh_token": newRefreshToken.Token,
		}

		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(data); err != nil {
			h.logger.Error("Failed to encode JSON response", "error", err)
			return JSONOAuthErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to encode response")
		}

		return nil
	}

	// Authorization code grant
	if grantTypeRaw != "authorization_code" {
		return JSONOAuthErrorResponse(w, http.StatusBadRequest, "unsupported_grant_type", "")
	}

	codeRaw := r.FormValue("code")
	redirectURIRaw := r.FormValue("redirect_uri")
	clientIDStrRaw := r.FormValue("client_id")
	verifierRaw := r.FormValue("code_verifier")
	clientSecretRaw := r.FormValue("client_secret")

	// Validate client
	clientIDRaw, err := uuid.Parse(clientIDStrRaw)
	if err != nil {
		h.logger.Error("Invalid client ID format", "client_id", clientIDStrRaw)
		return JSONOAuthErrorResponse(w, http.StatusBadRequest, "invalid_client", "")
	}

	client, err := h.db.GetOAuthClientByID(ctx, clientIDRaw)
	if err != nil {
		h.logger.Error("Failed to get OAuth client", "error", err, "client_id", clientIDRaw)
		return JSONOAuthErrorResponse(w, http.StatusBadRequest, "invalid_client", "")
	}

	if !slices.Contains(client.RedirectURIs, redirectURIRaw) {
		h.logger.Info("Invalid redirect URI", "redirect_uri", redirectURIRaw, "client_id", clientIDRaw)
		return JSONOAuthErrorResponse(w, http.StatusBadRequest, "invalid_redirect_uri", "")
	}

	// Exchange code for access token
	code, err := h.db.GetOAuthAuthorizationCodeByCode(ctx, codeRaw)
	if err != nil {
		h.logger.Debug("Failed to get OAuth authorization code", "error", err, "code", codeRaw)
		return JSONOAuthErrorResponse(w, http.StatusBadRequest, "invalid_grant", "Invalid authorization code")
	}

	// Mark code as used
	if err := h.db.UpdateOAuthAuthorizationCode(ctx, code.ID, database.UpdateOAuthAuthorizationCodeParams{
		UsedAt: util.Some(time.Now()),
	}); err != nil {
		h.logger.Error("Failed to update OAuth authorization code", "error", err, "code", code.Token)
		return JSONOAuthErrorResponse(w, http.StatusInternalServerError, "server_error", "Failed to update authorization code")
	}

	if code.ClientID != client.ID {
		return JSONOAuthErrorResponse(w, http.StatusBadRequest, "invalid_grant", "Client ID mismatch")
	}
	if code.RedirectURI != redirectURIRaw {
		return JSONOAuthErrorResponse(w, http.StatusBadRequest, "invalid_grant", "Redirect URI mismatch")
	}
	if time.Now().After(code.ExpiresAt) {
		return JSONOAuthErrorResponse(w, http.StatusBadRequest, "invalid_grant", "Authorization code expired")
	}

	// PKCE validation
	if !code.CodeChallenge.Some {
		return JSONOAuthErrorResponse(w, http.StatusBadRequest, "invalid_grant", "Missing code challenge")
	}

	if !code.CodeChallengeMethod.Some {
		return JSONOAuthErrorResponse(w, http.StatusBadRequest, "invalid_grant", "Missing code challenge method")
	}

	// Only S256 is supported for now
	if code.CodeChallengeMethod.Data != "S256" {
		return JSONOAuthErrorResponse(w, http.StatusBadRequest, "invalid_grant", "Unsupported code challenge method")
	}

	if verifierRaw == "" {
		return JSONOAuthErrorResponse(w, http.StatusBadRequest, "invalid_grant", "Missing code verifier")
	}

	// compute S256 hash of verifier
	imported := sha256.Sum256([]byte(verifierRaw))
	computed := base64.RawURLEncoding.EncodeToString(imported[:])
	if computed != code.CodeChallenge.Data {
		return JSONOAuthErrorResponse(w, http.StatusBadRequest, "invalid_grant", "Code verifier mismatch")
	}

	// For confidential clients, validate client secret
	if clientSecretRaw == "" {
		return JSONOAuthErrorResponse(w, http.StatusBadRequest, "invalid_client", "Missing client secret")
	}

	if client.Secret != clientSecretRaw {
		return JSONOAuthErrorResponse(w, http.StatusBadRequest, "invalid_client", "Invalid client secret")
	}
	// Issue access token
	token, err := util.RandomString(32)
	if err != nil {
		h.logger.Error("Failed to generate random string", "error", err)
		return JSONOAuthErrorResponse(w, http.StatusInternalServerError, "server_error", "")
	}

	accessToken, err := h.db.CreateOAuthAccessToken(ctx, database.CreateOAuthAccessTokenParams{
		Token:     token,
		ClientID:  client.ID,
		Data:      database.OAuthAccessTokenData{Scopes: code.Scopes},
		ExpiresAt: time.Now().Add(tokenTTL),
		UserID:    code.UserID,
	})
	if err != nil {
		h.logger.Error("Failed to create OAuth access token", "error", err)
		return JSONOAuthErrorResponse(w, http.StatusInternalServerError, "server_error", "")
	}

	responseBody := map[string]any{
		"access_token": accessToken.Token,
		"token_type":   "Bearer",
		"expires_in":   int(time.Until(accessToken.ExpiresAt).Seconds()),
		"scope":        strings.Join(accessToken.Data.Scopes, " "),
	}

	// If offline_access scope was granted, issue refresh token as well
	if slices.Contains(code.Scopes, "offline_access") {
		// Issue refresh token as well
		refreshTokenToken, err := util.RandomString(32)
		if err != nil {
			h.logger.Error("Failed to generate refresh token", "error", err)
			return JSONOAuthErrorResponse(w, http.StatusInternalServerError, "server_error", "")
		}
		refreshTokenExpires := time.Now().Add(30 * 24 * time.Hour) // e.g. 30 days

		refreshTokenChain, err := h.db.CreateOAuthRefreshTokenChain(ctx, database.CreateOAuthRefreshTokenChainParams{
			ClientID: client.ID,
			UserID:   code.UserID,
			Scopes:   code.Scopes,
		})
		if err != nil {
			h.logger.Error("Failed to create OAuth refresh token chain", "error", err)
			return JSONOAuthErrorResponse(w, http.StatusInternalServerError, "server_error", "")
		}

		refreshToken, err := h.db.CreateOAuthRefreshToken(ctx, database.CreateOAuthRefreshTokenParams{
			Token:     refreshTokenToken,
			ChainID:   refreshTokenChain.ID,
			ExpiresAt: refreshTokenExpires,
			UsedAt:    util.None[time.Time](),
		})
		if err != nil {
			h.logger.Error("Failed to create OAuth refresh token", "error", err)
			return JSONOAuthErrorResponse(w, http.StatusInternalServerError, "server_error", "")
		}

		responseBody["refresh_token"] = refreshToken.Token
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(responseBody); err != nil {
		h.logger.Error("Failed to encode JSON response", "error", err)
		return JSONOAuthErrorResponse(w, http.StatusInternalServerError, "server_error", "")
	}
	return nil
}

// Helper functions for OAuth error formatting --------------------------------------------
func JSONOAuthErrorResponse(w http.ResponseWriter, status int, code string, desc string) error {
	w.WriteHeader(status)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_, err := w.Write([]byte(`{"error":"` + code + `","error_description":"` + desc + `"}`))
	return err
}

func RedirectOAuthResponse(w http.ResponseWriter, redirectURI string, state string, errCode string) error {
	if redirectURI == "" { // cannot redirect, return JSON
		return JSONOAuthErrorResponse(w, http.StatusBadRequest, errCode, "")
	}

	// best effort build
	redirectURI += "?error=" + url.QueryEscape(errCode)
	if state != "" {
		redirectURI += "&state=" + url.QueryEscape(state)
	}

	w.WriteHeader(http.StatusFound)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Location", redirectURI)
	return nil
}

func (h *ApiHandler) StripeWebhook(w http.ResponseWriter, r *http.Request) error {
	// Handle Stripe webhook events
	// This is a placeholder for actual webhook handling logic
	endpointSecret := "whsec_r0fySCr2f4JP6Sm2lXYK8HXJkRApaRhC"
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.logger.Error("Failed to read webhook request body", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": "Invalid request body",
		})
	}
	event, err := webhook.ConstructEvent(body, r.Header.Get("Stripe-Signature"), endpointSecret)
	if err != nil {
		h.logger.Error("Failed to construct webhook event", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": "Invalid webhook payload",
		})
	}
	// Process the event based on its type
	switch event.Type {
	case "customer.subscription.created":
		// Handle successful customer subscription creation
		h.logger.Info("Customer subscription created", "event", event)
	case "customer.subscription.updated":
		// Handle customer subscription updated
		h.logger.Info("Customer subscription updated", "event", event)
	case "customer.subscription.deleted":
		// Handle customer subscription deletion
		h.logger.Info("Customer subscription deleted", "event", event)
	case "invoice.payment_succeeded":
		// Handle successful invoice payment
		h.logger.Info("Invoice payment succeeded", "event", event)
	case "invoice.payment_failed":
		// Handle failed invoice payment
		h.logger.Info("Invoice payment failed", "event", event)
	default:
		h.logger.Info("Unhandled event type", "type", event.Type)
	}

	// Respond with 200 OK to acknowledge receipt of the event
	w.WriteHeader(http.StatusOK)
	return JSONResponse(w, http.StatusOK, ApiResponse{
		Status:  APIResponseStatusSuccess,
		Message: "Webhook received successfully",
	})
}

func (h *ApiHandler) ListClients(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	userID := ctx.Value(config.UserIDContextKey).(uuid.UUID)

	clients, err := h.db.ListOAuthClients(ctx, database.ListOAuthClientsParams{
		OwnerID: util.Some(userID),
	})
	if err != nil {
		h.logger.Error("Failed to list OAuth clients", "error", err)
		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Failed to list OAuth clients",
		})
	}

	clientsResponse := make([]map[string]any, len(clients))
	for i, client := range clients {
		clientsResponse[i] = map[string]any{
			"id":            client.ID,
			"name":          client.Name,
			"redirect_uris": client.RedirectURIs,
			"owner_id":      client.OwnerID,
			"created_at":    client.CreatedAt.Unix(),
			"updated_at":    client.UpdatedAt.Unix(),
		}
	}

	return JSONResponse(w, http.StatusOK, ApiResponse{
		Status: APIResponseStatusSuccess,
		Data:   clientsResponse,
	})
}

type CreateClientRequest struct {
	Name          string   `json:"name"`
	RedirectURIs  []string `json:"redirect_uris"`
	Public        bool     `json:"public"`
	AllowedScopes []string `json:"allowed_scopes"`
}

func (h *ApiHandler) CreateClient(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	userID := ctx.Value(config.UserIDContextKey).(uuid.UUID)

	var requestBody CreateClientRequest
	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		h.logger.Error("Failed to parse request body", "error", err)
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Invalid request body",
		})
	}

	secret, err := util.RandomString(32)
	if err != nil {
		h.logger.Error("Failed to generate client secret", "error", err)
		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Failed to generate client secret",
		})
	}

	client, err := h.db.CreateOAuthClient(ctx, database.CreateOAuthClientParams{
		Name:         requestBody.Name,
		RedirectURIs: requestBody.RedirectURIs,
		OwnerID:      userID,
		Secret:       secret,
	})
	if err != nil {
		h.logger.Error("Failed to create OAuth client", "error", err)
		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Failed to create OAuth client",
		})
	}

	return JSONResponse(w, http.StatusCreated, ApiResponse{
		Status: APIResponseStatusSuccess,
		Data: map[string]any{
			"id":            client.ID,
			"name":          client.Name,
			"redirect_uris": client.RedirectURIs,
			"owner_id":      client.OwnerID,
			"client_secret": client.Secret, // Show secret only at creation time
			"created_at":    client.CreatedAt.Unix(),
			"updated_at":    client.UpdatedAt.Unix(),
		},
	})
}

func (h *ApiHandler) GetClient(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	clientIDStrRaw := ctx.Value("client_id").(string)
	if clientIDStrRaw == "" {
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Missing client ID",
		})
	}

	clientIDRaw, err := uuid.Parse(clientIDStrRaw)
	if err != nil {
		h.logger.Error("Invalid client ID format", "client_id", clientIDStrRaw)
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Invalid client ID format",
		})
	}

	client, err := h.db.GetOAuthClientByID(ctx, clientIDRaw)
	if err != nil {
		h.logger.Error("Failed to get OAuth client", "error", err)

		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Failed to get OAuth client",
		})
	}

	return JSONResponse(w, http.StatusOK, ApiResponse{
		Status: APIResponseStatusSuccess,
		Data: map[string]any{
			"id":            client.ID,
			"name":          client.Name,
			"redirect_uris": client.RedirectURIs,
			"owner_id":      client.OwnerID,
			"created_at":    client.CreatedAt.Unix(),
			"updated_at":    client.UpdatedAt.Unix(),
		},
	})
}

func (h *ApiHandler) DeleteClient(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	clientIDStrRaw := ctx.Value("client_id").(string)
	if clientIDStrRaw == "" {
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Missing client ID",
		})
	}

	clientIDRaw, err := uuid.Parse(clientIDStrRaw)
	if err != nil {
		h.logger.Error("Invalid client ID format", "client_id", clientIDStrRaw)
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Invalid client ID format",
		})
	}

	if err := h.db.DeleteOAuthClientByID(ctx, clientIDRaw); err != nil {
		h.logger.Error("Failed to delete OAuth client", "error", err)
		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Failed to delete OAuth client",
		})
	}

	return JSONResponse(w, http.StatusOK, ApiResponse{
		Status:  APIResponseStatusSuccess,
		Message: "OAuth client deleted successfully",
	})
}

func (h *ApiHandler) ListFiles(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	userID := ctx.Value(config.UserIDContextKey).(uuid.UUID)

	// fileIDs, err := h.authorization.ListCanReadFiles(c.Context(), userID)
	// if err != nil {
	// 	h.logger.Error("Failed to list readable files", "error", err, "user_id", userID)
	// 	return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
	// 		"status":  "error",
	// 		"message": "Failed to list readable files",
	// 	})
	// }

	// For now, list all files owned by the user
	// In the future, we should allow filter by shared
	// params.AllowedIDs = fileIDs

	files, err := h.db.ListFiles(ctx, database.ListFilesParams{
		OwnerID: util.Some(userID),
	})
	if err != nil {
		h.logger.Error("Failed to list files", "error", err, "user_id", userID)
		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Failed to list files",
		})
	}

	filesResponse := make([]map[string]any, 0, len(files))
	for _, file := range files {
		filesResponse = append(filesResponse, map[string]any{
			"id":            file.ID,
			"name":          file.Name,
			"mime_type":     file.MimeType,
			"size_bytes":    file.SizeBytes,
			"last_modified": file.UpdatedAt.Unix(),
		})
	}

	return JSONResponse(w, http.StatusOK, ApiResponse{
		Status: APIResponseStatusSuccess,
		Data:   filesResponse,
	})
}

type CreateFileRequest struct {
	Name     string                   `json:"name"`
	MimeType string                   `json:"mime_type"`
	Parent   util.Optional[uuid.UUID] `json:"parent"` // Optional parent folder ID
}

func (h *ApiHandler) CreateFile(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	userID := ctx.Value(config.UserIDContextKey).(uuid.UUID)

	// Parse the request body into a File struct
	var requestBody CreateFileRequest
	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		h.logger.Error("Failed to parse request body", "error", err)
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Invalid request body",
		})
	}

	// For now we only support creating folder through this endpoint
	// In the future, files should also be supported
	if requestBody.MimeType != "application/askfrank.folder" {
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Only folder creation is supported",
		})
	}

	file, err := h.db.CreateFile(ctx, database.CreateFileParams{
		OwnerID:   userID,
		ParentID:  requestBody.Parent,
		Name:      requestBody.Name,
		MimeType:  requestBody.MimeType,
		S3Key:     util.None[string](),
		SizeBytes: 0,
	})
	if err != nil {
		h.logger.Error("Failed to create file", "error", err, "user_id", userID)
		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Failed to create file",
		})
	}

	return JSONResponse(w, http.StatusCreated, ApiResponse{
		Status:  APIResponseStatusSuccess,
		Message: "File created successfully",
		Data: map[string]any{
			"id":            file.ID,
			"name":          file.Name,
			"mime_type":     file.MimeType,
			"size_bytes":    file.SizeBytes,
			"last_modified": file.UpdatedAt.Unix(),
		},
	})
}

func (h *ApiHandler) GetFile(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	// userID := ctx.Value(config.UserIDContextKey).(uuid.UUID)

	fileIDStr := r.PathValue("file_id")
	if fileIDStr == "" {
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "File ID is required",
		})
	}

	fileID, err := uuid.Parse(fileIDStr)
	if err != nil {
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Invalid file ID",
		})
	}

	// if ok, err := h.authorization.CanReadFile(c.Context(), userID, fileID); !ok {
	// 	h.logger.Error("User does not have permission to read file", "user_id", userID, "file_id", fileID, "error", err)
	// 	return util.FormatResponse(c, fiber.StatusForbidden, util.ApiResponse{
	// 		Status:  util.APIResponseStatusError,
	// 		Message: "You do not have permission to read this file",
	// 	})
	// }

	file, err := h.db.GetFileByID(ctx, fileID)
	if err != nil {
		h.logger.Error("Failed to get file", "error", err, "file_id", fileID)
		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Failed to get file",
		})
	}

	return JSONResponse(w, http.StatusOK, ApiResponse{
		Status: APIResponseStatusSuccess,
		Data: map[string]any{
			"id":            file.ID,
			"name":          file.Name,
			"mime_type":     file.MimeType,
			"size_bytes":    file.SizeBytes,
			"last_modified": file.UpdatedAt.Unix(),
		},
	})
}

func (h *ApiHandler) DeleteFile(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	// userID := c.Locals("user_id").(uuid.UUID)

	fileID := r.PathValue("file_id")
	if fileID == "" {
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "File ID is required",
		})
	}

	// todo check permission
	// if err := h.authorization.CanDeleteFile(c.Context(), uuid.Nil, uuid.MustParse(fileID)); err != nil {
	// 	h.logger.Error("User does not have permission to delete file", "error", err, "file_id", fileID)
	// 	return h.formatResponse(c, fiber.StatusForbidden, ApiResponse{
	// 		Status:  APIResponseStatusError,
	// 		Message: "You do not have permission to delete this file",
	// 	})
	// }

	if err := h.db.DeleteFileByID(ctx, uuid.MustParse(fileID)); err != nil {
		h.logger.Error("Failed to delete file", "error", err, "file_id", fileID)
		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Failed to delete file",
		})
	}

	// if err := h.authorization.RemoveFileReader(c.Context(), uuid.Nil, uuid.MustParse(fileID)); err != nil {
	// 	h.logger.Error("Failed to remove file reader permission", "error", err, "file_id", fileID)
	// 	// Not returning error to user since the file deletion was successful
	// }

	return JSONResponse(w, http.StatusOK, ApiResponse{
		Status:  APIResponseStatusSuccess,
		Message: "File deleted successfully",
	})
}

// func (h *ApiHandler) UploadFile(w http.ResponseWriter, r *http.Request) error {
// 	ctx := r.Context()
// 	userID := ctx.Value(config.UserIDContextKey).(uuid.UUID)

// 	// Get folder ID from form data (optional)
// 	var folderID util.Optional[uuid.UUID]
// 	if folderIDStr := r.FormValue("folder_id"); folderIDStr != "" {
// 		id, err := uuid.Parse(folderIDStr)
// 		if err != nil {
// 			return JSONResponse(w, http.StatusBadRequest, ApiResponse{
// 				Status:  APIResponseStatusError,
// 				Message: "Invalid folder ID",
// 			})
// 		}
// 		folderID = util.Some(id)
// 	}

// 	// Parse multipart form
// 	form, err := r.ParseMultipartForm(10 << 20) // 10 MB limit
// 	if err != nil {
// 		h.logger.Error("Failed to parse multipart form", "error", err)
// 		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Failed to parse multipart form",
// 		})
// 	}

// 	files := form.File["files"]
// 	if len(files) == 0 {
// 		return util.FormatResponse(c, fiber.StatusBadRequest, util.ApiResponse{
// 			Status:  util.APIResponseStatusError,
// 			Message: "No files provided",
// 		})
// 	}

// 	// Create uploads directory if it doesn't exist
// 	uploadDir := "uploads"
// 	if err := os.MkdirAll(uploadDir, 0755); err != nil {
// 		h.logger.Error("Failed to create upload directory", "error", err)
// 		return util.FormatResponse(c, fiber.StatusInternalServerError, util.ApiResponse{
// 			Status:  util.APIResponseStatusError,
// 			Message: "Failed to create upload directory",
// 		})
// 	}

// 	var uploadedFiles []fiber.Map

// 	for _, fileHeader := range files {
// 		// Generate unique filename
// 		ext := filepath.Ext(fileHeader.Filename)
// 		baseFilename := strings.TrimSuffix(fileHeader.Filename, ext)
// 		uniqueFilename := baseFilename + "_" + uuid.New().String() + ext
// 		filePath := filepath.Join(uploadDir, uniqueFilename)

// 		// Save file to disk
// 		if err := c.SaveFile(fileHeader, filePath); err != nil {
// 			h.logger.Error("Failed to save file", "error", err, "filename", fileHeader.Filename)
// 			continue
// 		}

// 		// Determine MIME type
// 		mimeType := fileHeader.Header.Get("Content-Type")
// 		if mimeType == "" {
// 			mimeType = "application/octet-stream"
// 		}

// 		// Create file record in database
// 		file, err := h.db.CreateFile(c.Context(), database.CreateFileParams{
// 			OwnerID:   userID,
// 			ParentID:  folderID,
// 			Name:      fileHeader.Filename,
// 			MimeType:  mimeType,
// 			S3Key:     util.None[string](),
// 			Path:      util.Some(filePath),
// 			SizeBytes: fileHeader.Size,
// 		})
// 		if err != nil {
// 			h.logger.Error("Failed to create file record", "error", err, "filename", fileHeader.Filename)
// 			// Try to delete the saved file
// 			os.Remove(filePath)
// 			continue
// 		}

// 		// if err := h.authorization.AddFileReader(c.Context(), userID, file.ID); err != nil {
// 		// 	h.logger.Error("Failed to add file reader permission", "error", err, "user_id", userID, "file_id", file.ID)
// 		// 	// Try to delete the saved file and database record
// 		// 	os.Remove(filePath)
// 		// 	if err := h.db.DeleteFile(c.Context(), file.ID); err != nil {
// 		// 		h.logger.Error("Failed to delete file record after permission error", "error", err, "file_id", file.ID)
// 		// 	}
// 		// 	continue
// 		// }

// 		uploadedFiles = append(uploadedFiles, fiber.Map{
// 			"id":       file.ID,
// 			"name":     file.Name,
// 			"size":     file.SizeBytes,
// 			"mimeType": file.MimeType,
// 		})
// 	}

// 	if len(uploadedFiles) == 0 {
// 		h.logger.Error("No files were uploaded successfully")
// 		return util.FormatResponse(c, fiber.StatusInternalServerError, util.ApiResponse{
// 			Status:  util.APIResponseStatusError,
// 			Message: "Failed to upload any files",
// 		})
// 	}

// 	return util.FormatResponse(c, fiber.StatusCreated, util.ApiResponse{
// 		Status: util.APIResponseStatusSuccess,
// 		Data:   uploadedFiles,
// 	})
// }

func (h *ApiHandler) DownloadFile(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	// userID := c.Locals("user_id").(uuid.UUID)

	fileIDStr := r.PathValue("file_id")
	fileID, err := uuid.Parse(fileIDStr)
	if err != nil {
		h.logger.Error("Invalid file ID", "error", err)
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Invalid file ID",
		})
	}

	// todo check file access

	file, err := h.db.GetFileByID(ctx, fileID)
	if err != nil {
		if err == database.ErrFileNotFound {
			h.logger.Error("File not found", "file_id", fileID)
			return JSONResponse(w, http.StatusNotFound, ApiResponse{
				Status:  APIResponseStatusError,
				Message: "File not found",
			})
		}
		h.logger.Error("Failed to retrieve file", "error", err, "file_id", fileID)
		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Failed to retrieve file",
		})
	}

	// Serve the file
	if err := Download(w, r, file.Path.Data, file.Name); err != nil {
		h.logger.Error("Failed to serve file", "error", err, "file_id", fileID)
		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Failed to serve file",
		})
	}

	return nil
}

type APIShareFileRequest struct {
	Email string `json:"email"`
}

func (h *ApiHandler) ShareFile(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	// userID := c.Locals("user_id").(uuid.UUID)

	// Get file ID from URL parameter
	fileIDStr := r.PathValue("file_id")
	fileID, err := uuid.Parse(fileIDStr)
	if err != nil {
		h.logger.Error("Invalid file ID", "error", err)
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Invalid file ID",
		})
	}

	// Check if the user has permission to share the file
	// if ok, err := h.authorization.CanShareFile(c.Context(), userID, fileID); !ok {
	// 	h.logger.Error("User does not have permission to share file", "user_id", userID, "file_id", fileID, "error", err)
	// 	return h.formatResponse(c, fiber.StatusForbidden, ApiResponse{
	// 		Status:  APIResponseStatusError,
	// 		Message: "You do not have permission to share this file",
	// 	})
	// }

	var req ShareFileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Error("Failed to parse request body", "error", err)
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Invalid request",
		})
	}

	// Check if the file exists
	file, err := h.db.GetFileByID(ctx, fileID)
	if err != nil {
		if err == database.ErrFileNotFound {
			h.logger.Error("File not found", "file_id", fileID)
			return JSONResponse(w, http.StatusNotFound, ApiResponse{
				Status:  APIResponseStatusError,
				Message: "File not found",
			})
		}

		h.logger.Error("Failed to retrieve file", "error", err, "file_id", fileID)
		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Failed to retrieve file",
		})
	}

	targetUser, err := h.db.GetUserByEmail(ctx, req.Email)
	if err != nil {
		if err == database.ErrUserNotFound {
			h.logger.Error("User not found", "email", req.Email)
			return JSONResponse(w, http.StatusNotFound, ApiResponse{
				Status:  APIResponseStatusError,
				Message: "User not found",
			})
		}

		h.logger.Error("Failed to retrieve user", "error", err, "email", req.Email)
		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Failed to retrieve user",
		})
	}

	// Check if the requesting user has permission to share the file
	// if ok, err := h.authorization.CanShareFile(c.Context(), userID, fileID); !ok {
	// 	h.logger.Error("User does not have permission to share file", "user_id", userID, "file_id", fileID, "error", err)
	// 	return h.formatResponse(c, fiber.StatusForbidden, ApiResponse{
	// 		Status:  APIResponseStatusError,
	// 		Message: "You do not have permission to share this file",
	// 	})
	// }

	if _, err = h.db.CreateFileShare(ctx, database.CreateFileShareParams{
		FileID:           file.ID,
		SharedWithUserID: targetUser.ID,
		Permission:       "read", // For simplicity, only "read" permission is supported now
	}); err != nil {
		h.logger.Error("Failed to create file share", "error", err, "file_id", file.ID, "shared_with_user_id", targetUser.ID)
		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Failed to share file",
		})
	}

	// if err := h.authorization.AddFileReader(c.Context(), targetUser.ID, file.ID); err != nil {
	// 	h.logger.Error("Failed to add file reader permission", "error", err, "user_id", targetUser.ID, "file_id", file.ID)
	// 	return util.FormatResponse(c, fiber.StatusInternalServerError, util.ApiResponse{
	// 		Status:  util.APIResponseStatusError,
	// 		Message: "Failed to share file",
	// 	})
	// }

	// Optionally, send notification email to the target user
	// go func() {
	// 	if err := h.emailer.SendFileSharedEmail(targetUser.Email, file.Name); err != nil {
	// 		h.logger.Error("Failed to send file shared email", "error", err, "email", targetUser.Email)
	// 	}
	// }()

	return JSONResponse(w, http.StatusOK, ApiResponse{
		Status:  APIResponseStatusSuccess,
		Message: "File shared successfully",
	})
}

type APIResponseStatus string

const (
	APIResponseStatusSuccess APIResponseStatus = "success"
	APIResponseStatusError   APIResponseStatus = "error"
)

// Response body format for API
type ApiResponse struct {
	Status  APIResponseStatus `json:"status"`
	Message string            `json:"message,omitempty"`
	Data    any               `json:"data,omitempty"`
}

// TriggerTestWebhookEvent creates a test webhook event for testing webhook delivery
func (h *ApiHandler) TriggerTestWebhookEvent(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	// Parse request body
	var req struct {
		EventType string `json:"event_type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Invalid request body",
		})
	}

	// Validate event type
	var eventType database.WebhookEventType
	switch req.EventType {
	case string(database.WebhookEventTypeFileCreated):
		eventType = database.WebhookEventTypeFileCreated
	case string(database.WebhookEventTypeFileDeleted):
		eventType = database.WebhookEventTypeFileDeleted
	case string(database.WebhookEventTypeUserLogin):
		eventType = database.WebhookEventTypeUserLogin
	case string(database.WebhookEventTypeUserLogout):
		eventType = database.WebhookEventTypeUserLogout
	default:
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Invalid event type. Must be one of: file.created, file.deleted, user.login, user.logout",
		})
	}

	// Import the daemon package for test helper
	// Note: In production, you might want to move this logic to a service layer
	testPayload := map[string]interface{}{
		"event_type": string(eventType),
		"timestamp":  time.Now().Format(time.RFC3339),
		"test":       true,
		"data": map[string]interface{}{
			"message": "This is a test webhook event triggered via API",
			"id":      "test-api-" + time.Now().Format("20060102-150405"),
		},
	}

	payloadBytes, err := json.Marshal(testPayload)
	if err != nil {
		h.logger.Error("Failed to marshal test payload", "error", err)
		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Failed to create test payload",
		})
	}

	// Create the webhook event
	event, err := h.db.CreateWebhookEvent(ctx, database.CreateWebhookEventParams{
		EventType: eventType,
		Payload:   payloadBytes,
	})
	if err != nil {
		h.logger.Error("Failed to create test webhook event", "error", err)
		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Failed to create webhook event",
		})
	}

	h.logger.Info("Test webhook event created via API",
		"event_id", event.ID,
		"event_type", eventType)

	return JSONResponse(w, http.StatusOK, ApiResponse{
		Status:  APIResponseStatusSuccess,
		Message: "Test webhook event created successfully",
		Data: map[string]interface{}{
			"event_id":   event.ID.String(),
			"event_type": string(eventType),
			"created_at": event.CreatedAt,
		},
	})
}

// JSONResponse writes a JSON response with the given status code and body.
func JSONResponse(w http.ResponseWriter, status int, body ApiResponse) error {
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(body)
}
