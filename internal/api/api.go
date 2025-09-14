package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"hp/internal/database"
	"hp/internal/openfga"
	"hp/internal/util"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/google/uuid"
	"github.com/stripe/stripe-go/v82/webhook"
)

var (
	codeTTL  = 5 * time.Minute
	tokenTTL = 1 * time.Hour
)

type ApiHandler struct {
	logger        *slog.Logger
	authorization *openfga.AuthorizationService
	db            *database.PostgresDatabase
	sessionStore  *session.Store
}

func NewApiHandler(logger *slog.Logger, authorization *openfga.AuthorizationService, db *database.PostgresDatabase, sessionStore *session.Store) *ApiHandler {
	return &ApiHandler{
		logger:        logger,
		authorization: authorization,
		db:            db,
		sessionStore:  sessionStore,
	}
}

func (h *ApiHandler) Healthy(c *fiber.Ctx) error {
	// Check database connection
	if err := h.db.Ping(c.Context()); err != nil {
		slog.Error("Database connection failed", "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "unhealthy",
			"message": "Database connection failed",
		})
	}

	// Additional health checks can be added here

	return c.JSON(fiber.Map{
		"status":  "healthy",
		"message": "Service is healthy",
	})
}

// Authorize implements OAuth2 Authorization Code (with PKCE for public clients)
// GET /api/auth/v1/authorize?response_type=code&client_id=&redirect_uri=&scope=&state=&code_challenge=&code_challenge_method=
func (h *ApiHandler) Authorize(c *fiber.Ctx) error {
	respTypeRaw := c.Query("response_type")
	clientIDStrRaw := c.Query("client_id")
	redirectURIRaw := c.Query("redirect_uri")
	scopeRaw := c.Query("scope")
	stateRaw := c.Query("state")
	codeChallengeRaw := c.Query("code_challenge")
	codeChallengeMethodRaw := c.Query("code_challenge_method", "")

	if respTypeRaw != "code" {
		h.logger.Info("Unsupported response type", "response_type", respTypeRaw)
		return oauthErrorRedirect(c, redirectURIRaw, stateRaw, "unsupported_response_type")
	}

	// Validate client
	clientIDRaw, err := uuid.Parse(clientIDStrRaw)
	if err != nil {
		h.logger.Info("Invalid client ID format", "client_id", clientIDRaw)
		return c.Status(fiber.StatusBadRequest).JSON(oauthErrorJSON("invalid_client", ""))
	}

	client, err := h.db.GetOAuthClient(c.Context(), clientIDRaw)
	if err != nil {
		h.logger.Info("Failed to get OAuth client", "error", err, "client_id", clientIDRaw)
		return c.Status(fiber.StatusBadRequest).JSON(oauthErrorJSON("invalid_client", "Unknown client_id"))
	}

	if !slices.Contains(client.RedirectURIs, redirectURIRaw) {
		h.logger.Info("Invalid redirect URI", "redirect_uri", redirectURIRaw, "client_id", clientIDRaw)
		return c.Status(fiber.StatusBadRequest).JSON(oauthErrorJSON("invalid_redirect_uri", "Redirect not registered"))
	}

	// Validate PKCE (must provide challenge)
	if codeChallengeRaw == "" {
		h.logger.Info("Missing code challenge for public client", "client_id", clientIDRaw)
		return oauthErrorRedirect(c, redirectURIRaw, stateRaw, "invalid_request")
	}
	if codeChallengeMethodRaw != "S256" && codeChallengeMethodRaw != "plain" && codeChallengeMethodRaw != "" { // allow empty -> treat as plain per RFC leniency
		h.logger.Info("Unsupported code challenge method", "method", codeChallengeMethodRaw, "client_id", clientIDRaw)
		return oauthErrorRedirect(c, redirectURIRaw, stateRaw, "invalid_request")
	}

	// Scopes
	var requestedScopes []string
	if scopeRaw != "" {
		requestedScopes = strings.Fields(scopeRaw)
	}

	var grantedScopes []string
	for _, rs := range requestedScopes {
		if slices.Contains(client.AllowedScopes, rs) {
			grantedScopes = append(grantedScopes, rs)
		}
	}

	// Get user ID from session
	sess, err := h.sessionStore.Get(c)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(oauthErrorJSON("server_error", "Session error"))
	}

	userIDRaw := sess.Get("user_id")
	if userIDRaw == nil {
		// redirect to login with return URL. For now simple 401.
		return c.Redirect("/login?return_to="+url.QueryEscape(c.OriginalURL()), fiber.StatusFound)
	}

	userID, ok := userIDRaw.(uuid.UUID)
	if !ok {
		h.logger.Info("Invalid session user id", "user_id", userID)
		return c.Status(fiber.StatusInternalServerError).JSON(oauthErrorJSON("server_error", "Invalid session user id"))
	}

	user, err := h.db.GetUser(c.Context(), userID)
	if err != nil {
		if errors.Is(err, database.ErrUserNotFound) {
			sess.Delete("user_id")
			if err := sess.Save(); err != nil {
				h.logger.Error("Failed to save session", "error", err)
			}
			return c.Redirect("/login?return_to="+url.QueryEscape(c.OriginalURL()), fiber.StatusFound)
		}
		h.logger.Error("Failed to get user", "error", err, "user_id", userID)
		return c.Status(fiber.StatusInternalServerError).JSON(oauthErrorJSON("server_error", "Failed to get user"))
	}

	// Create authorization code
	code, err := util.RandomString(32)
	if err != nil {
		h.logger.Error("Failed to generate authorization code", "error", err)
		return oauthErrorRedirect(c, redirectURIRaw, stateRaw, "server_error")
	}

	oauthCode, err := h.db.CreateOAuthAuthCode(c.Context(), database.CreateOAuthAuthCodeParams{
		Code:                code,
		ClientID:            client.ID,
		UserID:              user.ID,
		RedirectURI:         redirectURIRaw,
		CodeChallenge:       codeChallengeRaw,
		CodeChallengeMethod: codeChallengeMethodRaw,
		Scopes:              grantedScopes,
		ExpiresAt:           time.Now().Add(codeTTL),
	})

	if err != nil {
		h.logger.Error("Failed to create OAuth auth code", "error", err)
		return oauthErrorRedirect(c, redirectURIRaw, stateRaw, "server_error")
	}

	// Build redirect URL
	redirectURI := redirectURIRaw + "?code=" + url.QueryEscape(oauthCode.Code)
	if stateRaw != "" {
		redirectURI += "&state=" + url.QueryEscape(stateRaw)
	}

	return c.Redirect(redirectURI, http.StatusFound)
}

// OAuthToken issues access token for authorization_code grant with PKCE
// POST form: grant_type=authorization_code&code=&redirect_uri=&client_id=&code_verifier=
func (h *ApiHandler) OAuthToken(c *fiber.Ctx) error {
	grantTypeRaw := c.FormValue("grant_type")

	// Refresh token grant
	if grantTypeRaw == "refresh_token" {
		refreshTokenIDRaw := c.FormValue("refresh_token")
		clientIDRaw := c.FormValue("client_id")
		scopeRaw := c.FormValue("scope")

		// Validate refresh token
		refreshToken, err := h.db.GetOAuthRefreshToken(c.Context(), refreshTokenIDRaw)
		if err != nil {
			if errors.Is(err, database.ErrOAuthRefreshTokenNotFound) {
				return c.Status(fiber.StatusBadRequest).JSON(oauthErrorJSON("invalid_grant", "Invalid refresh token"))
			}

			h.logger.Error("Failed to get OAuth refresh token", "error", err, "refresh_token", refreshTokenIDRaw)
			return c.Status(fiber.StatusInternalServerError).JSON(oauthErrorJSON("server_error", "Failed to validate refresh token"))
		}

		if !slices.Contains(refreshToken.Scopes, "offline_access") {
			return c.Status(fiber.StatusBadRequest).JSON(oauthErrorJSON("invalid_grant", "Refresh token missing offline_access scope"))
		}

		// Validate client
		clientID, err := uuid.Parse(clientIDRaw)
		if err != nil {
			h.logger.Info("Invalid client ID format", "client_id", clientIDRaw)
			return c.Status(fiber.StatusBadRequest).JSON(oauthErrorJSON("invalid_client", ""))
		}

		client, err := h.db.GetOAuthClient(c.Context(), clientID)
		if err != nil {
			h.logger.Info("Failed to get OAuth client", "error", err, "client_id", clientID)
			return c.Status(fiber.StatusBadRequest).JSON(oauthErrorJSON("invalid_client", ""))
		}

		if refreshToken.ClientID != client.ID {
			return c.Status(fiber.StatusBadRequest).JSON(oauthErrorJSON("invalid_grant", "Client ID mismatch"))
		}

		if time.Now().After(refreshToken.ExpiresAt) {
			return c.Status(fiber.StatusBadRequest).JSON(oauthErrorJSON("invalid_grant", "Refresh token expired"))
		}

		// Scopes
		var grantedScopes []string
		if scopeRaw != "" {
			requestedScopes := strings.FieldsSeq(scopeRaw)
			for rs := range requestedScopes {
				if slices.Contains(refreshToken.Scopes, rs) {
					grantedScopes = append(grantedScopes, rs)
				}
			}
		}

		// Issue new access token
		newAccessTokenID, err := util.RandomString(32)
		if err != nil {
			slog.Error("Failed to generate random string", "error", err)
			return c.Status(fiber.StatusInternalServerError).JSON(oauthErrorJSON("server_error", "Failed to generate access token"))
		}

		newAccessToken, err := h.db.CreateOAuthAccessToken(c.Context(), database.CreateOAuthAccessTokenParams{
			Token:     newAccessTokenID,
			ClientID:  client.ID,
			Scopes:    grantedScopes,
			ExpiresAt: time.Now().Add(tokenTTL),
			UserID:    refreshToken.UserID,
		})
		if err != nil {
			slog.Error("Failed to create OAuth access token", "error", err)
			return c.Status(fiber.StatusInternalServerError).JSON(oauthErrorJSON("server_error", "Failed to create access token"))
		}

		// Invalidate (delete) the used refresh token for rotation
		if err := h.db.DeleteOAuthRefreshToken(c.Context(), refreshTokenIDRaw); err != nil {
			slog.Error("Failed to delete used refresh token", "error", err, "refresh_token", refreshTokenIDRaw)
			// Optionally: continue, but log for audit
		}

		// Issue a new refresh token
		newRefreshTokenID, err := util.RandomString(32)
		if err != nil {
			slog.Error("Failed to generate new refresh token", "error", err)
			return c.Status(fiber.StatusInternalServerError).JSON(oauthErrorJSON("server_error", "Failed to generate refresh token"))
		}
		refreshTokenExpires := time.Now().Add(30 * 24 * time.Hour) // e.g. 30 days

		newRefreshToken, err := h.db.CreateOAuthRefreshToken(c.Context(), database.CreateOAuthRefreshTokenParams{
			Token:     newRefreshTokenID,
			ClientID:  client.ID,
			UserID:    refreshToken.UserID,
			Scopes:    grantedScopes,
			ExpiresAt: refreshTokenExpires,
		})
		if err != nil {
			slog.Error("Failed to create new refresh token", "error", err)
			return c.Status(fiber.StatusInternalServerError).JSON(oauthErrorJSON("server_error", "Failed to create refresh token"))
		}

		return c.JSON(fiber.Map{
			"access_token":  newAccessToken.Token,
			"expires_in":    time.Until(newAccessToken.ExpiresAt).Seconds(),
			"token_type":    "Bearer",
			"scope":         strings.Join(newAccessToken.Scopes, " "),
			"refresh_token": newRefreshToken.Token,
		})
	}

	// Authorization code grant
	if grantTypeRaw != "authorization_code" {
		return c.Status(fiber.StatusBadRequest).JSON(oauthErrorJSON("unsupported_grant_type", ""))
	}
	codeRaw := c.FormValue("code")
	redirectURIRaw := c.FormValue("redirect_uri")
	clientIDStrRaw := c.FormValue("client_id")
	verifierRaw := c.FormValue("code_verifier")
	clientSecretRaw := c.FormValue("client_secret")

	// Validate client
	clientIDRaw, err := uuid.Parse(clientIDStrRaw)
	if err != nil {
		slog.Error("Invalid client ID format", "client_id", clientIDStrRaw)
		return c.Status(fiber.StatusBadRequest).JSON(oauthErrorJSON("invalid_client", ""))
	}

	client, err := h.db.GetOAuthClient(c.Context(), clientIDRaw)
	if err != nil {
		slog.Error("Failed to get OAuth client", "error", err, "client_id", clientIDRaw)
		return c.Status(fiber.StatusBadRequest).JSON(oauthErrorJSON("invalid_client", ""))
	}

	if !slices.Contains(client.RedirectURIs, redirectURIRaw) {
		return c.Status(fiber.StatusBadRequest).JSON(oauthErrorJSON("invalid_redirect_uri", ""))
	}

	// Exchange code for access token
	code, err := h.db.GetOAuthAuthCode(c.Context(), codeRaw)
	if err != nil {
		slog.Debug("Failed to get OAuth auth code", "error", err, "code", codeRaw)
		return c.Status(fiber.StatusBadRequest).JSON(oauthErrorJSON("invalid_grant", "Invalid authorization code"))
	}
	if err := h.db.DeleteOAuthAuthCode(c.Context(), code.Code); err != nil {
		slog.Error("Failed to delete OAuth auth code", "error", err, "code", code.Code)
		return c.Status(fiber.StatusInternalServerError).JSON(oauthErrorJSON("server_error", ""))
	}

	if code.ClientID != client.ID {
		return c.Status(fiber.StatusBadRequest).JSON(oauthErrorJSON("invalid_grant", "Client ID mismatch"))
	}
	if code.RedirectURI != redirectURIRaw {
		return c.Status(fiber.StatusBadRequest).JSON(oauthErrorJSON("invalid_grant", "Redirect URI mismatch"))
	}
	if time.Now().After(code.ExpiresAt) {
		return c.Status(fiber.StatusBadRequest).JSON(oauthErrorJSON("invalid_grant", "Authorization code expired"))
	}

	// PKCE validation
	if code.CodeChallenge == "" {
		return c.Status(fiber.StatusBadRequest).JSON(oauthErrorJSON("invalid_grant", "Missing code challenge"))
	}

	if code.CodeChallengeMethod == "" {
		return c.Status(fiber.StatusBadRequest).JSON(oauthErrorJSON("invalid_grant", "Missing code challenge method"))
	}

	// Only S256 is supported for now
	if code.CodeChallengeMethod != "S256" {
		return c.Status(fiber.StatusBadRequest).JSON(oauthErrorJSON("invalid_grant", "Unsupported code challenge method"))
	}

	if verifierRaw == "" {
		return c.Status(fiber.StatusBadRequest).JSON(oauthErrorJSON("invalid_grant", "Missing code verifier"))
	}

	// compute S256 hash of verifier
	imported := sha256.Sum256([]byte(verifierRaw))
	computed := base64.RawURLEncoding.EncodeToString(imported[:])
	if computed != code.CodeChallenge {
		return c.Status(fiber.StatusBadRequest).JSON(oauthErrorJSON("invalid_grant", "Code verifier mismatch"))
	}

	// For confidential clients, validate client secret
	if !client.Public {
		if clientSecretRaw == "" {
			return c.Status(fiber.StatusBadRequest).JSON(oauthErrorJSON("invalid_client", "Missing client secret"))
		}

		if client.Secret != clientSecretRaw {
			return c.Status(fiber.StatusBadRequest).JSON(oauthErrorJSON("invalid_client", "Invalid client secret"))
		}
	}

	responseBody := fiber.Map{}

	// Issue access token
	token, err := util.RandomString(32)
	if err != nil {
		slog.Error("Failed to generate random string", "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(oauthErrorJSON("server_error", ""))
	}

	accessToken, err := h.db.CreateOAuthAccessToken(c.Context(), database.CreateOAuthAccessTokenParams{
		Token:     token,
		ClientID:  client.ID,
		Scopes:    code.Scopes,
		ExpiresAt: time.Now().Add(tokenTTL),
		UserID:    code.UserID,
	})
	if err != nil {
		slog.Error("Failed to create OAuth access token", "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(oauthErrorJSON("server_error", ""))
	}

	responseBody["access_token"] = accessToken.Token
	responseBody["token_type"] = "bearer"
	responseBody["expires_in"] = int(time.Until(accessToken.ExpiresAt).Seconds())
	responseBody["scope"] = strings.Join(accessToken.Scopes, " ")

	// If offline_access scope was granted, issue refresh token as well
	if slices.Contains(code.Scopes, "offline_access") {
		// Issue refresh token as well
		refreshTokenID, err := util.RandomString(32)
		if err != nil {
			slog.Error("Failed to generate refresh token", "error", err)
			return c.Status(fiber.StatusInternalServerError).JSON(oauthErrorJSON("server_error", ""))
		}
		refreshTokenExpires := time.Now().Add(30 * 24 * time.Hour) // e.g. 30 days

		_, err = h.db.CreateOAuthRefreshToken(c.Context(), database.CreateOAuthRefreshTokenParams{
			Token:     refreshTokenID,
			ClientID:  client.ID,
			UserID:    code.UserID,
			Scopes:    code.Scopes,
			ExpiresAt: refreshTokenExpires,
		})
		if err != nil {
			slog.Error("Failed to create OAuth refresh token", "error", err)
			return c.Status(fiber.StatusInternalServerError).JSON(oauthErrorJSON("server_error", ""))
		}

		responseBody["refresh_token"] = refreshTokenID
	}

	return c.JSON(responseBody)
}

// Helper functions for OAuth error formatting --------------------------------------------
func oauthErrorJSON(code string, desc string) fiber.Map {
	return fiber.Map{"error": code, "error_description": desc}
}

func oauthErrorRedirect(c *fiber.Ctx, redirectURI string, state string, errCode string) error {
	if redirectURI == "" { // cannot redirect, return JSON
		return c.Status(fiber.StatusBadRequest).JSON(oauthErrorJSON(errCode, ""))
	}
	// best effort build
	redirectURI += "?error=" + url.QueryEscape(errCode)
	if state != "" {
		redirectURI += "&state=" + url.QueryEscape(state)
	}

	return c.Redirect(redirectURI, http.StatusFound)
}

func (h *ApiHandler) StripeWebhook(c *fiber.Ctx) error {
	// Handle Stripe webhook events
	// This is a placeholder for actual webhook handling logic
	endpointSecret := "whsec_r0fySCr2f4JP6Sm2lXYK8HXJkRApaRhC"
	event, err := webhook.ConstructEvent(c.Body(), c.Get("Stripe-Signature"), endpointSecret)
	if err != nil {
		slog.Error("Failed to construct webhook event", "error", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Invalid webhook payload",
		})
	}
	// Process the event based on its type
	switch event.Type {
	case "customer.subscription.created":
		// Handle successful customer subscription creation
		slog.Info("Customer subscription created", "event", event)
	case "customer.subscription.updated":
		// Handle customer subscription updated
		slog.Info("Customer subscription updated", "event", event)
	case "customer.subscription.deleted":
		// Handle customer subscription deletion
		slog.Info("Customer subscription deleted", "event", event)
	case "invoice.payment_succeeded":
		// Handle successful invoice payment
		slog.Info("Invoice payment succeeded", "event", event)
	case "invoice.payment_failed":
		// Handle failed invoice payment
		slog.Info("Invoice payment failed", "event", event)
	default:
		slog.Info("Unhandled event type", "type", event.Type)
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "Webhook received successfully",
	})
}

func (h *ApiHandler) ListClients(c *fiber.Ctx) error {
	clients, err := h.db.RetrieveOAuthClientList(c.Context())
	if err != nil {
		slog.Error("Failed to list OAuth clients", "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status": "error",
			"error":  "Failed to list OAuth clients",
		})
	}

	return c.JSON(fiber.Map{
		"status":  "success",
		"clients": clients,
	})
}

type CreateClientRequest struct {
	ClientID      uuid.UUID `json:"client_id"`
	Name          string    `json:"name"`
	RedirectURIs  []string  `json:"redirect_uris"`
	Public        bool      `json:"public"`
	ClientSecret  string    `json:"client_secret"`
	AllowedScopes []string  `json:"allowed_scopes"`
}

func (h *ApiHandler) CreateClient(c *fiber.Ctx) error {
	var requestBody CreateClientRequest
	if err := json.Unmarshal(c.Body(), &requestBody); err != nil {
		slog.Error("Failed to parse request body", "error", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status": "error",
			"error":  "Invalid request body",
		})
	}

	client, err := h.db.CreateOAuthClient(c.Context(), database.CreateOAuthClientParams{
		ClientID:      requestBody.ClientID,
		Name:          requestBody.Name,
		RedirectURIs:  requestBody.RedirectURIs,
		Public:        requestBody.Public,
		ClientSecret:  requestBody.ClientSecret,
		AllowedScopes: requestBody.AllowedScopes,
	})
	if err != nil {
		slog.Error("Failed to create OAuth client", "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status": "error",
			"error":  "Failed to create OAuth client",
		})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"status": "success",
		"client": client,
	})
}

func (h *ApiHandler) GetClient(c *fiber.Ctx) error {
	clientIDStrRaw := c.Params("client_id")
	if clientIDStrRaw == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status": "error",
			"error":  "Missing client ID",
		})
	}

	clientIDRaw, err := uuid.Parse(clientIDStrRaw)
	if err != nil {
		slog.Error("Invalid client ID format", "client_id", clientIDStrRaw)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status": "error",
			"error":  "Invalid client ID format",
		})
	}

	client, err := h.db.GetOAuthClient(c.Context(), clientIDRaw)
	if err != nil {
		slog.Error("Failed to get OAuth client", "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status": "error",
			"error":  "Failed to get OAuth client",
		})
	}

	return c.JSON(fiber.Map{
		"status": "success",
		"client": client,
	})
}

func (h *ApiHandler) DeleteClient(c *fiber.Ctx) error {
	clientIDStrRaw := c.Params("client_id")
	if clientIDStrRaw == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status": "error",
			"error":  "Missing client ID",
		})
	}

	clientIDRaw, err := uuid.Parse(clientIDStrRaw)
	if err != nil {
		slog.Error("Invalid client ID format", "client_id", clientIDStrRaw)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status": "error",
			"error":  "Invalid client ID format",
		})
	}

	if err := h.db.DeleteOAuthClient(c.Context(), clientIDRaw); err != nil {
		slog.Error("Failed to delete OAuth client", "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status": "error",
			"error":  "Failed to delete OAuth client",
		})
	}

	return c.JSON(fiber.Map{
		"status":  "success",
		"message": "OAuth client deleted successfully",
	})
}

func (h *ApiHandler) ListFiles(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)

	// fileIDs, err := h.authorization.ListCanReadFiles(c.Context(), userID)
	// if err != nil {
	// 	slog.Error("Failed to list readable files", "error", err, "user_id", userID)
	// 	return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
	// 		"status":  "error",
	// 		"message": "Failed to list readable files",
	// 	})
	// }

	var params database.RetrieveFileListParams
	params.OwnerID = userID
	// For now, list all files owned by the user
	// In the future, we should allow filter by shared
	// params.AllowedIDs = fileIDs

	files, err := h.db.RetrieveFileList(c.Context(), params)
	if err != nil {
		slog.Error("Failed to list files", "error", err, "user_id", userID)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status": "error",
			"error":  "Failed to list files",
		})
	}

	jsonFiles := make([]fiber.Map, 0, len(files))
	for _, file := range files {
		jsonFiles = append(jsonFiles, fiber.Map{
			"id":            file.ID,
			"name":          file.Name,
			"mime_type":     file.MimeType,
			"size_bytes":    file.SizeBytes,
			"last_modified": file.UpdatedAt.Unix(),
		})
	}

	return c.JSON(fiber.Map{
		"status": "success",
		"files":  jsonFiles,
	})
}

type CreateFileRequest struct {
	Name     string        `json:"name"`
	MimeType string        `json:"mime_type"`
	Parent   uuid.NullUUID `json:"parent"` // Optional parent folder ID
}

func (h *ApiHandler) CreateFile(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)

	// Parse the request body into a File struct
	var requestBody CreateFileRequest
	if err := json.Unmarshal(c.Body(), &requestBody); err != nil {
		slog.Error("Failed to parse request body", "error", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status": "error",
			"error":  "Invalid request body",
		})
	}

	params := database.CreateFileParams{
		OwnerID:   userID,
		ParentID:  requestBody.Parent,
		Name:      requestBody.Name,
		MimeType:  requestBody.MimeType,
		S3Key:     "",
		SizeBytes: 0,
	}

	// For now we only support creating folder through this endpoint
	// In the future, files should also be supported
	// if !file.IsFolder() {
	// 	return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
	// 		"status": "error",
	// 		"error":  "Invalid mime type for folder",
	// 	})
	// }

	file, err := h.db.CreateFile(c.Context(), params)
	if err != nil {
		slog.Error("Failed to create file", "error", err, "user_id", userID)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status": "error",
			"error":  "Failed to create file",
		})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"status": "success",
		"file": fiber.Map{
			"id":            file.ID,
			"name":          file.Name,
			"mime_type":     file.MimeType,
			"size_bytes":    file.SizeBytes,
			"last_modified": file.UpdatedAt.Unix(),
		},
	})
}

func (h *ApiHandler) GetFile(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)

	fileIDStr := c.Params("file_id")
	if fileIDStr == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status": "error",
			"error":  "File ID is required",
		})
	}

	fileID, err := uuid.Parse(fileIDStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status": "error",
			"error":  "Invalid file ID",
		})
	}

	if ok, err := h.authorization.CanReadFile(c.Context(), userID, fileID); !ok {
		slog.Error("User does not have permission to read file", "user_id", userID, "file_id", fileID, "error", err)
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"status": "error",
			"error":  "You do not have permission to read this file",
		})
	}

	file, err := h.db.GetFile(c.Context(), fileID)
	if err != nil {
		slog.Error("Failed to get file", "error", err, "file_id", fileID)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status": "error",
			"error":  "Failed to get file",
		})
	}

	return c.JSON(fiber.Map{
		"status": "success",
		"file": fiber.Map{
			"id":            file.ID,
			"name":          file.Name,
			"mime_type":     file.MimeType,
			"size_bytes":    file.SizeBytes,
			"last_modified": file.UpdatedAt.Unix(),
		},
	})
}

func (h *ApiHandler) DeleteFile(c *fiber.Ctx) error {
	// userID := c.Locals("user_id").(uuid.UUID)

	fileID := c.Params("file_id")
	if fileID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status": "error",
			"error":  "File ID is required",
		})
	}

	// todo check permission

	if err := h.db.DeleteFile(c.Context(), uuid.MustParse(fileID)); err != nil {
		slog.Error("Failed to delete file", "error", err, "file_id", fileID)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status": "error",
			"error":  "Failed to delete file",
		})
	}

	if err := h.authorization.RemoveFileReader(c.Context(), uuid.Nil, uuid.MustParse(fileID)); err != nil {
		slog.Error("Failed to remove file reader permission", "error", err, "file_id", fileID)
		// Not returning error to user since the file deletion was successful
	}

	return c.JSON(fiber.Map{
		"status":  "success",
		"message": "File deleted successfully",
	})
}

func (h *ApiHandler) UploadFile(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)

	// Get file ID from form data (optional)
	var fileID uuid.NullUUID
	if fileIDStr := c.FormValue("file_id"); fileIDStr != "" {
		id, err := uuid.Parse(fileIDStr)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"status": "error",
				"error":  "Invalid file ID",
			})
		}
		fileID = uuid.NullUUID{Valid: true, UUID: id}
	}

	// Parse multipart form
	form, err := c.MultipartForm()
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status": "error",
			"error":  "Failed to parse multipart form",
		})
	}

	files := form.File["files"]
	if len(files) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status": "error",
			"error":  "No files provided",
		})
	}

	// Create uploads directory if it doesn't exist
	uploadDir := "uploads"
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		slog.Error("Failed to create upload directory", "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status": "error",
			"error":  "Failed to create upload directory",
		})
	}

	var uploadedFiles []fiber.Map

	for _, fileHeader := range files {
		// Generate unique filename
		ext := filepath.Ext(fileHeader.Filename)
		baseFilename := strings.TrimSuffix(fileHeader.Filename, ext)
		uniqueFilename := baseFilename + "_" + uuid.New().String() + ext
		filePath := filepath.Join(uploadDir, uniqueFilename)

		// Save file to disk
		if err := c.SaveFile(fileHeader, filePath); err != nil {
			slog.Error("Failed to save file", "error", err, "filename", fileHeader.Filename)
			continue
		}

		// Determine MIME type
		mimeType := fileHeader.Header.Get("Content-Type")
		if mimeType == "" {
			mimeType = "application/octet-stream"
		}

		// Create file record in database
		var params database.CreateFileParams
		params.OwnerID = userID
		params.ParentID = fileID
		params.Name = fileHeader.Filename
		params.MimeType = mimeType
		params.S3Key = filePath
		params.SizeBytes = fileHeader.Size

		file, err := h.db.CreateFile(c.Context(), params)
		if err != nil {
			slog.Error("Failed to create file record", "error", err, "filename", fileHeader.Filename)
			// Try to delete the saved file
			os.Remove(filePath)
			continue
		}

		if err := h.authorization.AddFileReader(c.Context(), userID, file.ID); err != nil {
			slog.Error("Failed to add file reader permission", "error", err, "user_id", userID, "file_id", file.ID)
			// Try to delete the saved file and database record
			os.Remove(filePath)
			if err := h.db.DeleteFile(c.Context(), file.ID); err != nil {
				slog.Error("Failed to delete file record after permission error", "error", err, "file_id", file.ID)
			}
			continue
		}

		uploadedFiles = append(uploadedFiles, fiber.Map{
			"id":       file.ID,
			"name":     file.Name,
			"size":     file.SizeBytes,
			"mimeType": file.MimeType,
		})
	}

	if len(uploadedFiles) == 0 {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status": "error",
			"error":  "Failed to upload any files",
		})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"status": "success",
		"files":  uploadedFiles,
	})
}

func (h *ApiHandler) DownloadFile(c *fiber.Ctx) error {
	// userID := c.Locals("user_id").(uuid.UUID)

	fileIDStr := c.Params("file_id")
	fileID, err := uuid.Parse(fileIDStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status": "error",
			"error":  "Invalid file ID",
		})
	}

	// todo check file access

	file, err := h.db.GetFile(c.Context(), fileID)
	if err != nil {
		if err == database.ErrFileNotFound {
			slog.Error("File not found", "file_id", fileID)
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"status": "error",
				"error":  "File not found",
			})
		}
		slog.Error("Failed to retrieve file", "error", err, "file_id", fileID)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status": "error",
			"error":  "Failed to retrieve file",
		})
	}

	if _, err := os.Stat(file.S3Key); os.IsNotExist(err) {
		slog.Error("File does not exist on disk", "file_path", file.S3Key)
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"status": "error",
			"error":  "File not found",
		})
	}

	c.Set("Content-Disposition", `attachment; filename="`+file.Name+`"`)
	c.Set("Content-Type", file.MimeType)

	return c.SendFile(file.S3Key, false)
}

type ShareFileRequest struct {
	Email string `json:"email"`
}

func (h *ApiHandler) ShareFile(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	// Get file ID from URL parameter
	fileIDStr := c.Params("file_id")
	fileID, err := uuid.Parse(fileIDStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status": "error",
			"error":  "Invalid file ID",
		})
	}

	var req ShareFileRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status": "error",
			"error":  "Invalid request",
		})
	}

	// Check if the file exists
	file, err := h.db.GetFile(c.Context(), fileID)
	if err != nil {
		if err == database.ErrFileNotFound {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"status": "error",
				"error":  "File not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status": "error",
			"error":  "Failed to retrieve file",
		})
	}

	var retrieveUserParams database.RetrieveUserParams
	retrieveUserParams.Email = req.Email

	targetUser, err := h.db.RetrieveUser(c.Context(), retrieveUserParams)
	if err != nil {
		if err == database.ErrUserNotFound {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"status": "error",
				"error":  "User not found",
			})
		}

		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status": "error",
			"error":  "Failed to retrieve user",
		})
	}

	// Create a shared file record
	var createSharedFileParams database.CreateSharedFileParams
	createSharedFileParams.FileID = file.ID
	createSharedFileParams.SharingUserID = userID
	createSharedFileParams.ReceivingUserID = targetUser.ID
	createSharedFileParams.GrantedAt = time.Now()

	if err := h.db.CreateSharedFile(c.Context(), createSharedFileParams); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status": "error",
			"error":  "Failed to share file",
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "File shared successfully",
	})
}
