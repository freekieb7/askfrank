package web

import (
	"context"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"hp/internal/audit"
	"hp/internal/auth"
	"hp/internal/calendar"
	"hp/internal/config"
	"hp/internal/database"
	"hp/internal/drive"
	"hp/internal/i18n"
	"hp/internal/notifications"
	"hp/internal/oauth"
	"hp/internal/session"
	"hp/internal/user"
	"hp/internal/util"
	"hp/internal/web/translate"
	"hp/internal/web/views"
	"hp/internal/web/views/component"
	"hp/internal/webhook"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/a-h/templ"
	"github.com/google/uuid"
)

func init() {
	gob.Register(uuid.UUID{}) // Register uuid.UUID for session storage
}

type PageHandler struct {
	Logger         *slog.Logger
	Translator     *i18n.Translator
	SessionStore   *session.Store
	UserManager    *user.Manager
	Authenticator  *auth.Authenticator
	WebhookManager *webhook.Manager
	Notifier       *notifications.Manager
	DriveManager   *drive.Manager
	OAuthManager   *oauth.Manager
	Planner        *calendar.Manager
	Auditor        *audit.Auditor
}

func NewPageHandler(logger *slog.Logger, translator *i18n.Translator, sessionStore *session.Store, userManager *user.Manager, webhookManager *webhook.Manager, authenticator *auth.Authenticator, notifier *notifications.Manager, driveManager *drive.Manager, oauthManager *oauth.Manager, planner *calendar.Manager, auditor *audit.Auditor) *PageHandler {
	return &PageHandler{Logger: logger, Translator: translator, SessionStore: sessionStore, UserManager: userManager, WebhookManager: webhookManager, Authenticator: authenticator, Notifier: notifier, DriveManager: driveManager, OAuthManager: oauthManager, Planner: planner, Auditor: auditor}
}

func (h *PageHandler) layoutProps(ctx context.Context, title string) component.LayoutProps {
	lang := ctx.Value(config.LanguageContextKey).(i18n.Language)
	translator := translate.Translator{
		Translator: h.Translator,
		Language:   lang,
	}
	CSRFToken := ctx.Value(config.CSRFTokenContextKey).(string)

	return component.LayoutProps{
		Title:      title,
		Translator: translator,
		CSRFToken:  CSRFToken,
		// Description: "Your healthcare platform",
		// Keywords:    []string{"healthcare", "platform", "askfrank"},
	}
}

func (h *PageHandler) appLayoutProps(ctx context.Context, layoutProps component.LayoutProps, r *http.Request) component.AppLayoutProps {
	userID := ctx.Value(config.UserIDContextKey).(uuid.UUID)

	// Get recent notifications for the dropdown (limit to 10)
	unreadNotifications, err := h.Notifier.Unread(ctx, userID)
	if err != nil {
		h.Logger.Error("Failed to get recent notifications", "error", err)
		unreadNotifications = []notifications.Notification{}
	}

	componentNotifications := make([]component.Notification, len(unreadNotifications))

	for i, notification := range unreadNotifications {
		componentNotifications[i] = component.Notification{
			ID:        notification.ID.String(),
			Title:     notification.Title,
			Message:   notification.Message,
			Type:      string(notification.Type),
			IsRead:    notification.IsRead,
			ActionURL: "",
			CreatedAt: notification.CreatedAt.Format("2 Jan 2006 15:04"),
		}
	}

	user, err := h.UserManager.GetUser(ctx, userID)
	if err != nil {
		h.Logger.Error("Failed to get user by ID", "error", err)
	}

	return component.AppLayoutProps{
		LayoutProps: layoutProps,
		MenuItems: []component.MenuItem{
			{Name: "Home", URL: "/dashboard", Icon: "fas fa-home", Active: r.URL.Path == "/dashboard"},
			// {Name: "Calendar", URL: "/calendar", Icon: "fas fa-calendar", Active: strings.HasPrefix(r.URL.Path, "/calendar")},
			// {Name: "Drive", URL: "/drive", Icon: "fas fa-folder", Active: strings.HasPrefix(r.URL.Path, "/drive"), SubItems: []component.MenuItem{
			// 	{Name: "My Drive", URL: "/drive", Icon: "fas fa-folder", Active: r.URL.Path == "/drive"},
			// 	{Name: "Shared with Me", URL: "/drive/shared", Icon: "fas fa-folder-open", Active: strings.HasPrefix(r.URL.Path, "/drive/shared")},
			// }},
			// {Name: "Meetings", URL: "/meetings", Icon: "fas fa-video", Active: strings.HasPrefix(r.URL.Path, "/meetings")},
			// {Name: "Chat", URL: "/chat", Icon: "fas fa-comments", Active: strings.HasPrefix(r.URL.Path, "/chat")},
			// {Name: "Billing", URL: "/billing", Icon: "fas fa-credit-card", Active: strings.HasPrefix(r.URL.Path, "/billing")},
			{Name: "Developers", URL: "/developers", Icon: "fas fa-code", Active: strings.HasPrefix(r.URL.Path, "/developers"), SubItems: []component.MenuItem{
				// {Name: "API Documentation", URL: "/developers", Icon: "fas fa-book", Active: c.Path() == "/developers"},
				{Name: "Clients", URL: "/developers/clients", Icon: "fas fa-laptop-code", Active: strings.HasPrefix(r.URL.Path, "/developers/clients")},
				// {Name: "Webhooks", URL: "/developers/webhooks", Icon: "fas fa-rss", Active: strings.HasPrefix(r.URL.Path, "/developers/webhooks")},
				// {Name: "Logs", URL: "/developers/logs", Icon: "fas fa-file-alt", Active: strings.HasPrefix(r.URL.Path, "/developers/logs")},
			}},
		},
		HasUnreadNotification: len(unreadNotifications) > 0,
		UnreadCount:           len(unreadNotifications),
		RecentNotifications:   componentNotifications,
		UserInfo: component.UserInfo{
			ID:    user.ID.String(),
			Name:  user.Name,
			Email: user.Email,
		},
	}
}

func (h *PageHandler) ShowHomePage(w http.ResponseWriter, r *http.Request) error {
	return Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (h *PageHandler) ShowDocsPage(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	return render(ctx, w, views.DocsPage(views.DocsPageProps{
		LayoutProps: h.layoutProps(ctx, "API Documentation"),
	}))
}

func (h *PageHandler) ShowDashboardPage(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	return render(ctx, w, views.DashboardPage(views.DashboardPageProps{
		AppLayoutProps: h.appLayoutProps(ctx, h.layoutProps(ctx, "Dashboard"), r),
	}))
}

func (h *PageHandler) ShowLoginPage(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	sess, err := h.SessionStore.Get(ctx, r)
	if err != nil {
		return fmt.Errorf("failed to get session: %w", err)
	}
	defer func() {
		if err := h.SessionStore.Save(ctx, w, sess); err != nil {
			h.Logger.Error("Failed to save session", "error", err)
		}
	}()

	if sess.UserID.IsSet {
		return Redirect(w, r, "/dashboard", http.StatusSeeOther) // Redirect if already logged in
	}

	// Store the return_to query parameter in session for post-login redirection
	redirectToRaw := r.URL.Query().Get("return_to")
	if redirectToRaw != "" {
		sess.Data.RedirectTo = redirectToRaw
	}

	return render(ctx, w, views.LoginPage(views.LoginPageProps{
		LayoutProps: h.layoutProps(ctx, "Login"),
	}))
}

type LoginRequest struct {
	Email      string `json:"email"`
	Password   string `json:"password"`
	RememberMe bool   `json:"remember_me"`
}

func (h *PageHandler) Login(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	sess, err := h.SessionStore.Get(ctx, r)
	if err != nil {
		return JSONResponse(w, http.StatusInternalServerError, JSONResponseBody{
			Status:  APIResponseStatusError,
			Message: "Failed to get session",
		})
	}
	defer func() {
		if err := h.SessionStore.Save(ctx, w, sess); err != nil {
			h.Logger.Error("Failed to save session", "error", err)
		}
	}()

	// Get JSON data
	var loginReq LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&loginReq); err != nil {
		return JSONResponse(w, http.StatusBadRequest, JSONResponseBody{
			Status:  APIResponseStatusError,
			Message: "Invalid request payload",
		})
	}

	// Basic validation
	if loginReq.Email == "" || loginReq.Password == "" {
		return JSONResponse(w, http.StatusBadRequest, JSONResponseBody{
			Status:  APIResponseStatusError,
			Message: "Email and password are required",
		})
	}

	// Fetch user by email
	userID, err := h.Authenticator.Login(ctx, auth.LoginParam{
		Email:    loginReq.Email,
		Password: loginReq.Password,
	})
	if err != nil {
		return JSONResponse(w, http.StatusUnauthorized, JSONResponseBody{
			Status:  APIResponseStatusError,
			Message: "Invalid email or password",
		})
	}

	// Determine session duration based on "Remember Me" option
	var sessionDuration time.Duration
	if loginReq.RememberMe {
		sessionDuration = 30 * 24 * time.Hour // 30 days
	} else {
		sessionDuration = 2 * time.Hour // 2 hours
	}
	sess.ExpiresAt = time.Now().Add(sessionDuration)

	// Regenerate session ID to prevent fixation TODO look into this
	// if err := sess.Regenerate(); err != nil {
	// 	h.logger.Error("Failed to regenerate session ID", "error", err)
	// 	// Continue, but log
	// }
	// Set user ID in session
	sess.UserID = util.Some(userID)

	// Redirect to the originally requested page or home
	redirectTo := "/dashboard"

	if sess.Data.RedirectTo != "" {
		redirectTo = sess.Data.RedirectTo
		// Clear the redirect_to after using it
		sess.Data.RedirectTo = ""
	}

	return JSONResponse(w, http.StatusOK, JSONResponseBody{
		Status:  APIResponseStatusSuccess,
		Message: "Login successful! Redirecting...",
		Data: map[string]string{
			"redirect_to": redirectTo,
		},
	})
}

func (h *PageHandler) Logout(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	sess, err := h.SessionStore.Get(ctx, r)
	if err != nil {
		return JSONResponse(w, http.StatusInternalServerError, JSONResponseBody{
			Status:  APIResponseStatusError,
			Message: "Failed to get session",
		})
	}
	defer func() {
		if err := h.SessionStore.Save(ctx, w, sess); err != nil {
			h.Logger.Error("Failed to save session", "error", err)
		}
	}()

	if err := h.Authenticator.Logout(ctx, sess.UserID.Val); err != nil {
		h.Logger.Error("Failed to sign out user", "error", err)
	}

	if err := h.SessionStore.Destroy(ctx, w, sess); err != nil {
		h.Logger.Error("Failed to destroy session", "error", err)
	}

	return JSONResponse(w, http.StatusOK, JSONResponseBody{
		Status:  APIResponseStatusSuccess,
		Message: "Logout successful! Continue to login.",
		Data: map[string]any{
			"redirect_to": "/login",
		},
	})
}

func (h *PageHandler) ShowRegisterPage(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	return render(ctx, w, views.RegisterPage(views.RegisterPageProps{
		LayoutProps: h.layoutProps(ctx, "Register"),
	}))
}

type RegisterRequest struct {
	Name          string `json:"name"`
	Email         string `json:"email"`
	Password      string `json:"password"`
	TermsAccepted bool   `json:"terms_accepted"`
}

func (h *PageHandler) RegisterStandaloneUser(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	sess, err := h.SessionStore.Get(ctx, r)
	if err != nil {
		return JSONResponse(w, http.StatusInternalServerError, JSONResponseBody{
			Status:  APIResponseStatusError,
			Message: "Failed to get session",
		})
	}
	defer func() {
		if err := h.SessionStore.Save(ctx, w, sess); err != nil {
			h.Logger.Error("Failed to save session", "error", err)
		}
	}()

	// Get form data
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.Logger.Error("Failed to decode register request", "error", err)
		return JSONResponse(w, http.StatusBadRequest, JSONResponseBody{
			Status:  APIResponseStatusError,
			Message: "Invalid request",
		})
	}

	// Basic validation
	if req.Name == "" || req.Email == "" || req.Password == "" {
		return JSONResponse(w, http.StatusBadRequest, JSONResponseBody{
			Status:  APIResponseStatusError,
			Message: "All fields are required",
		})
	}

	if len(req.Password) < 8 {
		return JSONResponse(w, http.StatusBadRequest, JSONResponseBody{
			Status:  APIResponseStatusError,
			Message: "Password must be at least 8 characters long",
		})
	}

	if !req.TermsAccepted {
		return JSONResponse(w, http.StatusBadRequest, JSONResponseBody{
			Status:  APIResponseStatusError,
			Message: "You must accept the terms and conditions",
		})
	}

	// Check if user already exists
	userID, err := h.Authenticator.Register(ctx, auth.RegisterParam{
		Name:     req.Name,
		Email:    req.Email,
		Password: req.Password,
	})
	if err != nil {
		if errors.Is(err, auth.ErrEmailAlreadyInUse) {
			return JSONResponse(w, http.StatusBadRequest, JSONResponseBody{
				Status:  APIResponseStatusError,
				Message: "Email already in use",
			})
		}

		h.Logger.Error("Failed to register user", "error", err)
		return JSONResponse(w, http.StatusInternalServerError, JSONResponseBody{
			Status:  APIResponseStatusError,
			Message: "Failed to register user",
		})
	}

	// Regenerate session ID to prevent fixation TODO look into this
	// if err := sess.Regenerate(); err != nil {
	// 	h.logger.Error("Failed to regenerate session ID", "error", err)
	// 	// Continue, but log
	// }
	sess.ExpiresAt = time.Now().Add(2 * time.Hour) // Default 2 hour session

	// Set user ID in session
	sess.UserID = util.Some(userID)

	return JSONResponse(w, http.StatusOK, JSONResponseBody{
		Status:  APIResponseStatusSuccess,
		Message: "Registration successful! Continue to the app.",
		Data: map[string]any{
			"redirect_to": "/dashboard",
		},
	})
}

func (h *PageHandler) ShowOAuthClientsPage(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	// Get the list of OAuth clients for this user
	clients, err := h.OAuthManager.ListClients(ctx)
	if err != nil {
		h.Logger.Error("Failed to list OAuth clients", "error", err)
		return JSONResponse(w, http.StatusInternalServerError, JSONResponseBody{
			Status:  APIResponseStatusError,
			Message: "Failed to load OAuth clients",
		})
	}

	// Convert to view model
	viewClients := make([]views.OAuthClient, 0, len(clients))
	for _, client := range clients {
		viewClients = append(viewClients, views.OAuthClient{
			ID:           client.ID.String(),
			Name:         client.Name,
			Description:  "", // Add a default empty description
			ModifiedAt:   client.ModifiedAt,
			RedirectURIs: client.RedirectURIs,
		})
	}

	return render(ctx, w, views.OAuthClientsPage(views.OAuthClientsPageProps{
		AppLayoutProps: h.appLayoutProps(ctx, h.layoutProps(ctx, "OAuth Clients"), r),
		Clients:        viewClients,
	}))
}

type CreateOAuthClientRequest struct {
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	RedirectURIs []string `json:"redirect_uris"`
	Public       bool     `json:"public"`
	Scopes       []string `json:"scopes"`
}

func (h *PageHandler) CreateOAuthClient(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	var req CreateOAuthClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return JSONResponse(w, http.StatusBadRequest, JSONResponseBody{
			Status:  APIResponseStatusError,
			Message: "Invalid request payload",
		})
	}

	// Trim whitespace from all fields
	req.Name = strings.TrimSpace(req.Name)
	req.Description = strings.TrimSpace(req.Description)
	for i, uri := range req.RedirectURIs {
		req.RedirectURIs[i] = strings.TrimSpace(uri)
	}
	for i, scope := range req.Scopes {
		req.Scopes[i] = strings.TrimSpace(scope)
	}

	// Validation
	if req.Name == "" {
		return JSONResponse(w, http.StatusBadRequest, JSONResponseBody{
			Status:  APIResponseStatusError,
			Message: "Name is required",
		})
	}

	if len(req.RedirectURIs) == 0 {
		return JSONResponse(w, http.StatusBadRequest, JSONResponseBody{
			Status:  APIResponseStatusError,
			Message: "At least one redirect URI is required",
		})
	}

	client, err := h.OAuthManager.CreateClient(ctx, oauth.CreateClientParams{
		Name:          req.Name,
		IsPublic:      req.Public,
		RedirectURIs:  req.RedirectURIs,
		AllowedScopes: req.Scopes,
	})
	if err != nil {
		h.Logger.Error("Failed to create OAuth client", "error", err)
		return JSONResponse(w, http.StatusInternalServerError, JSONResponseBody{
			Status:  APIResponseStatusError,
			Message: "Failed to create OAuth client",
		})
	}

	// Return the newly created client details, including the secret
	// (this is the only time the secret will be fully visible)
	return JSONResponse(w, http.StatusCreated, JSONResponseBody{
		Status: APIResponseStatusSuccess,
		Data: map[string]any{
			"id":           client.ID.String(),
			"name":         client.Name,
			"redirectURIs": client.RedirectURIs,
			"public":       false,
			"secret":       client.Secret,
		},
	})
}

func (h *PageHandler) GetOAuthClient(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	// userID := c.Locals("user_id").(uuid.UUID)
	clientIDStr := r.PathValue("client_id")

	clientID, err := uuid.Parse(clientIDStr)
	if err != nil {
		return JSONResponse(w, http.StatusBadRequest, JSONResponseBody{
			Status:  APIResponseStatusError,
			Message: "Invalid client ID",
		})
	}

	client, err := h.OAuthManager.GetClientByID(ctx, clientID)
	if err != nil {
		if err == database.ErrOAuthClientNotFound {
			return JSONResponse(w, http.StatusNotFound, JSONResponseBody{
				Status:  APIResponseStatusError,
				Message: "OAuth client not found",
			})
		}
		h.Logger.Error("Failed to get OAuth client", "error", err, "client_id", clientID)
		return JSONResponse(w, http.StatusInternalServerError, JSONResponseBody{
			Status:  APIResponseStatusError,
			Message: "Failed to retrieve OAuth client",
		})
	}

	// Return the client details
	// Note: for security, we don't return the full client secret here
	// We return a masked version or nothing at all
	return JSONResponse(w, http.StatusOK, JSONResponseBody{
		Status: APIResponseStatusSuccess,
		Data: map[string]any{
			"id":            client.ID.String(),
			"name":          client.Name,
			"redirect_uris": client.RedirectURIs,
			"public":        client.IsPublic,
			"scopes":        client.AllowedScopes,
			"modified_at":   client.ModifiedAt,
		},
	})
}

func (h *PageHandler) DeleteOAuthClient(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	// userID := c.Locals("user_id").(uuid.UUID)
	clientIDStr := r.PathValue("client_id")

	clientID, err := uuid.Parse(clientIDStr)
	if err != nil {
		return JSONResponse(w, http.StatusBadRequest, JSONResponseBody{
			Status:  APIResponseStatusError,
			Message: "Invalid client ID",
		})
	}

	// Check if the client exists and belongs to the user
	_, err = h.OAuthManager.GetClientByID(ctx, clientID)
	if err != nil {
		if err == database.ErrOAuthClientNotFound {
			return JSONResponse(w, http.StatusNotFound, JSONResponseBody{
				Status:  APIResponseStatusError,
				Message: "OAuth client not found",
			})
		}
		h.Logger.Error("Failed to get OAuth client for deletion", "error", err, "client_id", clientID)
		return JSONResponse(w, http.StatusInternalServerError, JSONResponseBody{
			Status:  APIResponseStatusError,
			Message: "Failed to retrieve OAuth client",
		})
	}

	// Delete the client
	if err := h.OAuthManager.DeleteClientByID(ctx, clientID); err != nil {
		h.Logger.Error("Failed to delete OAuth client", "error", err, "client_id", clientID)
		return JSONResponse(w, http.StatusInternalServerError, JSONResponseBody{
			Status:  APIResponseStatusError,
			Message: "Failed to delete OAuth client",
		})
	}

	// Redirect back to the developer page after deletion
	return JSONResponse(w, http.StatusOK, JSONResponseBody{
		Status:  APIResponseStatusSuccess,
		Message: "OAuth client deleted successfully",
		Data: map[string]any{
			"redirect_to": "/developer",
		},
	})
}

func render(ctx context.Context, w http.ResponseWriter, component templ.Component) error {
	w.Header().Set("Content-Type", "text/html")
	return component.Render(ctx, w)
}
