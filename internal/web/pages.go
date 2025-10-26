package web

import (
	"context"
	"encoding/gob"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/freekieb7/askfrank/internal/audit"
	"github.com/freekieb7/askfrank/internal/auth"
	"github.com/freekieb7/askfrank/internal/calendar"
	"github.com/freekieb7/askfrank/internal/config"
	"github.com/freekieb7/askfrank/internal/database"
	"github.com/freekieb7/askfrank/internal/drive"
	"github.com/freekieb7/askfrank/internal/http"
	"github.com/freekieb7/askfrank/internal/i18n"
	"github.com/freekieb7/askfrank/internal/notifications"
	"github.com/freekieb7/askfrank/internal/oauth"
	"github.com/freekieb7/askfrank/internal/session"
	"github.com/freekieb7/askfrank/internal/user"
	"github.com/freekieb7/askfrank/internal/util"
	"github.com/freekieb7/askfrank/internal/web/ui"
	"github.com/freekieb7/askfrank/internal/web/ui/views"
	"github.com/freekieb7/askfrank/internal/web/ui/views/component"
	"github.com/freekieb7/askfrank/internal/webhook"

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

func (h *PageHandler) appLayoutProps(ctx context.Context, title string) component.AppLayoutProps {
	sess := ctx.Value(config.SessionContextKey).(session.Session)

	// Get recent notifications for the dropdown (limit to 10)
	unreadNotifications, err := h.Notifier.Unread(ctx, sess.UserID.Val)
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

	user, err := h.UserManager.GetUser(ctx, sess.UserID.Val)
	if err != nil {
		h.Logger.Error("Failed to get user by ID", "error", err)
	}

	return component.AppLayoutProps{
		LayoutProps: ui.LayoutProps(ctx, title, h.Translator),
		MenuItems: []component.MenuItem{
			{Name: "Home", URL: "/dashboard", Icon: "fas fa-home", Active: false},
			// {Name: "Calendar", URL: "/calendar", Icon: "fas fa-calendar", Active: strings.HasPrefix(r.URL.Path, "/calendar")},
			// {Name: "Drive", URL: "/drive", Icon: "fas fa-folder", Active: strings.HasPrefix(r.URL.Path, "/drive"), SubItems: []component.MenuItem{
			// 	{Name: "My Drive", URL: "/drive", Icon: "fas fa-folder", Active: r.URL.Path == "/drive"},
			// 	{Name: "Shared with Me", URL: "/drive/shared", Icon: "fas fa-folder-open", Active: strings.HasPrefix(r.URL.Path, "/drive/shared")},
			// }},
			// {Name: "Meetings", URL: "/meetings", Icon: "fas fa-video", Active: strings.HasPrefix(r.URL.Path, "/meetings")},
			// {Name: "Chat", URL: "/chat", Icon: "fas fa-comments", Active: strings.HasPrefix(r.URL.Path, "/chat")},
			// {Name: "Billing", URL: "/billing", Icon: "fas fa-credit-card", Active: strings.HasPrefix(r.URL.Path, "/billing")},
			{Name: "Admin", URL: "/admin", Icon: "fas fa-code", Active: false, SubItems: []component.MenuItem{
				{Name: "Users", URL: "/admin/users", Icon: "fas fa-users", Active: false},
				// {Name: "API Documentation", URL: "/admin", Icon: "fas fa-book", Active: c.Path() == "/admin"},
				{Name: "Clients", URL: "/admin/clients", Icon: "fas fa-laptop-code", Active: false},
				// {Name: "Webhooks", URL: "/admin/webhooks", Icon: "fas fa-rss", Active: strings.HasPrefix(r.URL.Path, "/admin/webhooks")},
				// {Name: "Logs", URL: "/admin/logs", Icon: "fas fa-file-alt", Active: strings.HasPrefix(r.URL.Path, "/admin/logs")},
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

func (h *PageHandler) ShowHomePage(ctx context.Context, req *http.Request, res *http.Response) error {
	return res.SendRedirect("/dashboard", http.StatusSeeOther)
}

func (h *PageHandler) ShowDocsPage(ctx context.Context, req *http.Request, res *http.Response) error {
	return ui.Render(ctx, res, views.DocsPage(views.DocsPageProps{
		LayoutProps: ui.LayoutProps(ctx, "API Documentation", h.Translator),
	}))
}

func (h *PageHandler) ShowDashboardPage(ctx context.Context, req *http.Request, res *http.Response) error {
	return ui.Render(ctx, res, views.DashboardPage(views.DashboardPageProps{
		AppLayoutProps: h.appLayoutProps(ctx, "Dashboard"),
	}))
}

func (h *PageHandler) ShowLoginPage(ctx context.Context, req *http.Request, res *http.Response) error {
	sess := ctx.Value(config.SessionContextKey).(session.Session)
	defer func() {
		if err := h.SessionStore.Update(ctx, sess); err != nil {
			h.Logger.Error("Failed to update session", "error", err)
		}
	}()

	if sess.UserID.IsSet {
		return res.SendRedirect("/dashboard", http.StatusSeeOther) // Redirect if already logged in
	}

	// Store the return_to query parameter in session for post-login redirection
	returnToRaw := req.URLQueryParam("return_to")

	return ui.Render(ctx, res, views.LoginPage(views.LoginPageProps{
		LayoutProps: ui.LayoutProps(ctx, "Login", h.Translator),
		ReturnTo:    returnToRaw,
	}))
}

type LoginRequestBody struct {
	Email      string `json:"email"`
	Password   string `json:"password"`
	RememberMe bool   `json:"remember_me"`
	ReturnTo   string `json:"return_to"`
}

func (h *PageHandler) Login(ctx context.Context, req *http.Request, res *http.Response) error {
	sess := ctx.Value(config.SessionContextKey).(session.Session)
	defer func() {
		if err := h.SessionStore.Update(ctx, sess); err != nil {
			h.Logger.Error("Failed to update session", "error", err)
		}
	}()

	// Get JSON data
	var reqBody LoginRequestBody
	if err := req.DecodeJSON(&reqBody); err != nil {
		h.Logger.Error("Failed to decode login request", "error", err)
		res.SetStatus(http.StatusBadRequest)
		return res.SendJSON(JSONResponseBody{
			Status:  ResponseStatusError,
			Message: "Invalid request payload",
		})
	}

	// Basic validation
	if reqBody.Email == "" || reqBody.Password == "" {
		res.SetStatus(http.StatusBadRequest)
		return res.SendJSON(JSONResponseBody{
			Status:  ResponseStatusError,
			Message: "Email and password are required",
		})
	}

	// Fetch user by email
	userID, err := h.Authenticator.Login(ctx, auth.LoginParam{
		Email:    reqBody.Email,
		Password: reqBody.Password,
	})
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			res.SetStatus(http.StatusUnauthorized)
			return res.SendJSON(JSONResponseBody{
				Status:  ResponseStatusError,
				Message: "Invalid email or password",
			})
		}

		h.Logger.Error("Failed to authenticate user", "error", err)
		res.SetStatus(http.StatusInternalServerError)
		return res.SendJSON(JSONResponseBody{
			Status:  ResponseStatusError,
			Message: "Internal server error",
		})
	}

	// Determine session duration based on "Remember Me" option
	var sessionDuration time.Duration
	if reqBody.RememberMe {
		sessionDuration = 30 * 24 * time.Hour // 30 days
	} else {
		sessionDuration = 2 * time.Hour // 2 hours
	}
	sess.ExpiresAt = time.Now().Add(sessionDuration)

	// Set user ID in session
	sess.UserID = util.Some(userID)

	// Regenerate session ID to prevent fixation TODO look into this
	sess, err = h.SessionStore.Regenerate(ctx, res, sess)
	if err != nil {
		h.Logger.Error("Failed to regenerate session ID", "error", err)
		// Fallback: just clear the user data
		sess.UserID = util.None[uuid.UUID]()
		sess.Data = session.SessionData{} // Clear all session data
		if updateErr := h.SessionStore.Update(ctx, sess); updateErr != nil {
			h.Logger.Error("Failed to update session during login", "error", updateErr)
		}
	}

	// Determine redirect URL
	redirectTo := "/dashboard"
	if reqBody.ReturnTo != "" {
		redirectTo = reqBody.ReturnTo
	}

	res.SetHeader("X-Redirect-To", redirectTo)
	return res.SendJSON(JSONResponseBody{
		Status:  ResponseStatusSuccess,
		Message: "Login successful",
	})
}

func (h *PageHandler) Logout(ctx context.Context, req *http.Request, res *http.Response) error {
	sess := ctx.Value(config.SessionContextKey).(session.Session)

	// Perform logout operations
	if sess.UserID.IsSet {
		if err := h.Authenticator.Logout(ctx, sess.UserID.Val); err != nil {
			h.Logger.Error("Failed to sign out user", "error", err)
			// Continue with logout even if this fails
		}

		h.Logger.Info("User logged out", "user_id", sess.UserID.Val)
		// Clear user ID from session
		sess.Clear()
	}

	// Clear all session data and regenerate session ID
	newSess, err := h.SessionStore.Regenerate(ctx, res, sess)
	if err != nil {
		h.Logger.Error("Failed to regenerate session during logout", "error", err)
		// Fallback: just clear the user data
		sess.UserID = util.None[uuid.UUID]()
		sess.Data = session.SessionData{} // Clear all session data
		if updateErr := h.SessionStore.Update(ctx, sess); updateErr != nil {
			h.Logger.Error("Failed to update session during logout", "error", updateErr)
		}
	} else {
		// Successfully regenerated session - new session is already saved
		sess = newSess
	}

	// Determine redirect URL
	redirectTo := req.URLQueryParam("redirect_to")
	if redirectTo == "" {
		redirectTo = "/login"
	}

	// Regular form request - redirect directly
	res.SetHeader("X-Redirect-To", redirectTo)
	return res.SendJSON(JSONResponseBody{
		Status:  ResponseStatusSuccess,
		Message: "Logout successful! Continue to login.",
	})
}

func (h *PageHandler) ShowRegisterPage(ctx context.Context, req *http.Request, res *http.Response) error {
	return ui.Render(ctx, res, views.RegisterPage(views.RegisterPageProps{
		LayoutProps: ui.LayoutProps(ctx, "Register", h.Translator),
	}))
}

type RegisterRequestBody struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (h *PageHandler) Register(ctx context.Context, req *http.Request, res *http.Response) error {
	sess := ctx.Value(config.SessionContextKey).(session.Session)
	defer func() {
		if err := h.SessionStore.Update(ctx, sess); err != nil {
			h.Logger.Error("Failed to update session", "error", err)
		}
	}()

	// Get form data
	var reqBody RegisterRequestBody
	if err := req.DecodeJSON(&reqBody); err != nil {
		h.Logger.Error("Failed to decode register request", "error", err)
		res.SetStatus(http.StatusBadRequest)
		return res.SendJSON(JSONResponseBody{
			Status:  ResponseStatusError,
			Message: "Invalid request",
		})
	}

	// Basic validation
	if reqBody.Name == "" || reqBody.Email == "" || reqBody.Password == "" {
		res.SetStatus(http.StatusBadRequest)
		return res.SendJSON(JSONResponseBody{
			Status:  ResponseStatusError,
			Message: "All fields are required",
		})
	}

	// Check if user already exists
	userID, err := h.Authenticator.Register(ctx, auth.RegisterParam{
		Name:     reqBody.Name,
		Email:    reqBody.Email,
		Password: reqBody.Password,
	})
	if err != nil {
		if errors.Is(err, auth.ErrEmailAlreadyInUse) {
			res.SetStatus(http.StatusBadRequest)
			return res.SendJSON(JSONResponseBody{
				Status:  ResponseStatusError,
				Message: "Email already in use",
			})
		}

		h.Logger.Error("Failed to register user", "error", err)
		res.SetStatus(http.StatusInternalServerError)
		return res.SendJSON(JSONResponseBody{
			Status:  ResponseStatusError,
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

	// Set session in context
	ctx = context.WithValue(ctx, config.SessionContextKey, sess)

	// Redirect to dashboard after successful registration
	res.SetHeader("X-Redirect-To", "/dashboard")
	return res.SendJSON(JSONResponseBody{
		Status:  ResponseStatusSuccess,
		Message: "Registration successful! Continue to the app.",
	})
}

func (h *PageHandler) ShowUsersPage(ctx context.Context, req *http.Request, res *http.Response) error {
	// Get the list of users
	users, err := h.UserManager.ListUsers(ctx)
	if err != nil {
		h.Logger.Error("Failed to list users", "error", err)
		res.SetStatus(http.StatusInternalServerError)
		return res.SendJSON(JSONResponseBody{
			Status:  ResponseStatusError,
			Message: "Failed to load users",
		})
	}

	// Convert to view model
	viewUsers := make([]views.User, 0, len(users))
	for _, user := range users {
		viewUsers = append(viewUsers, views.User{
			ID:    user.ID.String(),
			Name:  user.Name,
			Email: user.Email,
			// CreatedAt: user.CreatedAt,
			// UpdatedAt: user.UpdatedAt,
		})
	}

	return ui.Render(ctx, res, views.UsersPage(views.UsersPageProps{
		AppLayoutProps: h.appLayoutProps(ctx, "Users"),
		Users:          viewUsers,
	}))
}

func (h *PageHandler) ShowClientsPage(ctx context.Context, req *http.Request, res *http.Response) error {
	// Get the list of OAuth clients for this user
	clients, err := h.OAuthManager.ListClients(ctx)
	if err != nil {
		h.Logger.Error("Failed to list OAuth clients", "error", err)
		res.SetStatus(http.StatusInternalServerError)
		return res.SendJSON(JSONResponseBody{
			Status:  ResponseStatusError,
			Message: "Failed to load OAuth clients",
		})
	}

	// Convert to view model
	viewClients := make([]views.Client, 0, len(clients))
	for _, client := range clients {
		viewClients = append(viewClients, views.Client{
			ID:           client.ID.String(),
			Name:         client.Name,
			Secret:       client.Secret,
			Description:  "", // Add a default empty description
			ModifiedAt:   client.ModifiedAt,
			RedirectURIs: client.RedirectURIs,
			IsPublic:     client.IsPublic,
			Scopes:       client.Scopes,
		})
	}

	// Define available scopes (could be fetched from config or database)
	scopes := h.OAuthManager.ListScopes()
	viewScopes := make([]views.Scope, 0, len(scopes))
	for value, description := range scopes {
		viewScopes = append(viewScopes, views.Scope{
			Name:        string(value),
			Description: description,
		})
	}

	return ui.Render(ctx, res, views.ClientsPage(views.ClientsPageProps{
		AppLayoutProps: h.appLayoutProps(ctx, "OAuth Clients"),
		Clients:        viewClients,
		Scopes:         viewScopes,
	}))
}

type CreateOAuthClientRequestBody struct {
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	RedirectURIs []string `json:"redirect_uris"`
	Public       bool     `json:"public"`
	Scopes       []string `json:"scopes"`
}

func (h *PageHandler) CreateClient(ctx context.Context, req *http.Request, res *http.Response) error {

	var reqBody CreateOAuthClientRequestBody
	if err := req.DecodeJSON(&reqBody); err != nil {
		h.Logger.Error("Failed to decode create OAuth client request", "error", err)
		res.SetStatus(http.StatusBadRequest)
		return res.SendJSON(JSONResponseBody{
			Status:  ResponseStatusError,
			Message: "Invalid request payload",
		})
	}

	// Trim whitespace from all fields
	reqBody.Name = strings.TrimSpace(reqBody.Name)
	reqBody.Description = strings.TrimSpace(reqBody.Description)
	for i, uri := range reqBody.RedirectURIs {
		reqBody.RedirectURIs[i] = strings.TrimSpace(uri)
	}
	for i, scope := range reqBody.Scopes {
		reqBody.Scopes[i] = strings.TrimSpace(scope)
	}

	// Validation
	if reqBody.Name == "" {
		res.SetStatus(http.StatusBadRequest)
		return res.SendJSON(JSONResponseBody{
			Status:  ResponseStatusError,
			Message: "Name is required",
		})
	}

	if len(reqBody.RedirectURIs) == 0 {
		res.SetStatus(http.StatusBadRequest)
		return res.SendJSON(JSONResponseBody{
			Status:  ResponseStatusError,
			Message: "At least one redirect URI is required",
		})
	}

	client, err := h.OAuthManager.CreateClient(ctx, oauth.CreateClientParams{
		Name:          reqBody.Name,
		IsPublic:      reqBody.Public,
		RedirectURIs:  reqBody.RedirectURIs,
		AllowedScopes: reqBody.Scopes,
	})
	if err != nil {
		h.Logger.Error("Failed to create OAuth client", "error", err)
		res.SetStatus(http.StatusInternalServerError)
		return res.SendJSON(JSONResponseBody{
			Status:  ResponseStatusError,
			Message: "Failed to create OAuth client",
		})
	}

	// Return the newly created client details, including the secret
	// (this is the only time the secret will be fully visible)
	return res.SendJSON(JSONResponseBody{
		Status: ResponseStatusSuccess,
		Data: map[string]any{
			"id":           client.ID.String(),
			"name":         client.Name,
			"redirectURIs": client.RedirectURIs,
			"public":       false,
			"secret":       client.Secret,
			"scopes":       client.Scopes,
		},
	})
}

type DeleteOAuthClientRequestBody struct {
	ClientID string `json:"client_id"`
}

func (h *PageHandler) DeleteClient(ctx context.Context, req *http.Request, res *http.Response) error {

	var reqBody DeleteOAuthClientRequestBody
	if err := req.DecodeJSON(&reqBody); err != nil {
		h.Logger.Error("Failed to decode delete OAuth client request", "error", err)
		res.SetStatus(http.StatusBadRequest)
		return res.SendJSON(JSONResponseBody{
			Status:  ResponseStatusError,
			Message: "Invalid request payload",
		})
	}

	clientIDStr := strings.TrimSpace(reqBody.ClientID)

	clientID, err := uuid.Parse(clientIDStr)
	if err != nil {
		h.Logger.Error("Invalid client ID format", "error", err, "client_id", clientIDStr)
		res.SetStatus(http.StatusBadRequest)
		return res.SendJSON(JSONResponseBody{
			Status:  ResponseStatusError,
			Message: "Invalid client ID",
		})
	}

	// Check if the client exists and belongs to the user
	_, err = h.OAuthManager.GetClientByID(ctx, clientID)
	if err != nil {
		if err == database.ErrOAuthClientNotFound {
			h.Logger.Error("OAuth client not found", "error", err, "client_id", clientID)
			res.SetStatus(http.StatusNotFound)
			return res.SendJSON(JSONResponseBody{
				Status:  ResponseStatusError,
				Message: "OAuth client not found",
			})
		}
		h.Logger.Error("Failed to get OAuth client for deletion", "error", err, "client_id", clientID)
		return res.SendJSON(JSONResponseBody{
			Status:  ResponseStatusError,
			Message: "Failed to retrieve OAuth client",
		})
	}

	// Delete the client
	if err := h.OAuthManager.DeleteClientByID(ctx, clientID); err != nil {
		h.Logger.Error("Failed to delete OAuth client", "error", err, "client_id", clientID)
		return res.SendJSON(JSONResponseBody{
			Status:  ResponseStatusError,
			Message: "Failed to retrieve OAuth client",
		})
	}

	// Delete the client
	if err := h.OAuthManager.DeleteClientByID(ctx, clientID); err != nil {
		h.Logger.Error("Failed to delete OAuth client", "error", err, "client_id", clientID)
		res.SetStatus(http.StatusInternalServerError)
		return res.SendJSON(JSONResponseBody{
			Status:  ResponseStatusError,
			Message: "Failed to delete OAuth client",
		})
	}

	// Redirect back to the developer page after deletion
	return res.SendJSON(JSONResponseBody{
		Status:  ResponseStatusSuccess,
		Message: "OAuth client deleted successfully",
	})
}

type ResponseStatus string

const (
	ResponseStatusSuccess ResponseStatus = "success"
	ResponseStatusError   ResponseStatus = "error"
)

// Response body format for API
type JSONResponseBody struct {
	Status  ResponseStatus `json:"status"`
	Message string         `json:"message,omitempty"`
	Data    any            `json:"data,omitempty"`
}
