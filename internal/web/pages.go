package web

import (
	"context"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"hp/internal/auth"
	"hp/internal/config"
	"hp/internal/database"
	"hp/internal/i18n"
	"hp/internal/openfga"
	"hp/internal/session"
	"hp/internal/subscription"
	"hp/internal/util"
	"hp/internal/web/translate"
	"hp/internal/web/views"
	"hp/internal/web/views/component"
	"hp/internal/webhook"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/a-h/templ"
	"github.com/google/uuid"
)

func init() {
	gob.Register(uuid.UUID{}) // Register uuid.UUID for session storage
}

type PageHandler struct {
	logger              *slog.Logger
	translator          *i18n.Translator
	sessionStore        *session.Store
	db                  *database.Database
	authorization       *openfga.AuthorizationService
	authenticator       *auth.Authenticator
	webhookManager      *webhook.Manager
	subscriptionManager *subscription.Manager
}

func NewPageHandler(logger *slog.Logger, translator *i18n.Translator, sessionStore *session.Store, db *database.Database, authenticator *auth.Authenticator, webhookManager *webhook.Manager, subscriptionManager *subscription.Manager) *PageHandler {
	return &PageHandler{logger: logger, translator: translator, sessionStore: sessionStore, db: db, authenticator: authenticator, webhookManager: webhookManager, subscriptionManager: subscriptionManager}
}

func (h *PageHandler) layoutProps(ctx context.Context, title string) component.LayoutProps {
	lang := ctx.Value(config.LanguageContextKey).(i18n.Language)
	translator := translate.Translator{
		Translator: h.translator,
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
	recentNotifications, err := h.db.ListNotifications(ctx, database.ListNotificationsParams{
		OwnerID:          util.Some(userID),
		Limit:            util.Some(int32(10)),
		OrderByCreatedAt: util.Some(database.OrderByDESC),
	})
	if err != nil {
		h.logger.Error("Failed to get recent notifications", "error", err)
		recentNotifications = []database.Notification{}
	}

	// Count unread notifications
	unreadNotifications, err := h.db.ListNotifications(ctx, database.ListNotificationsParams{
		OwnerID: util.Some(userID),
		Read:    util.Some(false),
	})
	if err != nil {
		h.logger.Error("Failed to get unread notifications count", "error", err)
		unreadNotifications = []database.Notification{}
	}

	// Convert notifications to component format
	componentNotifications := make([]component.Notification, len(recentNotifications))
	for i, dbNotification := range recentNotifications {
		componentNotifications[i] = component.Notification{
			ID:        dbNotification.ID.String(),
			Title:     dbNotification.Title,
			Message:   dbNotification.Message,
			Type:      dbNotification.Type,
			IsRead:    dbNotification.IsRead,
			ActionURL: dbNotification.ActionURL,
			CreatedAt: dbNotification.CreatedAt.Format("2 Jan 2006 15:04"),
		}
	}

	return component.AppLayoutProps{
		LayoutProps: layoutProps,
		MenuItems: []component.MenuItem{
			{Name: "Home", URL: "/dashboard", Icon: "fas fa-home", Active: r.URL.Path == "/dashboard"},
			{Name: "Calendar", URL: "/calendar", Icon: "fas fa-calendar", Active: strings.HasPrefix(r.URL.Path, "/calendar")},
			{Name: "Drive", URL: "/drive", Icon: "fas fa-folder", Active: strings.HasPrefix(r.URL.Path, "/drive"), SubItems: []component.MenuItem{
				{Name: "My Drive", URL: "/drive", Icon: "fas fa-folder", Active: r.URL.Path == "/drive"},
				{Name: "Shared with Me", URL: "/drive/shared", Icon: "fas fa-folder-open", Active: strings.HasPrefix(r.URL.Path, "/drive/shared")},
			}},
			{Name: "Meetings", URL: "/meetings", Icon: "fas fa-video", Active: strings.HasPrefix(r.URL.Path, "/meetings")},
			{Name: "Billing", URL: "/billing", Icon: "fas fa-credit-card", Active: strings.HasPrefix(r.URL.Path, "/billing")},
			{Name: "Developers", URL: "/developers", Icon: "fas fa-code", Active: strings.HasPrefix(r.URL.Path, "/developers"), SubItems: []component.MenuItem{
				// {Name: "API Documentation", URL: "/developers", Icon: "fas fa-book", Active: c.Path() == "/developers"},
				{Name: "Clients", URL: "/developers/clients", Icon: "fas fa-laptop-code", Active: strings.HasPrefix(r.URL.Path, "/developers/clients")},
				{Name: "Webhooks", URL: "/developers/webhooks", Icon: "fas fa-rss", Active: strings.HasPrefix(r.URL.Path, "/developers/webhooks")},
				{Name: "Logs", URL: "/developers/logs", Icon: "fas fa-file-alt", Active: strings.HasPrefix(r.URL.Path, "/developers/logs")},
			}},
		},
		HasUnreadNotification: len(unreadNotifications) > 0,
		UnreadCount:           len(unreadNotifications),
		RecentNotifications:   componentNotifications,
	}
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

	sess, err := h.sessionStore.Get(ctx, r)
	if err != nil {
		return fmt.Errorf("failed to get session: %w", err)
	}
	defer func() {
		if err := h.sessionStore.Save(ctx, w, sess); err != nil {
			h.logger.Error("Failed to save session", "error", err)
		}
	}()

	if sess.UserID.Some {
		return Redirect(w, r, "/dashboard", http.StatusSeeOther) // Redirect if already logged in
	}

	// Store the return_to query parameter in session for post-login redirection
	redirectToRaw := r.URL.Query().Get("return_to")
	if redirectToRaw != "" {
		sess.Data["redirect_to"] = redirectToRaw
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

	sess, err := h.sessionStore.Get(ctx, r)
	if err != nil {
		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Failed to get session",
		})
	}
	defer func() {
		if err := h.sessionStore.Save(ctx, w, sess); err != nil {
			h.logger.Error("Failed to save session", "error", err)
		}
	}()

	// Get JSON data
	var loginReq LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&loginReq); err != nil {
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Invalid request payload",
		})
	}

	// Basic validation
	if loginReq.Email == "" || loginReq.Password == "" {
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Email and password are required",
		})
	}

	// Fetch user by email
	userID, err := h.authenticator.Login(ctx, auth.LoginParam{
		Email:    loginReq.Email,
		Password: loginReq.Password,
	})
	if err != nil {
		return JSONResponse(w, http.StatusUnauthorized, ApiResponse{
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

	if sess.Data["redirect_to"] != nil {
		redirectTo = sess.Data["redirect_to"].(string)
		// Clear the redirect_to after using it
		delete(sess.Data, "redirect_to")
	}

	return JSONResponse(w, http.StatusOK, ApiResponse{
		Status:  APIResponseStatusSuccess,
		Message: "Login successful! Redirecting...",
		Data: map[string]string{
			"redirect_to": redirectTo,
		},
	})
}

func (h *PageHandler) Logout(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	sess, err := h.sessionStore.Get(ctx, r)
	if err != nil {
		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Failed to get session",
		})
	}
	defer func() {
		if err := h.sessionStore.Save(ctx, w, sess); err != nil {
			h.logger.Error("Failed to save session", "error", err)
		}
	}()

	if err := h.authenticator.Logout(ctx, sess.UserID.Data); err != nil {
		h.logger.Error("Failed to sign out user", "error", err)
	}

	if err := h.sessionStore.Destroy(ctx, w, sess); err != nil {
		h.logger.Error("Failed to destroy session", "error", err)
	}

	return JSONResponse(w, http.StatusOK, ApiResponse{
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

func (h *PageHandler) Register(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	sess, err := h.sessionStore.Get(ctx, r)
	if err != nil {
		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Failed to get session",
		})
	}
	defer func() {
		if err := h.sessionStore.Save(ctx, w, sess); err != nil {
			h.logger.Error("Failed to save session", "error", err)
		}
	}()

	// Get form data
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Error("Failed to decode register request", "error", err)
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Invalid request",
		})
	}

	// Basic validation
	if req.Name == "" || req.Email == "" || req.Password == "" {
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "All fields are required",
		})
	}

	if len(req.Password) < 8 {
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Password must be at least 8 characters long",
		})
	}

	if !req.TermsAccepted {
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "You must accept the terms and conditions",
		})
	}

	// Check if user already exists
	userID, err := h.authenticator.Register(ctx, auth.RegisterParam{
		Name:     req.Name,
		Email:    req.Email,
		Password: req.Password,
	})
	if err != nil {
		if errors.Is(err, auth.ErrEmailAlreadyInUse) {
			return JSONResponse(w, http.StatusBadRequest, ApiResponse{
				Status:  APIResponseStatusError,
				Message: "Email already in use",
			})
		}

		h.logger.Error("Failed to register user", "error", err)
		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
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

	return JSONResponse(w, http.StatusOK, ApiResponse{
		Status:  APIResponseStatusSuccess,
		Message: "Registration successful! Continue to the app.",
		Data: map[string]any{
			"redirect_to": "/dashboard",
		},
	})
}

func (h *PageHandler) ShowBillingPage(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	return render(ctx, w, views.BillingPage(views.BillingPageProps{
		AppLayoutProps: h.appLayoutProps(ctx, h.layoutProps(ctx, "Billing"), r),
	}))
}

type ChangeSubscriptionRequest struct {
	NewPlan string `json:"new_plan"` // e.g., "free", "pro", "enterprise"
}

func (h *PageHandler) ChangeSubscription(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	userID := ctx.Value(config.UserIDContextKey).(uuid.UUID)

	var req ChangeSubscriptionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Error("Failed to decode change subscription request", "error", err)
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Invalid request",
		})
	}

	if req.NewPlan == "" {
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "New plan is required",
		})
	}

	var plan subscription.Plan
	switch req.NewPlan {
	case "free":
		plan = subscription.PlanFree
	case "pro":
		plan = subscription.PlanPro
	// case "enterprise":
	// 	plan = subscription.PlanEnterprise
	default:
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Invalid plan selected",
		})
	}

	if err := h.subscriptionManager.ChangeSubscription(ctx, userID, plan); err != nil {
		h.logger.Error("Failed to change subscription", "error", err)
		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Failed to change subscription",
		})
	}

	return JSONResponse(w, http.StatusOK, ApiResponse{
		Status:  APIResponseStatusSuccess,
		Message: "Subscription changed successfully",
	})
}

// func (h *PageHandler) CreateCheckoutSession(w http.ResponseWriter, r *http.Request) error {
// 	params := &stripe.CheckoutSessionParams{

// 	}
// }

// func (h *PageHandler) UpdateBilling(w http.ResponseWriter, r *http.Request) error {
// 	stripe.Key = "sk_test_51Rm9NXRpsw6KPSOTjxYsYKz1oMczIt9tbWJqYpS58mwkDyCcU6T5pDuMCOu5J1tisAzoxrUuXwjacjwaWxV1liad00S5SBnCid"

// 	domain := "https://webhook.site/9c023c39-c641-4d41-97c9-850555964554" // Replace with your actual domain

// 	priceTable := map[string]string{
// 		"free":       "",
// 		"pro":        "price_1Rrg4RRpsw6KPSOT3xe54iWO",
// 		"enterprise": "price_1Rrg54Rpsw6KPSOTW3K8Ur3L",
// 	}

// 	priceID := c.FormValue("price")
// 	price, exists := priceTable[priceID]
// 	if !exists {
// 		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Invalid price selected",
// 		})
// 	}

// 	checkoutParams := &stripe.CheckoutSessionParams{
// 		Mode: stripe.String(string(stripe.CheckoutSessionModeSubscription)),
// 		LineItems: []*stripe.CheckoutSessionLineItemParams{
// 			{
// 				Price:    stripe.String(price),
// 				Quantity: stripe.Int64(1),
// 			},
// 		},
// 		SuccessURL: stripe.String(domain + "/success.html?session_id={CHECKOUT_SESSION_ID}"),
// 		CancelURL:  stripe.String(domain + "/cancel.html"),
// 	}

// 	s, err := stripeSession.New(checkoutParams)
// 	if err != nil {
// 		log.Printf("session.New: %v", err)
// 		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Failed to create checkout session",
// 		})
// 	}

// 	return JSONResponse(w, http.StatusOK, ApiResponse{
// 		Status: APIResponseStatusSuccess,
// 		Data: map[string]any{
// 			"redirect": s.URL,
// 		},
// 	})
// }

func (h *PageHandler) ShowMyDrivePage(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	userID := ctx.Value(config.UserIDContextKey).(uuid.UUID)

	files, err := h.db.ListFiles(ctx, database.ListFilesParams{
		OwnerID:  util.Some(userID),
		ParentID: util.Some(util.None[uuid.UUID]()), // Root folder
	})
	if err != nil {
		h.logger.Error("Failed to get files for folder", "error", err)
		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Failed to load files for folder",
		})
	}

	viewFiles := make([]views.File, 0, len(files))
	for _, file := range files {
		viewFiles = append(viewFiles, views.File{
			ID:          file.ID.String(),
			Name:        file.Name,
			Size:        file.SizeBytes,
			MimeType:    file.MimeType,
			IsFolder:    file.MimeType == "application/askfrank.folder",
			IsViewable:  file.MimeType == "application/pdf" || file.MimeType == "application/image",
			DownloadURL: "/drive/download_file/" + file.ID.String() + "/download",
		})
	}

	// Build breadcrumbs
	// breadcrumbs := make([]views.Breadcrumb, 0)
	// breadcrumbs = append(breadcrumbs, views.Breadcrumb{
	// 	Name: "My Drive",
	// 	URL:  "/drive",
	// })

	breadcrumbs := []views.Breadcrumb{
		{
			Name: "My Drive",
			URL:  "/drive",
		},
	}
	// if params.InFolder != uuid.Nil {
	// 	parentFiles, err := h.db.GetParentFolders(ctx, userID, params.InFolder)
	// 	if err != nil {
	// 		h.logger.Error("Failed to get parent folders for breadcrumb", "error", err, "file_id", params.InFolder.UUID)
	// 		// If we can't get parent folders, just show the file name
	// 		breadcrumbs = append(breadcrumbs, views.Breadcrumb{
	// 			Name: options.InFolder.UUID.String(),
	// 			URL:  "/drive/folder/" + options.InFolder.UUID.String(),
	// 		})
	// 	} else {
	// 		for _, parentFile := range parentFiles {
	// 			breadcrumbs = append(breadcrumbs, views.Breadcrumb{
	// 				Name: parentFile.Name,
	// 				URL:  "/drive/folder/" + parentFile.ID.String(),
	// 			})
	// 		}
	// 	}
	// }

	currentFolderID := ""
	return render(ctx, w, views.DrivePage(views.DrivePageProps{
		AppLayoutProps:  h.appLayoutProps(ctx, h.layoutProps(ctx, "My Drive"), r),
		Files:           viewFiles,
		Breadcrumbs:     breadcrumbs,
		CurrentFolderID: currentFolderID,
	}))
}

type CreateFolderRequest struct {
	Name     string `json:"name"`
	ParentID string `json:"parent_id"`
}

func (h *PageHandler) CreateFolder(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	userID := ctx.Value(config.UserIDContextKey).(uuid.UUID)

	// Parse request
	var requestBody CreateFolderRequest
	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Failed to parse request",
		})
	}

	// Validation
	if requestBody.Name == "" {
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Name is required",
		})
	}

	parentID := util.None[uuid.UUID]()
	if requestBody.ParentID != "" {
		parentIDRaw, err := uuid.Parse(requestBody.ParentID)
		if err != nil {
			return JSONResponse(w, http.StatusBadRequest, ApiResponse{
				Status:  APIResponseStatusError,
				Message: "Invalid Parent ID",
			})
		}
		parentID = util.Some(parentIDRaw)
	}

	// Create folder in database
	folder, err := h.db.CreateFile(ctx, database.CreateFileParams{
		OwnerID:   userID,
		Name:      requestBody.Name,
		ParentID:  parentID,
		MimeType:  "application/askfrank.folder",
		Path:      util.None[string](),
		S3Key:     util.None[string](),
		SizeBytes: 0,
	})
	if err != nil {
		h.logger.Error("Failed to create folder", "error", err)
		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Failed to create folder",
		})
	}

	return JSONResponse(w, http.StatusCreated, ApiResponse{
		Status:  APIResponseStatusSuccess,
		Message: "Folder created successfully",
		Data: map[string]any{
			"folder_id": folder.ID.String(),
		},
	})
}

type UploadFileRequest struct {
	FolderID string `json:"folder_id"`
}

func (h *PageHandler) UploadFile(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	userID := ctx.Value(config.UserIDContextKey).(uuid.UUID)

	// Get folder ID from form data (optional)
	var uploadReq UploadFileRequest

	if err := json.NewDecoder(r.Body).Decode(&uploadReq); err != nil {
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Failed to parse request",
		})
	}

	var folderID util.Optional[uuid.UUID]
	if folderIDStr := uploadReq.FolderID; folderIDStr != "" {
		id, err := uuid.Parse(folderIDStr)
		if err != nil {
			return JSONResponse(w, http.StatusBadRequest, ApiResponse{
				Status:  APIResponseStatusError,
				Message: "Invalid folder ID",
			})
		}
		folderID = util.Some(id)
	}

	// Parse multipart form
	if err := r.ParseMultipartForm(32 << 20); err != nil { // 32 MB
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Failed to parse multipart form",
		})
	}

	files := r.MultipartForm.File["files"]
	if len(files) == 0 {
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "No files provided",
		})
	}

	// Create uploads directory if it doesn't exist
	uploadDir := "uploads"
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		slog.Error("Failed to create upload directory", "error", err)
		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Failed to create upload directory",
		})
	}

	var uploadedFiles []map[string]any

	for _, fileHeader := range files {
		// Generate unique filename
		ext := filepath.Ext(fileHeader.Filename)
		baseFilename := strings.TrimSuffix(fileHeader.Filename, ext)
		uniqueFilename := baseFilename + "_" + uuid.New().String() + ext
		filePath := filepath.Join(uploadDir, uniqueFilename)

		// Open the uploaded file
		srcFile, err := fileHeader.Open()
		if err != nil {
			slog.Error("Failed to open uploaded file", "error", err, "filename", fileHeader.Filename)
			continue
		}
		defer srcFile.Close()

		// Create destination file
		dstFile, err := os.Create(filePath)
		if err != nil {
			slog.Error("Failed to create destination file", "error", err, "filename", fileHeader.Filename)
			continue
		}
		defer dstFile.Close()

		if _, err := io.Copy(dstFile, srcFile); err != nil {
			slog.Error("Failed to save uploaded file", "error", err, "filename", fileHeader.Filename)
			// Try to delete the partially saved file
			os.Remove(filePath)
			continue
		}

		// Re-open the file to read its header for MIME type detection
		savedFile, err := os.Open(filePath)
		if err != nil {
			slog.Error("Failed to open saved file for MIME type detection", "error", err, "filename", fileHeader.Filename)
			// Try to delete the saved file
			os.Remove(filePath)
			continue
		}
		defer savedFile.Close()

		buffer := make([]byte, 512)
		if _, err := savedFile.Read(buffer); err != nil {
			slog.Error("Failed to read file header for MIME type detection", "error", err, "filename", fileHeader.Filename)
			// Try to delete the saved file
			os.Remove(filePath)
			continue
		}

		fileHeader.Header.Set("Content-Type", http.DetectContentType(buffer))

		// Reset file pointer
		if _, err := savedFile.Seek(0, 0); err != nil {
			slog.Error("Failed to reset file pointer", "error", err, "filename", fileHeader.Filename)
			// Try to delete the saved file
			os.Remove(filePath)
			continue
		}

		// Optionally, you can implement virus scanning here

		// Optionally, upload to S3 or another storage service here and get the S3 key

		// For this example, we'll just store the local file path
		// In a real application, you might want to store a URL or S3 key instead

		// Determine MIME type
		mimeType := fileHeader.Header.Get("Content-Type")
		if mimeType == "" {
			mimeType = "application/octet-stream"
		}

		// Create file record in database
		file, err := h.db.CreateFile(ctx, database.CreateFileParams{
			OwnerID:   userID,
			ParentID:  folderID,
			Name:      fileHeader.Filename,
			MimeType:  mimeType,
			S3Key:     util.None[string](),
			Path:      util.Some(filePath),
			SizeBytes: fileHeader.Size,
		})
		if err != nil {
			slog.Error("Failed to create file record", "error", err, "filename", fileHeader.Filename)
			// Try to delete the saved file
			os.Remove(filePath)
			continue
		}

		// if err := h.authorization.AddFileReader(ctx, userID, file.ID); err != nil {
		// 	slog.Error("Failed to add file reader permission", "error", err, "user_id", userID, "file_id", file.ID)
		// 	// Try to delete the saved file and database record
		// 	os.Remove(filePath)
		// 	if err := h.db.DeleteFile(ctx, file.ID); err != nil {
		// 		slog.Error("Failed to delete file record after permission error", "error", err, "file_id", file.ID)
		// 	}
		// 	continue
		// }

		uploadedFiles = append(uploadedFiles, map[string]any{
			"id":       file.ID,
			"name":     file.Name,
			"size":     file.SizeBytes,
			"mimeType": file.MimeType,
		})
	}

	if len(uploadedFiles) == 0 {
		slog.Error("No files were uploaded successfully")
		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Failed to upload any files",
		})
	}

	return JSONResponse(w, http.StatusCreated, ApiResponse{
		Status: APIResponseStatusSuccess,
		Data:   uploadedFiles,
	})
}

type ShareFileRequest struct {
	FileID string `json:"file_id"`
	Email  string `json:"email"`
}

func (h *PageHandler) ShareFile(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	userID := ctx.Value(config.UserIDContextKey).(uuid.UUID)

	var req ShareFileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Invalid request body",
		})
	}

	// Validation
	if req.FileID == "" || req.Email == "" {
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "File ID and email are required",
		})
	}

	fileID, err := uuid.Parse(req.FileID)
	if err != nil {
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Invalid file ID",
		})
	}

	// Get the user to share with
	shareWithUser, err := h.db.GetUserByEmail(ctx, req.Email)
	if err != nil {
		if err == database.ErrUserNotFound {
			return JSONResponse(w, http.StatusNotFound, ApiResponse{
				Status:  APIResponseStatusError,
				Message: "User to share with not found",
			})
		}

		h.logger.Error("Failed to get user by email", "error", err)
		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Something went wrong, please try again later",
		})
	}

	// Check if the file exists and belongs to the current user
	file, err := h.db.GetFileByID(ctx, fileID)
	if err != nil {
		if err == database.ErrFileNotFound {
			return JSONResponse(w, http.StatusNotFound, ApiResponse{
				Status:  APIResponseStatusError,
				Message: "File not found",
			})
		}

		h.logger.Error("Failed to get file by ID", "error", err)
		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Something went wrong, please try again later",
		})
	}

	if file.OwnerID != userID {
		return JSONResponse(w, http.StatusForbidden, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "You do not have permission to share this file",
		})
	}

	if file.OwnerID != userID {
		return JSONResponse(w, http.StatusForbidden, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "You do not have permission to share this file",
		})
	}

	// Add permission in OpenFGA
	if err := h.authorization.AddFileReader(ctx, shareWithUser.ID, file.ID); err != nil {
		h.logger.Error("Failed to add file reader permission", "error", err)
		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Failed to share file",
		})
	}

	return JSONResponse(w, http.StatusOK, ApiResponse{
		Status:  APIResponseStatusSuccess,
		Message: "File shared successfully",
	})
}

type DownloadFileRequest struct {
	FileID string `json:"file_id"`
}

func (h *PageHandler) DownloadFile(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	userID := ctx.Value(config.UserIDContextKey).(uuid.UUID)

	var req DownloadFileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Invalid request body",
		})
	}

	fileID, err := uuid.Parse(req.FileID)
	if err != nil {
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Invalid file ID",
		})
	}

	// Check if the user has permission to access the file
	hasAccess, err := h.authorization.CanReadFile(ctx, userID, fileID)
	if err != nil {
		h.logger.Error("Failed to check file access", "error", err)
		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Failed to check file access",
		})
	}
	if !hasAccess {
		return JSONResponse(w, http.StatusForbidden, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "You do not have permission to access this file",
		})
	}

	file, err := h.db.GetFileByID(ctx, fileID)
	if err != nil {
		if err == database.ErrFileNotFound {
			return JSONResponse(w, http.StatusNotFound, ApiResponse{
				Status:  APIResponseStatusError,
				Message: "File not found",
			})
		}

		h.logger.Error("Failed to get file by ID", "error", err)
		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Something went wrong, please try again later",
		})
	}

	if !file.Path.Some {
		return JSONResponse(w, http.StatusNotFound, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "File not found on server",
		})
	}

	// Serve the file for download
	return Download(w, r, file.Path.Unwrap(), file.Name)
}

func (h *PageHandler) ShowSharedFilePage(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	userID := ctx.Value(config.UserIDContextKey).(uuid.UUID)

	sharedFiles, err := h.db.ListSharedFiles(ctx, database.ListSharedFilesParams{
		UserID: util.Some(userID),
	})
	if err != nil {
		h.logger.Error("Failed to get files for folder", "error", err)
		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Failed to load files for folder",
		})
	}

	viewFiles := make([]views.File, 0, len(sharedFiles))
	for _, file := range sharedFiles {
		viewFiles = append(viewFiles, views.File{
			ID:       file.ID.String(),
			Name:     file.Name,
			Size:     file.SizeBytes,
			MimeType: file.MimeType,
			IsFolder: file.MimeType == "application/askfrank.folder",
		})
	}

	// Build breadcrumbs
	breadcrumbs := make([]views.Breadcrumb, 0)
	breadcrumbs = append(breadcrumbs, views.Breadcrumb{
		Name: "Shared with me",
		URL:  "/drive/shared",
	})

	currentFolderID := ""
	return render(ctx, w, views.DrivePage(views.DrivePageProps{
		AppLayoutProps:  h.appLayoutProps(ctx, h.layoutProps(ctx, "Shared with me"), r),
		Files:           viewFiles,
		Breadcrumbs:     breadcrumbs,
		CurrentFolderID: currentFolderID,
	}))
}

func (h *PageHandler) ShowOAuthClientsPage(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	userID := ctx.Value(config.UserIDContextKey).(uuid.UUID)

	// Get the list of OAuth clients for this user
	clients, err := h.db.ListOAuthClients(ctx, database.ListOAuthClientsParams{
		OwnerID: util.Some(userID),
	})
	if err != nil {
		h.logger.Error("Failed to list OAuth clients", "error", err)
		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
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
			CreatedAt:    client.CreatedAt,
			RedirectURIs: client.RedirectURIs,
		})
	}

	return render(ctx, w, views.OAuthClientsPage(views.OAuthClientsPageProps{
		AppLayoutProps: h.appLayoutProps(ctx, h.layoutProps(ctx, "OAuth Clients"), r),
		Clients:        viewClients,
	}))
}

type CreateOAuthClientRequest struct {
	Name         string `json:"name"`
	RedirectURIs string `json:"redirect_uris"` // Newline-separated URIs
	Public       string `json:"public"`        // "true" or "false"
	Scopes       string `json:"scopes"`        // Comma-separated scopes
}

func (h *PageHandler) CreateOAuthClient(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	userID := ctx.Value(config.UserIDContextKey).(uuid.UUID)

	var req CreateOAuthClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Invalid request payload",
		})
	}

	// Validation
	if req.Name == "" {
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Name is required",
		})
	}

	if req.RedirectURIs == "" {
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "At least one redirect URI is required",
		})
	}

	// Process redirect URIs (split by newline)
	redirectURIs := strings.Split(req.RedirectURIs, "\n")
	for i, uri := range redirectURIs {
		redirectURIs[i] = strings.TrimSpace(uri)
	}

	// Filter out empty URIs
	var filteredURIs []string
	for _, uri := range redirectURIs {
		if uri != "" {
			filteredURIs = append(filteredURIs, uri)
		}
	}

	if len(filteredURIs) == 0 {
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "At least one valid redirect URI is required",
		})
	}

	// Process public flag
	isPublic := req.Public == "true"

	// Process scopes
	allowedScopes := strings.Split(req.Scopes, ",")
	for i, scope := range allowedScopes {
		allowedScopes[i] = strings.TrimSpace(scope)
	}

	// Create the client in the database
	secret, err := util.RandomString(32)
	if err != nil {
		h.logger.Error("Failed to generate client secret", "error", err)
		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Failed to generate client credentials",
		})
	}

	client, err := h.db.CreateOAuthClient(ctx, database.CreateOAuthClientParams{
		OwnerID:       userID,
		Name:          req.Name,
		RedirectURIs:  filteredURIs,
		Secret:        secret,
		IsPublic:      isPublic,
		AllowedScopes: allowedScopes,
	})
	if err != nil {
		h.logger.Error("Failed to create OAuth client", "error", err)
		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Failed to create OAuth client",
		})
	}

	// Return the newly created client details, including the secret
	// (this is the only time the secret will be fully visible)
	return JSONResponse(w, http.StatusCreated, ApiResponse{
		Status: APIResponseStatusSuccess,
		Data: map[string]any{
			"id":           client.ID.String(),
			"name":         client.Name,
			"redirectURIs": client.RedirectURIs,
			"public":       false,
			"secret":       client.Secret,
			"createdAt":    client.CreatedAt,
		},
	})
}

func (h *PageHandler) GetOAuthClient(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	// userID := c.Locals("user_id").(uuid.UUID)
	clientIDStr := r.PathValue("id")

	clientID, err := uuid.Parse(clientIDStr)
	if err != nil {
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Invalid client ID",
		})
	}

	client, err := h.db.GetOAuthClientByID(ctx, clientID)
	if err != nil {
		if err == database.ErrOAuthClientNotFound {
			return JSONResponse(w, http.StatusNotFound, ApiResponse{
				Status:  APIResponseStatusError,
				Message: "OAuth client not found",
			})
		}
		h.logger.Error("Failed to get OAuth client", "error", err, "client_id", clientID)
		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Failed to retrieve OAuth client",
		})
	}

	// Return the client details
	// Note: for security, we don't return the full client secret here
	// We return a masked version or nothing at all
	return JSONResponse(w, http.StatusOK, ApiResponse{
		Status: APIResponseStatusSuccess,
		Data: map[string]any{
			"id":           client.ID.String(),
			"name":         client.Name,
			"redirectURIs": client.RedirectURIs,
			"public":       client.IsPublic,
			"scopes":       client.AllowedScopes,
			"createdAt":    client.CreatedAt,
			"updatedAt":    client.UpdatedAt,
		},
	})
}

func (h *PageHandler) DeleteOAuthClient(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	// userID := c.Locals("user_id").(uuid.UUID)
	clientIDStr := r.PathValue("id")

	clientID, err := uuid.Parse(clientIDStr)
	if err != nil {
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Invalid client ID",
		})
	}

	// Check if the client exists and belongs to the user
	_, err = h.db.GetOAuthClientByID(ctx, clientID)
	if err != nil {
		if err == database.ErrOAuthClientNotFound {
			return JSONResponse(w, http.StatusNotFound, ApiResponse{
				Status:  APIResponseStatusError,
				Message: "OAuth client not found",
			})
		}
		h.logger.Error("Failed to get OAuth client for deletion", "error", err, "client_id", clientID)
		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Failed to retrieve OAuth client",
		})
	}

	// Delete the client
	if err := h.db.DeleteOAuthClientByID(ctx, clientID); err != nil {
		h.logger.Error("Failed to delete OAuth client", "error", err, "client_id", clientID)
		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Failed to delete OAuth client",
		})
	}

	// Redirect back to the developer page after deletion
	return JSONResponse(w, http.StatusOK, ApiResponse{
		Status:  APIResponseStatusSuccess,
		Message: "OAuth client deleted successfully",
		Data: map[string]any{
			"redirect_to": "/developer",
		},
	})
}

func (h *PageHandler) ShowFolderPage(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	userID := ctx.Value(config.UserIDContextKey).(uuid.UUID)

	folderIDStr := ctx.Value("folder_id").(string)
	if folderIDStr == "" {
		return Redirect(w, r, "/drive", http.StatusSeeOther)
	}

	// Validate folder ID
	folderID, err := uuid.Parse(folderIDStr)
	if err != nil {
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Invalid folder ID",
		})
	}

	// Check if the user has access to this folder
	ok, err := h.authorization.CanReadFile(ctx, userID, folderID)
	if err != nil {
		h.logger.Error("Authorization check failed", "error", err, "user_id", userID, "folder_id", folderID)
		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Failed to check permissions",
		})
	}
	if !ok {
		return JSONResponse(w, http.StatusForbidden, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "You do not have permission to access this folder",
		})
	}

	files, err := h.db.ListFiles(ctx, database.ListFilesParams{
		ParentID: util.Some(util.Some(folderID)),
	})
	if err != nil {
		h.logger.Error("Failed to get files for folder", "error", err)
		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Failed to load files for folder",
		})
	}

	viewFiles := make([]views.File, 0, len(files))
	for _, file := range files {
		viewFiles = append(viewFiles, views.File{
			ID:          file.ID.String(),
			Name:        file.Name,
			Size:        file.SizeBytes,
			MimeType:    file.MimeType,
			IsFolder:    file.MimeType == "application/askfrank.folder",
			IsViewable:  file.MimeType == "application/pdf" || file.MimeType == "application/image",
			DownloadURL: "/api/drive/v1/files/" + file.ID.String() + "/download",
		})
	}

	// Build breadcrumbs
	breadcrumbs := make([]views.Breadcrumb, 0)
	breadcrumbs = append(breadcrumbs, views.Breadcrumb{
		Name: "My Drive",
		URL:  "/drive",
	})
	breadcrumbs = append(breadcrumbs, views.Breadcrumb{
		Name: "Folder",
		URL:  "/drive/v1/folder/" + folderID.String(),
	})

	// todo parent folder must be
	// parentFiles, err := h.db.GetParentFolders(ctx, userID, params.InFolder)
	// if err != nil {
	// 	h.logger.Error("Failed to get parent folders for breadcrumb", "error", err, "file_id", params.InFolder.UUID)
	// 	// If we can't get parent folders, just show the file name
	// 	breadcrumbs = append(breadcrumbs, views.Breadcrumb{
	// 		Name: options.InFolder.UUID.String(),
	// 		URL:  "/drive/folder/" + options.InFolder.UUID.String(),
	// 	})
	// } else {
	// 	for _, parentFile := range parentFiles {
	// 		breadcrumbs = append(breadcrumbs, views.Breadcrumb{
	// 			Name: parentFile.Name,
	// 			URL:  "/drive/folder/" + parentFile.ID.String(),
	// 		})
	// 	}
	// }

	currentFolderID := ""
	return render(ctx, w, views.DrivePage(views.DrivePageProps{
		AppLayoutProps:  h.appLayoutProps(ctx, h.layoutProps(ctx, "My Drive"), r),
		Files:           viewFiles,
		Breadcrumbs:     breadcrumbs,
		CurrentFolderID: currentFolderID,
	}))
}

func (h *PageHandler) ShowCreateMeetingPage(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	return render(ctx, w, views.CreateMeetingPage(views.CreateMeetingPageProps{
		AppLayoutProps: h.appLayoutProps(ctx, h.layoutProps(ctx, "Create Meeting"), r),
	}))
}

func (h *PageHandler) ShowMeetingPage(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	meetingID := r.PathValue("id")
	if meetingID == "" {
		return Redirect(w, r, "/meeting", http.StatusSeeOther)
	}

	return render(ctx, w, views.MeetingPage(views.MeetingPageProps{
		AppLayoutProps: h.appLayoutProps(ctx, h.layoutProps(ctx, "Meeting"), r),
		MeetingID:      meetingID,
	}))
}

func (h *PageHandler) ShowCalendarPage(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	userID := ctx.Value(config.UserIDContextKey).(uuid.UUID)

	numDays := 35 // 5 weeks from now
	startDate := time.Now()
	endDate := startDate.AddDate(0, 0, numDays)

	events, err := h.db.ListCalendarEvents(ctx, database.ListCalendarEventsParams{
		OwnerID:   util.Some(userID),
		StartDate: util.Some(startDate),
		EndDate:   util.Some(endDate),
	})
	if err != nil {
		h.logger.Error("Failed to list calendar events", "error", err, "user_id", userID)
		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Failed to load calendar events",
		})
	}

	// Convert database events to view events
	viewEvents := make([]views.CalendarEvent, len(events))
	for i, event := range events {
		viewEvents[i] = views.CalendarEvent{
			ID:          event.ID.String(),
			Title:       event.Title,
			Description: event.Description,
			StartTime:   event.StartTime,
			EndTime:     event.EndTime,
			Location:    event.Location.Unwrap(),
			AllDay:      event.AllDay,
			Status:      string(event.Status),
		}
	}

	// Convert to view model for days (simplified now that JS handles most of the work)
	viewDays := make([]views.CalendarDay, numDays)
	for i := range viewDays {
		date := startDate.AddDate(0, 0, i)
		viewDays[i] = views.CalendarDay{
			Date:   date,
			Events: []views.CalendarEvent{}, // Events will be handled by JavaScript
		}
	}

	// Get current month for navigation
	currentMonth := time.Date(time.Now().Year(), time.Now().Month(), 1, 0, 0, 0, 0, time.UTC)

	return render(ctx, w, views.CalendarPage(views.CalendarPageProps{
		AppLayoutProps: h.appLayoutProps(ctx, h.layoutProps(ctx, "Calendar"), r),
		Days:           viewDays,
		CurrentMonth:   currentMonth,
		Events:         viewEvents,
	}))
}

func (h *PageHandler) ShowWebhooksPage(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	userID := ctx.Value(config.UserIDContextKey).(uuid.UUID)

	// Get the list of webhooks for this user

	subscription, err := h.db.ListWebhookSubscriptions(ctx, database.ListWebhookSubscriptionsParams{
		OwnerID: util.Some(userID),
	})
	if err != nil {
		h.logger.Error("Failed to list webhooks", "error", err)
		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Failed to load webhooks",
		})
	}

	// Convert to view model
	viewSubscriptions := make([]views.WebhookSubscription, 0, len(subscription))
	for _, webhook := range subscription {
		eventTypes := make([]string, len(webhook.EventTypes))
		for i, eventType := range webhook.EventTypes {
			eventTypes[i] = string(eventType)
		}

		viewSubscriptions = append(viewSubscriptions, views.WebhookSubscription{
			ID:           webhook.ID.String(),
			Name:         webhook.Name,
			Description:  webhook.Description,
			URL:          webhook.URL,
			EventTypes:   eventTypes,
			IsActive:     webhook.IsActive,
			Activity:     time.Time{},
			ResponseTime: time.Time{},
			ErrorRate:    0,
		})
	}
	return render(ctx, w, views.WebhooksPage(views.WebhooksPageProps{
		AppLayoutProps: h.appLayoutProps(ctx, h.layoutProps(ctx, "Webhooks"), r),
		Subscriptions:  viewSubscriptions,
		EventTypes:     h.webhookManager.EventTypes(),
	}))
}

type CreateWebhookRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	URL         string   `json:"url"`
	EventTypes  []string `json:"event_types"`
}

func (h *PageHandler) CreateWebhookSubscription(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	userID := ctx.Value(config.UserIDContextKey).(uuid.UUID)

	var req CreateWebhookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Invalid request payload",
		})
	}

	if req.Name == "" || req.URL == "" || len(req.EventTypes) == 0 {
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Name, URL, and at least one event type are required",
		})
	}

	// Validate event types
	eventTypes := make([]webhook.EventType, len(req.EventTypes))
	for idx, etStr := range req.EventTypes {
		vet, err := webhook.EventTypeFromString(etStr)
		if err != nil {
			return JSONResponse(w, http.StatusBadRequest, ApiResponse{
				Status:  APIResponseStatusError,
				Message: "Invalid event type: " + etStr,
			})
		}
		eventTypes[idx] = vet
	}

	subscriptionID, err := h.webhookManager.RegisterSubscription(ctx, webhook.RegisterSubscriptionParam{
		OwnerID:     userID,
		Name:        req.Name,
		Description: req.Description,
		URL:         req.URL,
		EventTypes:  eventTypes,
	})
	if err != nil {
		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Failed to create webhook subscription",
		})
	}

	return JSONResponse(w, http.StatusCreated, ApiResponse{
		Status: APIResponseStatusSuccess,
		Data: map[string]any{
			"id": subscriptionID.String(),
			// "name":        webhook.Name,
			// "description": webhook.Description,
			// "url":         webhook.URL,
			// "event_types": webhook.EventTypes,
			// "is_active":   webhook.IsActive,
			// "created_at":  webhook.CreatedAt,
		},
	})
}

func (h *PageHandler) DeleteWebhook(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	userID := ctx.Value(config.UserIDContextKey).(uuid.UUID)

	// Get webhook ID from URL path
	webhookID := r.PathValue("id")
	if webhookID == "" {
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Webhook ID is required",
		})
	}

	webhookUUID, err := uuid.Parse(webhookID)
	if err != nil {
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Invalid webhook ID format",
		})
	}

	// First check if the webhook exists and belongs to this user by listing user webhooks
	if err := h.db.DeleteWebhookByID(ctx, webhookUUID, database.DeleteWebhookParams{
		OwnerID: util.Some(userID),
	}); err != nil {
		h.logger.Error("Failed to delete webhook", "error", err, "webhookID", webhookID)
		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Failed to delete webhook",
		})
	}

	return JSONResponse(w, http.StatusOK, ApiResponse{
		Status:  APIResponseStatusSuccess,
		Message: "Webhook deleted successfully",
	})
}

func (h *PageHandler) ShowAuditLogsPage(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	userID := ctx.Value(config.UserIDContextKey).(uuid.UUID)

	// Parse query parameters for filtering (e.g., startTime, endTime)
	startTimeStr := r.URL.Query().Get("startTime")
	endTimeStr := r.URL.Query().Get("endTime")

	var startTime, endTime time.Time
	var err error

	if startTimeStr != "" {
		startTime, err = time.Parse("2006-01-02T15:04", startTimeStr)
		if err != nil {
			return JSONResponse(w, http.StatusBadRequest, ApiResponse{
				Status:  APIResponseStatusError,
				Message: "Invalid start time format",
			})
		}
	} else {
		startTime = time.Now().AddDate(0, -1, 0) // Default to 1 month ago
	}

	if endTimeStr != "" {
		endTime, err = time.Parse("2006-01-02T15:04", endTimeStr)
		if err != nil {
			return JSONResponse(w, http.StatusBadRequest, ApiResponse{
				Status:  APIResponseStatusError,
				Message: "Invalid end time format",
			})
		}
	} else {
		endTime = time.Now() // Default to now
	}

	// Ensure startTime is before endTime
	if startTime.After(endTime) {
		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Start time must be before end time",
		})
	}

	// Get the list of audit logs for this user
	logs, err := h.db.ListAuditLogEvents(ctx, database.ListAuditLogEventsParams{
		OwnerID:   util.Some(userID),
		StartTime: util.Some(startTime),
		EndTime:   util.Some(endTime),
	})
	if err != nil {
		h.logger.Error("Failed to list audit logs", "error", err)
		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Status:  APIResponseStatusError,
			Message: "Failed to load audit logs",
		})
	}

	// Convert to view model
	viewEvents := make([]views.AuditLogEvent, len(logs))
	for i := range logs {
		viewEvents[i] = views.AuditLogEvent{
			ID:        logs[i].ID.String(),
			Title:     logs[i].EventType,
			Info:      string(logs[i].EventData),
			CreatedAt: logs[i].CreatedAt,
		}
	}
	return render(ctx, w, views.AuditLogsPage(views.AuditLogsPageProps{
		AppLayoutProps: h.appLayoutProps(ctx, h.layoutProps(ctx, "Audit Logs"), r),
		Events:         viewEvents,
	}))
}

func render(ctx context.Context, w http.ResponseWriter, component templ.Component) error {
	w.Header().Set("Content-Type", "text/html")
	return component.Render(ctx, w)
}
