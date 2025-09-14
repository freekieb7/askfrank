package web

import (
	"encoding/gob"
	"hp/internal/database"
	"hp/internal/i18n"
	"hp/internal/openfga"
	"hp/internal/web/views"
	"log"
	"log/slog"

	"github.com/a-h/templ"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/google/uuid"
	"github.com/stripe/stripe-go/v82"
	stripeSession "github.com/stripe/stripe-go/v82/checkout/session"
	"golang.org/x/crypto/bcrypt"
)

func init() {
	gob.Register(uuid.UUID{}) // Register uuid.UUID for session storage
}

type PageHandler struct {
	logger        *slog.Logger
	translator    *i18n.Translator
	sessionStore  *session.Store
	db            *database.PostgresDatabase
	authorization *openfga.AuthorizationService
}

func NewPageHandler(logger *slog.Logger, translator *i18n.Translator, sessionStore *session.Store, db *database.PostgresDatabase, authorization *openfga.AuthorizationService) *PageHandler {
	return &PageHandler{logger: logger, translator: translator, sessionStore: sessionStore, db: db, authorization: authorization}
}

func (h *PageHandler) ShowHomePage(c *fiber.Ctx) error {
	return render(c, views.HomePage(c, h.translate))
}

func (h *PageHandler) ShowLoginPage(c *fiber.Ctx) error {
	sess, err := h.sessionStore.Get(c)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Failed to get session")
	}
	defer func() {
		if err := sess.Save(); err != nil {
			h.logger.Error("Failed to save session", "error", err)
		}
	}()

	if sess.Get("user_id") != nil {
		return c.Redirect("/", fiber.StatusSeeOther) // Redirect if already logged in
	}

	// Store the return_to query parameter in session for post-login redirection
	redirectToRaw := c.Query("return_to")
	if redirectToRaw != "" {
		sess.Set("redirect_to", redirectToRaw)
	}

	return render(c, views.LoginPage(c, h.translate))
}

func (h *PageHandler) Login(c *fiber.Ctx) error {
	sess, err := h.sessionStore.Get(c)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Failed to get session")
	}
	defer func() {
		if err := sess.Save(); err != nil {
			h.logger.Error("Failed to save session", "error", err)
		}
	}()

	// Get form data
	email := c.FormValue("email")
	password := c.FormValue("password")

	// Basic validation
	if email == "" || password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Email and password are required",
		})
	}

	var params database.RetrieveUserParams
	params.Email = email

	user, err := h.db.RetrieveUser(c.Context(), params)
	if err != nil {
		if err == database.ErrUserNotFound {
			h.logger.Warn("Login attempt with non-existing user", "email", email)
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid email or password",
			})
		}

		h.logger.Error("Failed to get user by email", "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Something went wrong, please try again later",
		})
	}

	if err := bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(password)); err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid email or password",
		})
	}

	// Regenerate session ID to prevent fixation
	if err := sess.Regenerate(); err != nil {
		h.logger.Error("Failed to regenerate session ID", "error", err)
		// Continue, but log
	}
	// Set user ID in session
	sess.Set("user_id", user.ID)

	// Redirect to the originally requested page or home
	redirectTo := "/"
	if redirectRaw := sess.Get("redirect_to"); redirectRaw != nil {
		if redirectStr, ok := redirectRaw.(string); ok && redirectStr != "" {
			redirectTo = redirectStr
		}
		// Clear the redirect_to after using it
		sess.Delete("redirect_to")
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":   "success",
		"message":  "Login successful! Redirecting...",
		"redirect": redirectTo,
	})
}

func (h *PageHandler) Logout(c *fiber.Ctx) error {
	sess, err := h.sessionStore.Get(c)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Failed to get session")
	}
	defer func() {
		if err := sess.Save(); err != nil {
			h.logger.Error("Failed to save session", "error", err)
		}
	}()

	if err := sess.Destroy(); err != nil {
		h.logger.Error("Failed to destroy session", "error", err)
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":   "success",
		"message":  "Logout successful! Continue to login.",
		"redirect": "/login",
	})
}

func (h *PageHandler) ShowRegisterPage(c *fiber.Ctx) error {
	return render(c, views.RegisterPage(c, h.translate))
}

func (h *PageHandler) Register(c *fiber.Ctx) error {
	sess, err := h.sessionStore.Get(c)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Failed to get session")
	}
	defer func() {
		if err := sess.Save(); err != nil {
			h.logger.Error("Failed to save session", "error", err)
		}
	}()

	// Get form data
	name := c.FormValue("name")
	email := c.FormValue("email")
	password := c.FormValue("password")
	termsAccepted := c.FormValue("terms")

	// Basic validation
	if name == "" || email == "" || password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "All fields are required",
		})
	}

	if len(password) < 8 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Password must be at least 8 characters long",
		})
	}

	if termsAccepted != "on" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "You must accept the terms and conditions",
		})
	}

	// Check if user already exists
	var retrieveUserParams database.RetrieveUserParams
	retrieveUserParams.Email = email

	_, err = h.db.RetrieveUser(c.Context(), retrieveUserParams)
	if err == nil {
		// User already exists
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error": "An account with this email already exists",
		})
	}
	if err != database.ErrUserNotFound {
		h.logger.Error("Failed to check if user exists", "error", err, "email", email)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Something went wrong, please try again later",
		})
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		h.logger.Error("Failed to hash password", "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to hash password, please try again later",
		})
	}

	var createUserParams database.CreateUserParams
	createUserParams.Name = name
	createUserParams.Email = email
	createUserParams.PasswordHash = passwordHash

	user, err := h.db.CreateUser(c.Context(), createUserParams)
	if err != nil {
		h.logger.Error("Failed to create user", "error", err, "params", createUserParams)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create user, please try again later",
		})
	}

	// Set user ID in session
	sess.Set("user_id", user.ID)

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":   "success",
		"message":  "Registration successful! Continue to the app.",
		"redirect": "/",
	})
}

func (h *PageHandler) ShowBillingPage(c *fiber.Ctx) error {
	return render(c, views.BillingPage(c, h.translate))
}

func (h *PageHandler) UpdateBilling(c *fiber.Ctx) error {
	stripe.Key = "sk_test_51Rm9NXRpsw6KPSOTjxYsYKz1oMczIt9tbWJqYpS58mwkDyCcU6T5pDuMCOu5J1tisAzoxrUuXwjacjwaWxV1liad00S5SBnCid"

	domain := "https://webhook.site/9c023c39-c641-4d41-97c9-850555964554" // Replace with your actual domain

	priceTable := map[string]string{
		"free":       "",
		"pro":        "price_1Rrg4RRpsw6KPSOT3xe54iWO",
		"enterprise": "price_1Rrg54Rpsw6KPSOTW3K8Ur3L",
	}

	priceID := c.FormValue("price")
	price, exists := priceTable[priceID]
	if !exists {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid price selected",
		})
	}

	checkoutParams := &stripe.CheckoutSessionParams{
		Mode: stripe.String(string(stripe.CheckoutSessionModeSubscription)),
		LineItems: []*stripe.CheckoutSessionLineItemParams{
			{
				Price:    stripe.String(price),
				Quantity: stripe.Int64(1),
			},
		},
		SuccessURL: stripe.String(domain + "/success.html?session_id={CHECKOUT_SESSION_ID}"),
		CancelURL:  stripe.String(domain + "/cancel.html"),
	}

	s, err := stripeSession.New(checkoutParams)
	if err != nil {
		log.Printf("session.New: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status": "error",
			"error":  "Failed to create checkout session",
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":   "succeeded",
		"redirect": s.URL,
	})
}

func (h *PageHandler) ShowMyDrivePage(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)

	var params database.RetrieveFileListParams
	params.OwnerID = userID
	params.InFolder = uuid.Nil // Root folder

	files, err := h.db.RetrieveFileList(c.Context(), params)
	if err != nil {
		h.logger.Error("Failed to get files for folder", "error", err, "params", params)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to load files for folder",
		})
	}

	viewFiles := make([]views.File, 0, len(files))
	for _, file := range files {
		viewFiles = append(viewFiles, views.File{
			ID:          file.ID.String(),
			Name:        file.Name,
			Size:        file.SizeBytes,
			MimeType:    file.MimeType,
			IsFolder:    file.IsFolder(),
			IsViewable:  file.IsPDF() || file.IsImage(),
			DownloadURL: "/api/drive/v1/files/" + file.ID.String() + "/download",
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
	// 	parentFiles, err := h.db.GetParentFolders(c.Context(), userID, params.InFolder)
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
	return render(c, views.DrivePage(c, h.translate, viewFiles, breadcrumbs, currentFolderID))
}

func (h *PageHandler) ShowSharedFilePage(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)

	sharedFiles, err := h.db.RetrieveSharedFiles(c.Context(), database.RetrieveSharedFilesParams{
		UserID: userID,
	})
	if err != nil {
		h.logger.Error("Failed to get files for folder", "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to load files for folder",
		})
	}

	viewFiles := make([]views.File, 0, len(sharedFiles))
	for _, file := range sharedFiles {
		viewFiles = append(viewFiles, views.File{
			ID:       file.ID.String(),
			Name:     file.Name,
			Size:     file.SizeBytes,
			MimeType: file.MimeType,
			IsFolder: file.IsFolder(),
		})
	}

	// Build breadcrumbs
	breadcrumbs := make([]views.Breadcrumb, 0)
	breadcrumbs = append(breadcrumbs, views.Breadcrumb{
		Name: "Shared with me",
		URL:  "/drive/shared",
	})

	currentFileID := ""
	return render(c, views.DrivePage(c, h.translate, viewFiles, breadcrumbs, currentFileID))
}

func (h *PageHandler) ShowFolderPage(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)

	folderIDStr := c.Params("folder_id")
	folderID := uuid.MustParse(folderIDStr)

	ok, err := h.authorization.CanReadFile(c.Context(), userID, folderID)
	if err != nil {
		h.logger.Error("Authorization check failed", "error", err, "user_id", userID, "folder_id", folderID)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to check permissions",
		})
	}
	if !ok {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "You do not have permission to access this folder",
		})
	}

	var params database.RetrieveFileListParams
	params.InFolder = folderID

	files, err := h.db.RetrieveFileList(c.Context(), params)
	if err != nil {
		h.logger.Error("Failed to get files for folder", "error", err, "params", params)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to load files for folder",
		})
	}

	viewFiles := make([]views.File, 0, len(files))
	for _, file := range files {
		viewFiles = append(viewFiles, views.File{
			ID:          file.ID.String(),
			Name:        file.Name,
			Size:        file.SizeBytes,
			MimeType:    file.MimeType,
			IsFolder:    file.IsFolder(),
			IsViewable:  file.IsPDF() || file.IsImage(),
			DownloadURL: "/api/drive/v1/files/" + file.ID.String() + "/download",
		})
	}

	// Build breadcrumbs
	breadcrumbs := make([]views.Breadcrumb, 0)
	breadcrumbs = append(breadcrumbs, views.Breadcrumb{
		Name: "My Drive",
		URL:  "/drive",
	})

	// todo parent folder must be
	// parentFiles, err := h.db.GetParentFolders(c.Context(), userID, params.InFolder)
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
	return render(c, views.DrivePage(c, h.translate, viewFiles, breadcrumbs, currentFolderID))
}

func render(c *fiber.Ctx, component templ.Component) error {
	c.Set("Content-Type", "text/html")
	return component.Render(c.Context(), c.Response().BodyWriter())
}

func (h *PageHandler) translate(c *fiber.Ctx, key string) string {
	lang := c.Locals("lang").(i18n.Language)
	return h.translator.T(lang, key)
}
