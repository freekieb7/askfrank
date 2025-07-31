package api

import (
	"askfrank/internal/model"
	"askfrank/internal/monitoring"
	"askfrank/internal/repository"
	"askfrank/internal/service"
	"askfrank/internal/storage"
	"askfrank/resources/view"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/a-h/templ"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrSessionUserIDNotFound = errors.New("user ID not found in session")
)

type AppHandler struct {
	store               *session.Store
	repo                repository.Repository
	storage             storage.Storage
	telemetry           monitoring.Telemetry
	auditService        *service.AuditService
	subscriptionService *service.SubscriptionService
	usageService        *service.UsageService
}

func NewAppHandler(store *session.Store, repository repository.Repository, storageBackend storage.Storage, subscriptionSvc *service.SubscriptionService, tel monitoring.Telemetry) AppHandler {
	auditService := service.NewAuditService(repository)
	usageService := service.NewUsageService(repository, tel.Logger())
	return AppHandler{
		store:               store,
		repo:                repository,
		storage:             storageBackend,
		telemetry:           tel,
		auditService:        auditService,
		subscriptionService: subscriptionSvc,
		usageService:        usageService,
	}
}

func (h *AppHandler) ShowHomePage(c *fiber.Ctx) error {
	return render(c, view.HomePage(c))
}

func (h *AppHandler) ShowLoginPage(c *fiber.Ctx) error {
	// Store RECAPTCHA site key in locals for template
	c.Locals("recaptcha_site_key", os.Getenv("RECAPTCHA_SITE_KEY"))
	return render(c, view.LoginPage(c))
}

func (h *AppHandler) Login(c *fiber.Ctx) error {
	email := c.FormValue("email")
	password := c.FormValue("password")

	// Validate input
	if email == "" || password == "" {
		return c.Status(400).JSON(fiber.Map{
			"error": "Email and password are required",
		})
	}

	// Sanitize email input
	email = strings.TrimSpace(strings.ToLower(email))

	// Get user by email
	user, err := h.repo.GetUserByEmail(email)
	if err != nil {
		if err == repository.ErrUserNotFound {
			// Return generic error to prevent email enumeration
			return c.Status(401).JSON(fiber.Map{
				"error": "Invalid email or password",
			})
		}
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to get user by email", "error", err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Internal server error",
		})
	}

	// Check password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return c.Status(401).JSON(fiber.Map{
			"error": "Invalid email or password",
		})
	}

	// Check if user's email is verified
	if !user.IsEmailVerified {
		return c.Status(403).JSON(fiber.Map{
			"error": "Please verify your email address before logging in",
		})
	}

	// Store user ID in session
	sess, err := h.store.Get(c)
	if err != nil {
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to get session", "error", err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to create session",
		})
	}
	sess.Set("user_id", user.ID.String())
	if err := sess.Save(); err != nil {
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to save session", "error", err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to save session",
		})
	}

	// Log successful login
	h.telemetry.Logger().InfoContext(c.Context(), "User logged in successfully", "email", email, "user_id", user.ID, "ip", c.IP())

	// Log audit event for login
	auditCtx := service.ExtractAuditContext(&user.ID, c.IP(), c.Get("User-Agent"), sess.ID())
	h.auditService.LogAuthenticationEvent(c.Context(), user.ID, model.AuditActionLogin, auditCtx)

	return c.Redirect("/account")
}

func (h *AppHandler) Logout(c *fiber.Ctx) error {
	sess, err := h.store.Get(c)
	if err != nil {
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to get session", "error", err)
		return c.Status(500).SendString("Failed to get sessions")
	}

	// Get user ID for logging before deleting
	userID, err := h.sessionUserId(sess)
	if err != nil {
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to get user ID from session", "error", err)
		return c.Status(500).SendString("Failed to get user ID")
	}

	// Log audit event for logout
	auditCtx := service.ExtractAuditContext(&userID, c.IP(), c.Get("User-Agent"), sess.ID())
	h.auditService.LogAuthenticationEvent(c.Context(), userID, model.AuditActionLogout, auditCtx)

	// Clear session
	sess.Delete("user_id")
	if err := sess.Save(); err != nil {
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to save session", "error", err)
		return c.Status(500).SendString("Failed to save session")
	}

	// Log successful logout
	h.telemetry.Logger().InfoContext(c.Context(), "User logged out successfully", "user_id", userID, "ip", c.IP())

	return c.Redirect("/auth/login?logout=true")
}

func (h *AppHandler) ShowCreateUserPage(c *fiber.Ctx) error {
	// Store RECAPTCHA site key in locals for template
	c.Locals("recaptcha_site_key", os.Getenv("RECAPTCHA_SITE_KEY"))
	return render(c, view.CreateUserPage(c))
}

func (h *AppHandler) ShowCheckInboxPage(c *fiber.Ctx) error {
	sess, err := h.store.Get(c) // Ensure session is initialized
	if err != nil {
		return err
	}

	// Get user ID from session
	userID, err := h.sessionUserId(sess)
	if err != nil {
		if errors.Is(err, ErrSessionUserIDNotFound) {
			return c.Redirect("/auth/login")
		}

		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to get user ID from session", "error", err)
		return c.Status(500).SendString("Failed to get user ID")
	}

	user, err := h.repo.GetUserByID(userID)
	if err != nil {
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to get user by ID", "error", err)
		return c.Status(500).SendString("Failed to retrieve user information")
	}

	return render(c, view.CheckInboxPage(c, user.Email))
}

func (h *AppHandler) ShowPricingPage(c *fiber.Ctx) error {
	return render(c, view.PricingPage(c))
}

func (h *AppHandler) ShowAccountPage(c *fiber.Ctx) error {
	sess, err := h.store.Get(c)
	if err != nil {
		return err
	}

	userID, err := h.sessionUserId(sess)
	if err != nil {
		if errors.Is(err, ErrSessionUserIDNotFound) {
			return c.Redirect("/auth/login")
		}

		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to get user ID from session", "error", err)
		return c.Status(500).SendString("Failed to get user ID")
	}

	user, err := h.repo.GetUserByID(userID)
	if err != nil {
		if err == repository.ErrUserNotFound {
			sess.Delete("user_id") // Clear session if user not found
			if err := sess.Save(); err != nil {
				h.telemetry.Logger().ErrorContext(c.Context(), "Failed to save session after user not found", "error", err)
				return c.Status(500).SendString("Failed to save session")
			}
			return c.Redirect("/auth/login?error=user_not_found")
		}

		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to get user by ID", "error", err)
		return c.Status(500).SendString("Failed to retrieve user information")
	}

	return render(c, view.AccountPage(c, user))
}

func (h *AppHandler) ShowDashboardPage(c *fiber.Ctx) error {
	sess, err := h.store.Get(c)
	if err != nil {
		return err
	}

	userID, err := h.sessionUserId(sess)
	if err != nil {
		if errors.Is(err, ErrSessionUserIDNotFound) {
			return c.Redirect("/auth/login")
		}

		return c.Status(500).SendString("Failed to get user ID from session")
	}

	user, err := h.repo.GetUserByID(userID)
	if err != nil {
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to get user by ID", "error", err)
		return c.Status(500).SendString("Failed to retrieve user information")
	}

	return render(c, view.DashboardPage(c, user))
}

func (h *AppHandler) ShowWorkspacePage(c *fiber.Ctx) error {
	sess, err := h.store.Get(c)
	if err != nil {
		return err
	}

	userID, err := h.sessionUserId(sess)
	if err != nil {
		if errors.Is(err, ErrSessionUserIDNotFound) {
			return c.Redirect("/auth/login")
		}

		return c.Status(500).SendString("Failed to get user ID from session")
	}

	user, err := h.repo.GetUserByID(userID)
	if err != nil {
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to get user by ID", "error", err)
		return c.Status(500).SendString("Failed to retrieve user information")
	}

	// Get user's folders
	folders, err := h.repo.GetFoldersByOwnerID(userID)
	if err != nil {
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to get folders", "error", err)
		return c.Status(500).SendString("Failed to retrieve folders")
	}

	// Get user's documents
	documents, err := h.repo.GetDocumentsByOwnerID(userID)
	if err != nil {
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to get documents", "error", err)
		return c.Status(500).SendString("Failed to retrieve documents")
	}

	return render(c, view.WorkspacePage(c, user, folders, documents))
}

func (h *AppHandler) CheckInbox(c *fiber.Ctx) error {
	sess, err := h.store.Get(c)
	if err != nil {
		return err
	}

	userID, err := h.sessionUserId(sess)
	if err != nil {
		if errors.Is(err, ErrSessionUserIDNotFound) {
			return c.Redirect("/auth/login")
		}

		return c.Status(500).SendString("Failed to get user ID from session")
	}

	user, err := h.repo.GetUserByID(userID)
	if err != nil {
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to get user by ID", "error", err)
		return c.Status(500).SendString("Failed to retrieve user information")
	}

	activationCode := c.FormValue("activation_code") // Get activation code from form
	if activationCode == "" {
		return c.Status(400).SendString("Activation code is required")
	}

	userRegistration, err := h.repo.GetUserRegistrationByUserID(userID)
	if err != nil {
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to get user registration by ID", "userid", userID, "error", err)
		return c.Status(500).SendString("Failed to retrieve user registration information")
	}

	// Validate activation code
	if userRegistration.ActivationCode != activationCode {
		return c.Status(400).SendString("Invalid activation code")
	}

	// Delete user registration after successful activation
	if err := h.repo.DeleteUserRegistration(userRegistration.ID); err != nil {
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to delete user registration", "error", err)
		return c.Status(500).SendString("Failed to delete user registration")
	}

	user.IsEmailVerified = true // Mark email as verified

	if err := h.repo.UpdateUser(user); err != nil {
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to update user", "error", err)
		return c.Status(500).SendString("Failed to update user information")
	}

	return c.Redirect("/account")
}

func (h *AppHandler) CreateUser(c *fiber.Ctx) error {
	// Get sanitized form data from security middleware
	email, ok := c.Locals("sanitized_email").(string)
	if !ok {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid email data",
		})
	}

	password, ok := c.Locals("sanitized_password").(string)
	if !ok {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid password data",
		})
	}

	terms := c.FormValue("terms")
	newsletter := c.FormValue("newsletter")

	// Validate required fields
	if email == "" || password == "" {
		return c.Status(400).JSON(fiber.Map{
			"error": "All required fields must be filled",
		})
	}

	if terms != "on" {
		return c.Status(400).JSON(fiber.Map{
			"error": "You must agree to the terms of service",
		})
	}

	// Additional password strength validation
	if len(password) < 8 {
		return c.Status(400).JSON(fiber.Map{
			"error": "Password must be at least 8 characters long",
		})
	}

	// Check if user already exists
	_, err := h.repo.GetUserByEmail(email)
	if err == nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "User with this email already exists",
		})
	} else if err != repository.ErrUserNotFound {
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to check existing user", "error", err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Internal server error",
		})
	}

	// Hash the password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to hash password", "error", err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to process password",
		})
	}

	// Create user model
	user := model.User{
		ID:              uuid.New(),
		Name:            strings.Split(email, "@")[0],
		Email:           email,
		PasswordHash:    string(passwordHash),
		Role:            model.RoleUser,
		IsEmailVerified: false,
		CreatedAt:       time.Now(),
	}

	if err := h.repo.CreateUser(user); err != nil {
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to create user", "error", err)

		// Record failed registration metric
		h.telemetry.RecordUserRegistration(c.Context(), email, false)

		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to create user account",
		})
	}

	// Record successful registration metric
	h.telemetry.RecordUserRegistration(c.Context(), email, true)

	// Generate activation code
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	activationCode := make([]byte, 6)
	for i := range activationCode {
		activationCode[i] = charset[rand.Intn(len(charset))]
	}
	codeStr := string(activationCode)

	// Create user registration model
	userRegistration := model.UserRegistration{
		ID:             uuid.New(),
		UserID:         user.ID,
		ActivationCode: codeStr,
		CreatedAt:      time.Now(),
	}

	if err := h.repo.CreateUserRegistration(userRegistration); err != nil {
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to create user registration", "error", err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Internal server error",
		})
	}

	// Log the signup attempt
	h.telemetry.Logger().InfoContext(c.Context(), "New user signup", "email", email, "newsletter", newsletter != "", "ip", c.IP())
	h.telemetry.Logger().DebugContext(c.Context(), "Activation code generated", "code", codeStr)

	// // Send confirmation email (in production, use a proper email service)
	// go func() {
	// 	if err := sendConfirmationEmail(email, codeStr); err != nil {
	// 		log.Printf("Failed to send confirmation email: %v", err)
	// 	}
	// }()

	// add user to session store
	sess, err := h.store.Get(c)
	if err != nil {
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to get session", "error", err)
		return c.Status(500).SendString("Failed to get session")
	}
	sess.Set("user_id", user.ID.String())
	if err := sess.Save(); err != nil {
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to save session", "error", err)
		return c.Status(500).SendString("Failed to save session")
	}

	// Redirect to check inbox page
	return c.Redirect("/auth/sign-up/check-inbox")
}

func (h *AppHandler) ConfirmUser(c *fiber.Ctx) error {
	// Get form data
	email := c.FormValue("email")
	activationCode := c.FormValue("activation_code")

	// Basic validation
	if email == "" || activationCode == "" {
		return c.Status(400).SendString("Email and activation code are required")
	}

	// Validate activation code (check against database)
	userRegistration, err := h.repo.GetUserRegistrationByEmail(email)
	if err != nil {
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to get user registration", "error", err)
		return c.Status(400).SendString("Invalid email or activation code")
	}

	if userRegistration.ActivationCode != activationCode {
		return c.Status(400).SendString("Invalid activation code")
	}

	if err := h.repo.DeleteUserRegistration(userRegistration.ID); err != nil {
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to delete user registration", "error", err)
		return c.Status(500).SendString("Failed to complete activation")
	}

	h.telemetry.Logger().InfoContext(c.Context(), "User activated successfully", "email", email)

	// Redirect to success page or login
	return c.Redirect("/?activated=true")
}

// ShowAdminPage displays the admin dashboard with user overview
func (h *AppHandler) ShowAdminPage(c *fiber.Ctx) error {
	h.telemetry.Logger().InfoContext(c.Context(), "Admin dashboard accessed")
	// Check if user is authenticated
	sess, err := h.store.Get(c)
	if err != nil {
		return err
	}

	userID, err := h.sessionUserId(sess)
	if err != nil {
		if errors.Is(err, ErrSessionUserIDNotFound) {
			return c.Redirect("/auth/login")
		}
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to get user ID from session", "error", err)
		return c.Status(500).SendString("Failed to get user ID from session")
	}

	// Get current user to check admin privileges
	currentUser, err := h.repo.GetUserByID(userID)
	if err != nil {
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to get current user", "error", err)
		return c.Status(500).SendString("Failed to retrieve user information")
	}

	// Check if user is admin
	if currentUser.Role != model.RoleAdmin {
		h.telemetry.Logger().WarnContext(c.Context(), "Unauthorized admin access attempt", "user_id", userID, "email", currentUser.Email, "ip", c.IP())
		return c.Status(403).SendString("Access denied: Admin privileges required")
	}

	// Get pagination parameters
	// Parse pagination parameters
	page := c.QueryInt("page", 1)
	if page < 1 {
		page = 1
	}
	limit := 20 // Users per page
	offset := (page - 1) * limit

	// Get user statistics
	stats, err := h.repo.GetUserStats()
	if err != nil {
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to get user statistics", "error", err)
		return c.Status(500).SendString("Failed to retrieve user statistics")
	}

	// Get all users with pagination
	users, totalUsers, err := h.repo.GetAllUsers(limit, offset)
	if err != nil {
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to get users", "error", err)
		return c.Status(500).SendString("Failed to retrieve users")
	}

	// Calculate total pages
	totalPages := (totalUsers + limit - 1) / limit

	// Prepare admin page data
	adminData := view.AdminPageData{
		Stats: view.AdminStats{
			TotalUsers:           stats.TotalUsers,
			ActiveUsers:          stats.ActiveUsers,
			PendingRegistrations: stats.PendingRegistrations,
			TodayRegistrations:   stats.TodayRegistrations,
		},
		Users:       users,
		CurrentPage: page,
		TotalPages:  totalPages,
		TotalUsers:  totalUsers,
	}

	// Log admin access
	h.telemetry.Logger().InfoContext(c.Context(), "Admin dashboard accessed",
		"admin_user_id", userID,
		"admin_email", currentUser.Email,
		"total_users", stats.TotalUsers,
		"page", page,
		"ip", c.IP(),
	)

	return render(c, view.AdminPage(c, adminData))
}

// AdminActivateUser activates a user account (admin only)
func (h *AppHandler) AdminActivateUser(c *fiber.Ctx) error {
	// Check authentication
	sess, err := h.store.Get(c)
	if err != nil {
		return c.Status(500).SendString("Session error")
	}

	userID, err := h.sessionUserId(sess)
	if err != nil {
		if errors.Is(err, ErrSessionUserIDNotFound) {
			return c.Status(401).SendString("Unauthorized")
		}

		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to get user ID from session", "error", err)
		return c.Status(500).SendString("Failed to get user ID from session")
	}

	// Get current user to check admin privileges
	currentUser, err := h.repo.GetUserByID(userID)
	if err != nil {
		return c.Status(500).SendString("Failed to get current user")
	}

	// Check if user is admin
	if currentUser.Role != model.RoleAdmin {
		h.telemetry.Logger().WarnContext(c.Context(), "Non-admin user attempted to access admin function",
			"user_id", userID,
			"email", currentUser.Email,
			"action", "activate_user",
			"ip", c.IP(),
		)
		return c.Status(403).SendString("Access denied")
	}

	// Get target user ID from URL params
	targetUserID := c.Params("id")
	if targetUserID == "" {
		return c.Status(400).SendString("User ID required")
	}

	targetUUID, err := uuid.Parse(targetUserID)
	if err != nil {
		return c.Status(400).SendString("Invalid user ID format")
	}

	// Get target user to verify it exists and get info for logging
	targetUser, err := h.repo.GetUserByIDForAdmin(targetUUID)
	if err != nil {
		if err == repository.ErrUserNotFound {
			return c.Status(404).SendString("User not found")
		}
		return c.Status(500).SendString("Failed to get target user")
	}

	// Activate the user
	err = h.repo.ActivateUser(targetUUID)
	if err != nil {
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to activate user",
			"error", err,
			"admin_user_id", userID,
			"target_user_id", targetUserID,
		)
		return c.Status(500).SendString("Failed to activate user")
	}

	// Log admin action
	h.telemetry.Logger().InfoContext(c.Context(), "User activated by admin",
		"admin_user_id", userID,
		"admin_email", currentUser.Email,
		"target_user_id", targetUserID,
		"target_email", targetUser.Email,
		"ip", c.IP(),
	)

	// Return success response for HTMX
	return c.Status(200).SendString(`
		<span class="inline-flex px-2 py-1 text-xs font-semibold rounded-full bg-green-100 text-green-800">
			Verified
		</span>
	`)
}

// AdminDeleteUser deletes a user account (admin only)
func (h *AppHandler) AdminDeleteUser(c *fiber.Ctx) error {
	// Check authentication
	sess, err := h.store.Get(c)
	if err != nil {
		return c.Status(500).SendString("Session error")
	}

	userID, err := h.sessionUserId(sess)
	if err != nil {
		if errors.Is(err, ErrSessionUserIDNotFound) {
			return c.Status(401).SendString("Unauthorized")
		}
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to get user ID from session", "error", err)
		return c.Status(500).SendString("Failed to get user ID from session")
	}

	// Get current user to check admin privileges
	currentUser, err := h.repo.GetUserByID(userID)
	if err != nil {
		return c.Status(500).SendString("Failed to get current user")
	}

	// Check if user is admin
	if currentUser.Role != model.RoleAdmin {
		h.telemetry.Logger().WarnContext(c.Context(), "Non-admin user attempted to access admin function",
			"user_id", userID,
			"email", currentUser.Email,
			"action", "delete_user",
			"ip", c.IP(),
		)
		return c.Status(403).SendString("Access denied")
	}

	// Get target user ID from URL params
	targetUserID := c.Params("id")
	if targetUserID == "" {
		return c.Status(400).SendString("User ID required")
	}

	targetUUID, err := uuid.Parse(targetUserID)
	if err != nil {
		return c.Status(400).SendString("Invalid user ID format")
	}

	// Prevent admin from deleting themselves
	if targetUUID == userID {
		return c.Status(400).SendString("Cannot delete your own account")
	}

	// Get target user to verify it exists and get info for logging
	targetUser, err := h.repo.GetUserByIDForAdmin(targetUUID)
	if err != nil {
		if err == repository.ErrUserNotFound {
			return c.Status(404).SendString("User not found")
		}
		return c.Status(500).SendString("Failed to get target user")
	}

	// Delete the user
	err = h.repo.DeleteUser(targetUUID)
	if err != nil {
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to delete user",
			"error", err,
			"admin_user_id", userID,
			"target_user_id", targetUserID,
		)
		return c.Status(500).SendString("Failed to delete user")
	}

	// Log admin action
	h.telemetry.Logger().InfoContext(c.Context(), "User deleted by admin",
		"admin_user_id", userID,
		"admin_email", currentUser.Email,
		"target_user_id", targetUserID,
		"target_email", targetUser.Email,
		"ip", c.IP(),
	)

	// Return success response for HTMX (remove the table row)
	return c.Status(200).SendString("")
}

// ShowAdminUserView displays detailed view of a specific user for admins
func (h *AppHandler) ShowAdminUserView(c *fiber.Ctx) error {
	// Check if user is logged in and has admin privileges
	sess, err := h.store.Get(c)
	if err != nil {
		return c.Redirect("/auth/login")
	}

	userID, err := h.sessionUserId(sess)
	if err != nil {
		if errors.Is(err, ErrSessionUserIDNotFound) {
			return c.Redirect("/auth/login")
		}
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to get user ID from session", "error", err)
		return c.Status(500).SendString("Failed to get user ID from session")
	}

	// Get current user to verify admin role
	currentUser, err := h.repo.GetUserByID(userID)
	if err != nil {
		return c.Redirect("/auth/login")
	}

	if currentUser.Role != "admin" {
		return c.Status(403).SendString("Access denied")
	}

	// Get user ID from URL parameter
	targetUserIdStr := c.Params("id")
	targetUserId, err := uuid.Parse(targetUserIdStr)
	if err != nil {
		return c.Status(400).SendString("Invalid user ID")
	}

	// Get target user details
	targetUser, err := h.repo.GetUserByIDForAdmin(targetUserId)
	if err != nil {
		if err == repository.ErrUserNotFound {
			return c.Status(404).SendString("User not found")
		}
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to get user for admin view",
			"error", err,
			"admin_user_id", userID,
			"target_user_id", targetUserId,
		)
		return c.Status(500).SendString("Failed to retrieve user")
	}

	// Get user registration if it exists (for pending users)
	var registration *model.UserRegistration
	if !targetUser.IsEmailVerified {
		userRegistration, err := h.repo.GetUserRegistrationByEmail(targetUser.Email)
		if err == nil {
			registration = &userRegistration
		}
	}

	// Determine available actions
	canActivate := !targetUser.IsEmailVerified && registration != nil
	canDelete := targetUser.Role != "admin" || targetUser.ID != currentUser.ID // Can't delete yourself or other admins

	data := view.AdminUserViewData{
		User:         targetUser,
		Registration: registration,
		CanActivate:  canActivate,
		CanDelete:    canDelete,
	}

	return render(c, view.AdminUserView(c, data))
}

// ShowAuditPage displays the audit log for admin users
func (h *AppHandler) ShowAuditPage(c *fiber.Ctx) error {
	// Check if user is authenticated
	sess, err := h.store.Get(c)
	if err != nil {
		return err
	}

	userID, err := h.sessionUserId(sess)
	if err != nil {
		if errors.Is(err, ErrSessionUserIDNotFound) {
			return c.Redirect("/auth/login")
		}
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to get user ID from session", "error", err)
		return c.Status(500).SendString("Failed to get user ID from session")
	}

	// Get current user to check admin privileges
	currentUser, err := h.repo.GetUserByID(userID)
	if err != nil {
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to get current user", "error", err)
		return c.Status(500).SendString("Failed to retrieve user information")
	}

	// Check if user is admin
	if currentUser.Role != model.RoleAdmin {
		h.telemetry.Logger().WarnContext(c.Context(), "Unauthorized audit access attempt", "user_id", userID, "email", currentUser.Email, "ip", c.IP())
		return c.Status(403).SendString("Access denied: Admin privileges required")
	}

	// Parse filter parameters
	filters := model.AuditFilters{
		EntityType: c.Query("entity_type"),
		Action:     model.AuditAction(c.Query("action")),
		Limit:      20, // Default page size
	}

	// Parse pagination
	page := c.QueryInt("page", 1)
	if page < 1 {
		page = 1
	}
	filters.Offset = (page - 1) * filters.Limit

	// Parse date filters
	if startDate := c.Query("start_date"); startDate != "" {
		if parsed, err := time.Parse("2006-01-02", startDate); err == nil {
			filters.StartDate = &parsed
		}
	}

	if endDate := c.Query("end_date"); endDate != "" {
		if parsed, err := time.Parse("2006-01-02", endDate); err == nil {
			// Set to end of day
			endOfDay := parsed.Add(23*time.Hour + 59*time.Minute + 59*time.Second)
			filters.EndDate = &endOfDay
		}
	}

	// Get audit logs
	auditLogs, err := h.repo.GetAuditLogs(c.Context(), filters)
	if err != nil {
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to get audit logs", "error", err)
		return c.Status(500).SendString("Failed to retrieve audit logs")
	}

	// Get total count for pagination
	totalLogs, err := h.repo.GetAuditLogsCount(c.Context(), model.AuditFilters{
		EntityType: filters.EntityType,
		Action:     filters.Action,
		StartDate:  filters.StartDate,
		EndDate:    filters.EndDate,
	})
	if err != nil {
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to get audit logs count", "error", err)
		return c.Status(500).SendString("Failed to retrieve audit logs count")
	}

	// Calculate total pages
	totalPages := (totalLogs + filters.Limit - 1) / filters.Limit

	// Prepare audit page data
	auditData := view.AuditPageData{
		AuditLogs:   auditLogs,
		CurrentPage: page,
		TotalPages:  totalPages,
		TotalLogs:   totalLogs,
		Filters:     filters,
	}

	// Log audit page access
	h.telemetry.Logger().InfoContext(c.Context(), "Audit page accessed",
		"admin_user_id", userID,
		"admin_email", currentUser.Email,
		"page", page,
		"total_logs", totalLogs,
		"ip", c.IP(),
	)

	return render(c, view.AuditPage(c, currentUser, auditData))
}

// CreateFolder creates a new folder for the authenticated user
func (h *AppHandler) CreateFolder(c *fiber.Ctx) error {
	sess, err := h.store.Get(c)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Session error"})
	}

	userID, err := h.sessionUserId(sess)
	if err != nil {
		if errors.Is(err, ErrSessionUserIDNotFound) {
			return c.Status(401).JSON(fiber.Map{"error": "Unauthorized"})
		}
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to get user ID from session", "error", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get user ID from session"})
	}

	name := strings.TrimSpace(c.FormValue("name"))
	if name == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Folder name is required"})
	}

	folder := model.Folder{
		ID:           uuid.New(),
		Name:         name,
		OwnerID:      userID,
		LastModified: time.Now(),
	}

	err = h.repo.CreateFolder(folder)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create folder"})
	}

	// Log audit event
	auditCtx := service.ExtractAuditContext(&userID, c.IP(), c.Get("User-Agent"), sess.ID())
	newValues := map[string]interface{}{
		"name":     folder.Name,
		"owner_id": folder.OwnerID.String(),
	}
	h.auditService.LogFolderAction(c.Context(), folder.ID, model.AuditActionCreate, auditCtx, nil, newValues)

	return c.JSON(fiber.Map{"success": true, "folder": folder})
}

// DeleteFolder deletes a folder for the authenticated user
func (h *AppHandler) DeleteFolder(c *fiber.Ctx) error {
	sess, err := h.store.Get(c)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Session error"})
	}

	userID, err := h.sessionUserId(sess)
	if err != nil {
		if errors.Is(err, ErrSessionUserIDNotFound) {
			return c.Status(401).JSON(fiber.Map{"error": "Unauthorized"})
		}
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to get user ID from session", "error", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get user ID from session"})
	}

	folderIDStr := c.Params("id")
	folderID, err := uuid.Parse(folderIDStr)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid folder ID"})
	}

	// Verify folder belongs to user before deleting
	folder, err := h.repo.GetFolderByID(folderID)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Folder not found"})
	}

	if folder.OwnerID != userID {
		return c.Status(403).JSON(fiber.Map{"error": "Access denied"})
	}

	// Store folder info for audit log
	oldValues := map[string]interface{}{
		"name":     folder.Name,
		"owner_id": folder.OwnerID.String(),
	}

	err = h.repo.DeleteFolder(folderID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to delete folder"})
	}

	// Log audit event
	auditCtx := service.ExtractAuditContext(&userID, c.IP(), c.Get("User-Agent"), sess.ID())
	h.auditService.LogFolderAction(c.Context(), folderID, model.AuditActionDelete, auditCtx, oldValues, nil)

	return c.JSON(fiber.Map{"success": true})
}

// CreateDocument creates a new document for the authenticated user
func (h *AppHandler) CreateDocument(c *fiber.Ctx) error {
	sess, err := h.store.Get(c)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Session error"})
	}

	userID, err := h.sessionUserId(sess)
	if err != nil {
		if errors.Is(err, ErrSessionUserIDNotFound) {
			return c.Status(401).JSON(fiber.Map{"error": "Unauthorized"})
		}
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to get user ID from session", "error", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get user ID from session"})
	}

	name := strings.TrimSpace(c.FormValue("name"))
	if name == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Document name is required"})
	}

	document := model.Document{
		ID:           uuid.New(),
		Name:         name,
		OwnerID:      userID,
		Size:         0,   // Size will be set later when content is uploaded
		FolderID:     nil, // Optional folder ID
		LastModified: time.Now(),
	}

	// Handle optional folder ID
	folderIDStr := c.FormValue("folder_id")
	if folderIDStr != "" {
		folderID, err := uuid.Parse(folderIDStr)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid folder ID"})
		}

		// Verify folder belongs to user
		folder, err := h.repo.GetFolderByID(folderID)
		if err != nil {
			return c.Status(404).JSON(fiber.Map{"error": "Folder not found"})
		}

		// Ensure folder belongs to the user
		if folder.OwnerID != userID {
			return c.Status(403).JSON(fiber.Map{"error": "Access denied to folder"})
		}

		document.FolderID = &folderID
	}

	err = h.repo.CreateDocument(document)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create document"})
	}

	// Track usage if this is a report document
	if strings.Contains(strings.ToLower(document.Name), "report") {
		// Check if user has remaining reports in their plan
		canCreateReport, err := h.usageService.CheckUsageLimits(c.Context(), userID, model.UsageTypeReports)
		if err != nil {
			h.telemetry.Logger().WarnContext(c.Context(), "Failed to check usage limits", "error", err, "user_id", userID)
		} else if !canCreateReport {
			h.telemetry.Logger().InfoContext(c.Context(), "Report created over plan limit", "user_id", userID, "document_name", document.Name)
		}

		// Track report generation usage
		err = h.usageService.TrackReportGeneration(c.Context(), userID, "document_report")
		if err != nil {
			h.telemetry.Logger().ErrorContext(c.Context(), "Failed to track report usage", "error", err, "user_id", userID)
		}
	}

	// Log audit event
	auditCtx := service.ExtractAuditContext(&userID, c.IP(), c.Get("User-Agent"), sess.ID())
	newValues := map[string]interface{}{
		"name":     document.Name,
		"owner_id": document.OwnerID.String(),
	}
	if document.FolderID != nil {
		newValues["folder_id"] = document.FolderID.String()
	}
	h.auditService.LogDocumentAction(c.Context(), document.ID, model.AuditActionCreate, auditCtx, nil, newValues)

	return c.JSON(fiber.Map{"success": true, "document": document})
}

// DeleteDocument deletes a document for the authenticated user
func (h *AppHandler) DeleteDocument(c *fiber.Ctx) error {
	sess, err := h.store.Get(c)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Session error"})
	}

	userID, err := h.sessionUserId(sess)
	if err != nil {
		if errors.Is(err, ErrSessionUserIDNotFound) {
			return c.Status(401).JSON(fiber.Map{"error": "Unauthorized"})
		}
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to get user ID from session", "error", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get user ID from session"})
	}

	documentIDStr := c.Params("id")
	documentID, err := uuid.Parse(documentIDStr)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid document ID"})
	}

	// Verify document belongs to user before deleting
	document, err := h.repo.GetDocumentByID(documentID)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Document not found"})
	}

	if document.OwnerID != userID {
		return c.Status(403).JSON(fiber.Map{"error": "Access denied"})
	}

	// Store document info for audit log
	oldValues := map[string]interface{}{
		"name":     document.Name,
		"owner_id": document.OwnerID.String(),
	}
	if document.FolderID != nil {
		oldValues["folder_id"] = document.FolderID.String()
	}

	err = h.repo.DeleteDocument(documentID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to delete document"})
	}

	// Log audit event
	auditCtx := service.ExtractAuditContext(&userID, c.IP(), c.Get("User-Agent"), sess.ID())
	h.auditService.LogDocumentAction(c.Context(), documentID, model.AuditActionDelete, auditCtx, oldValues, nil)

	return c.JSON(fiber.Map{"success": true})
}

func render(c *fiber.Ctx, component templ.Component) error {
	c.Set("Content-Type", "text/html")
	return component.Render(c.Context(), c.Response().BodyWriter())
}

func (h *AppHandler) sessionUserId(sess *session.Session) (uuid.UUID, error) {
	sessUserID := sess.Get("user_id")
	if sessUserID == nil {
		return uuid.UUID{}, ErrSessionUserIDNotFound
	}

	userIDStr, ok := sessUserID.(string)
	if !ok || userIDStr == "" {
		return uuid.UUID{}, errors.New("invalid user ID")
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return uuid.UUID{}, errors.New("invalid user ID format")
	}

	return userID, nil
}

// UploadFile handles file uploads for documents
func (h *AppHandler) UploadFile(c *fiber.Ctx) error {
	sess, err := h.store.Get(c)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Session error"})
	}

	userID, err := h.sessionUserId(sess)
	if err != nil {
		if errors.Is(err, ErrSessionUserIDNotFound) {
			return c.Status(401).JSON(fiber.Map{"error": "Unauthorized"})
		}
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get user ID"})
	}

	// Get the document ID from URL params
	documentIDStr := c.Params("id")
	documentID, err := uuid.Parse(documentIDStr)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid document ID"})
	}

	// Verify document belongs to user
	document, err := h.repo.GetDocumentByID(documentID)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Document not found"})
	}

	if document.OwnerID != userID {
		return c.Status(403).JSON(fiber.Map{"error": "Access denied"})
	}

	// Get uploaded file
	file, err := c.FormFile("file")
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "No file uploaded"})
	}

	// Validate file size (limit to 10MB for now)
	const maxFileSize = 10 * 1024 * 1024 // 10MB
	if file.Size > maxFileSize {
		return c.Status(400).JSON(fiber.Map{"error": "File too large (max 10MB)"})
	}

	// Open the uploaded file
	src, err := file.Open()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to open uploaded file"})
	}
	defer src.Close()

	// Store the file
	storageKey, err := h.storage.Store(c.Context(), userID, file.Filename, src, file.Header.Get("Content-Type"))
	if err != nil {
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to store file", "error", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to store file"})
	}

	// Update document with storage information
	document.Size = uint64(file.Size)
	document.ContentType = file.Header.Get("Content-Type")
	document.StorageKey = storageKey
	document.LastModified = time.Now()

	err = h.repo.UpdateDocument(document)
	if err != nil {
		// Try to clean up the stored file
		h.storage.Delete(c.Context(), storageKey)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to update document"})
	}

	// Log audit event
	auditCtx := service.ExtractAuditContext(&userID, c.IP(), c.Get("User-Agent"), sess.ID())
	oldValues := map[string]interface{}{
		"size":         0,
		"content_type": "",
		"storage_key":  "",
	}
	newValues := map[string]interface{}{
		"size":         document.Size,
		"content_type": document.ContentType,
		"storage_key":  document.StorageKey,
	}
	h.auditService.LogDocumentAction(c.Context(), documentID, model.AuditActionUpdate, auditCtx, oldValues, newValues)

	return c.JSON(fiber.Map{
		"success":  true,
		"document": document,
		"message":  "File uploaded successfully",
	})
}

// DownloadFile handles file downloads for documents
func (h *AppHandler) DownloadFile(c *fiber.Ctx) error {
	sess, err := h.store.Get(c)
	if err != nil {
		return c.Status(500).SendString("Session error")
	}

	userID, err := h.sessionUserId(sess)
	if err != nil {
		if errors.Is(err, ErrSessionUserIDNotFound) {
			return c.Status(401).SendString("Unauthorized")
		}
		return c.Status(500).SendString("Failed to get user ID")
	}

	// Get the document ID from URL params
	documentIDStr := c.Params("id")
	documentID, err := uuid.Parse(documentIDStr)
	if err != nil {
		return c.Status(400).SendString("Invalid document ID")
	}

	// Verify document belongs to user
	document, err := h.repo.GetDocumentByID(documentID)
	if err != nil {
		return c.Status(404).SendString("Document not found")
	}

	if document.OwnerID != userID {
		return c.Status(403).SendString("Access denied")
	}

	// Check if document has a file
	if document.StorageKey == "" {
		return c.Status(404).SendString("No file associated with this document")
	}

	// Get file from storage
	fileReader, err := h.storage.Retrieve(c.Context(), document.StorageKey)
	if err != nil {
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to retrieve file", "error", err)
		return c.Status(500).SendString("Failed to retrieve file")
	}
	defer fileReader.Close()

	// Set appropriate headers
	c.Set("Content-Type", document.ContentType)
	c.Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, document.Name))
	c.Set("Content-Length", fmt.Sprintf("%d", document.Size))

	// Log audit event for file access
	auditCtx := service.ExtractAuditContext(&userID, c.IP(), c.Get("User-Agent"), sess.ID())
	h.auditService.LogDocumentAction(c.Context(), documentID, model.AuditActionRead, auditCtx, nil, nil)

	// Stream the file to the response
	return c.SendStream(fileReader)
}

// ServeFile serves files for local storage (when using local storage backend)
func (h *AppHandler) ServeFile(c *fiber.Ctx) error {
	// This endpoint is only for local storage
	// For S3, we use presigned URLs directly
	sess, err := h.store.Get(c)
	if err != nil {
		return c.Status(500).SendString("Session error")
	}

	userID, err := h.sessionUserId(sess)
	if err != nil {
		if errors.Is(err, ErrSessionUserIDNotFound) {
			return c.Status(401).SendString("Unauthorized")
		}
		return c.Status(500).SendString("Failed to get user ID")
	}

	// Get storage key from URL path
	storageKey := c.Params("*")
	if storageKey == "" {
		return c.Status(400).SendString("Invalid file path")
	}

	// Verify the file belongs to the user by checking the storage key pattern
	// Storage key format: userID/year/month/uuid_filename
	if !strings.HasPrefix(storageKey, userID.String()+"/") {
		return c.Status(403).SendString("Access denied")
	}

	// Check if file exists
	exists, err := h.storage.Exists(c.Context(), storageKey)
	if err != nil {
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to check file existence", "error", err)
		return c.Status(500).SendString("Internal server error")
	}

	if !exists {
		return c.Status(404).SendString("File not found")
	}

	// Get file metadata
	metadata, err := h.storage.GetMetadata(c.Context(), storageKey)
	if err != nil {
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to get file metadata", "error", err)
		return c.Status(500).SendString("Internal server error")
	}

	// Get file from storage
	fileReader, err := h.storage.Retrieve(c.Context(), storageKey)
	if err != nil {
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to retrieve file", "error", err)
		return c.Status(500).SendString("Failed to retrieve file")
	}
	defer fileReader.Close()

	// Set appropriate headers
	c.Set("Content-Type", metadata.ContentType)
	c.Set("Content-Length", fmt.Sprintf("%d", metadata.Size))
	c.Set("Last-Modified", metadata.LastModified.Format(time.RFC1123))
	c.Set("ETag", metadata.ETag)

	// Stream the file to the response
	return c.SendStream(fileReader)
}

// Subscription handlers
func (h *AppHandler) ShowSubscriptionPlans(c *fiber.Ctx) error {
	sess, err := h.store.Get(c)
	if err != nil {
		return c.Redirect("/auth/login")
	}

	userID, err := h.sessionUserId(sess)
	if err != nil {
		if errors.Is(err, ErrSessionUserIDNotFound) {
			return c.Redirect("/auth/login")
		}
		return c.Status(500).SendString("Failed to get user ID")
	}

	user, err := h.repo.GetUserByID(userID)
	if err != nil {
		return c.Status(500).SendString("Failed to get user")
	}

	plans, err := h.repo.GetSubscriptionPlans(c.Context())
	if err != nil {
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to get subscription plans", "error", err)
		return c.Status(500).SendString("Failed to load subscription plans")
	}

	// Get current subscription if exists
	var currentSubscription *model.UserSubscription
	if sub, err := h.repo.GetActiveSubscriptionByUserID(c.Context(), userID); err == nil {
		currentSubscription = &sub
	}

	return render(c, view.SubscriptionPlansPage(c, user, plans, currentSubscription))
}

func (h *AppHandler) CreateCheckoutSession(c *fiber.Ctx) error {
	sess, err := h.store.Get(c)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Session error"})
	}

	userID, err := h.sessionUserId(sess)
	if err != nil {
		if errors.Is(err, ErrSessionUserIDNotFound) {
			return c.Status(401).JSON(fiber.Map{"error": "Unauthorized"})
		}
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get user ID"})
	}

	var req struct {
		PlanID     string `json:"plan_id"`
		SuccessURL string `json:"success_url"`
		CancelURL  string `json:"cancel_url"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	planID, err := uuid.Parse(req.PlanID)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid plan ID"})
	}

	session, err := h.subscriptionService.CreateCheckoutSession(
		c.Context(), userID, planID, req.SuccessURL, req.CancelURL)
	if err != nil {
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to create checkout session", "error", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create checkout session"})
	}

	return c.JSON(fiber.Map{"checkout_url": session.URL})
}

func (h *AppHandler) CancelSubscription(c *fiber.Ctx) error {
	sess, err := h.store.Get(c)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Session error"})
	}

	userID, err := h.sessionUserId(sess)
	if err != nil {
		if errors.Is(err, ErrSessionUserIDNotFound) {
			return c.Status(401).JSON(fiber.Map{"error": "Unauthorized"})
		}
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get user ID"})
	}

	err = h.subscriptionService.CancelSubscription(c.Context(), userID)
	if err != nil {
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to cancel subscription", "error", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to cancel subscription"})
	}

	return c.JSON(fiber.Map{"success": true})
}

func (h *AppHandler) StripeWebhook(c *fiber.Ctx) error {
	payload := c.Body()
	signature := c.Get("Stripe-Signature")

	err := h.subscriptionService.HandleWebhook(c.Context(), payload, signature)
	if err != nil {
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to handle webhook", "error", err)
		return c.Status(400).JSON(fiber.Map{"error": "Webhook processing failed"})
	}

	return c.JSON(fiber.Map{"received": true})
}

// Usage tracking handlers
func (h *AppHandler) GetUsageSummary(c *fiber.Ctx) error {
	sess, err := h.store.Get(c)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Session error"})
	}

	userID, err := h.sessionUserId(sess)
	if err != nil {
		if errors.Is(err, ErrSessionUserIDNotFound) {
			return c.Status(401).JSON(fiber.Map{"error": "Unauthorized"})
		}
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get user ID"})
	}

	summary, err := h.usageService.GetUsageSummary(c.Context(), userID)
	if err != nil {
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to get usage summary", "error", err, "user_id", userID)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get usage summary"})
	}

	// Get plan limits for comparison
	limits, err := h.subscriptionService.GetPlanLimits(c.Context(), userID)
	if err != nil {
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to get plan limits", "error", err, "user_id", userID)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get plan limits"})
	}

	return c.JSON(fiber.Map{
		"usage_summary": summary,
		"plan_limits":   limits,
	})
}

func (h *AppHandler) ProcessOverages(c *fiber.Ctx) error {
	sess, err := h.store.Get(c)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Session error"})
	}

	userID, err := h.sessionUserId(sess)
	if err != nil {
		if errors.Is(err, ErrSessionUserIDNotFound) {
			return c.Status(401).JSON(fiber.Map{"error": "Unauthorized"})
		}
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get user ID"})
	}

	err = h.usageService.ProcessMonthlyOverages(c.Context(), userID)
	if err != nil {
		h.telemetry.Logger().ErrorContext(c.Context(), "Failed to process overages", "error", err, "user_id", userID)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to process overages"})
	}

	return c.JSON(fiber.Map{"success": true})
}
