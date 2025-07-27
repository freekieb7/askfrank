package api

import (
	"askfrank/internal/middleware"
	"askfrank/internal/model"
	"askfrank/internal/repository"
	"askfrank/resources/view"
	"log/slog"
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

type Handler struct {
	store    *session.Store
	repo     repository.Repository
	security *middleware.SecurityMiddleware
	logger   *slog.Logger
}

func NewHandler(store *session.Store, repository repository.Repository, security *middleware.SecurityMiddleware, logger *slog.Logger) Handler {
	return Handler{store: store, repo: repository, security: security, logger: logger}
}

func (h *Handler) ShowHomePage(c *fiber.Ctx) error {
	return render(c, view.HomePage(c))
}

func (h *Handler) ShowLoginPage(c *fiber.Ctx) error {
	// Store RECAPTCHA site key in locals for template
	c.Locals("recaptcha_site_key", os.Getenv("RECAPTCHA_SITE_KEY"))
	return render(c, view.LoginPage(c))
}

func (h *Handler) Login(c *fiber.Ctx) error {
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
		h.logger.ErrorContext(c.Context(), "Failed to get user by email", "error", err)
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
	if !user.EmailVerified {
		return c.Status(403).JSON(fiber.Map{
			"error": "Please verify your email address before logging in",
		})
	}

	// Store user ID in session
	sess, err := h.store.Get(c)
	if err != nil {
		h.logger.ErrorContext(c.Context(), "Failed to get session", "error", err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to create session",
		})
	}
	sess.Set("user_id", user.ID.String())
	if err := sess.Save(); err != nil {
		h.logger.ErrorContext(c.Context(), "Failed to save session", "error", err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to save session",
		})
	}

	// Log successful login
	h.logger.InfoContext(c.Context(), "User logged in successfully", "email", email, "user_id", user.ID, "ip", c.IP())

	return c.Redirect("/account")
}

func (h *Handler) Logout(c *fiber.Ctx) error {
	sess, err := h.store.Get(c)
	if err != nil {
		h.logger.ErrorContext(c.Context(), "Failed to get session", "error", err)
		return c.Status(500).SendString("Failed to get sessions")
	}

	// Get user ID for logging before deleting
	userID := sess.Get("user_id")

	// Clear session
	sess.Delete("user_id")
	if err := sess.Save(); err != nil {
		h.logger.ErrorContext(c.Context(), "Failed to save session", "error", err)
		return c.Status(500).SendString("Failed to save session")
	}

	// Log successful logout
	if userID != nil {
		h.logger.InfoContext(c.Context(), "User logged out successfully", "user_id", userID, "ip", c.IP())
	}

	return c.Redirect("/auth/login?logout=true")
}

func (h *Handler) ShowCreateUserPage(c *fiber.Ctx) error {
	// Store RECAPTCHA site key in locals for template
	c.Locals("recaptcha_site_key", os.Getenv("RECAPTCHA_SITE_KEY"))
	return render(c, view.CreateUserPage(c))
}

func (h *Handler) ShowCheckInboxPage(c *fiber.Ctx) error {
	sess, err := h.store.Get(c) // Ensure session is initialized
	if err != nil {
		return err
	}

	sessUserId := sess.Get("user_id")
	if sessUserId == nil {
		return c.Redirect("/auth/login")
	}

	userIdStr, ok := sessUserId.(string)
	if !ok {
		return c.Status(400).SendString("Invalid session user ID")
	}

	userId, err := uuid.Parse(userIdStr)
	if err != nil {
		return c.Status(400).SendString("Invalid user ID format")
	}

	user, err := h.repo.GetUserByID(userId)
	if err != nil {
		h.logger.ErrorContext(c.Context(), "Failed to get user by ID", "error", err)
		return c.Status(500).SendString("Failed to retrieve user information")
	}

	return render(c, view.CheckInboxPage(c, user.Email))
}

func (h *Handler) ShowPricingPage(c *fiber.Ctx) error {
	// Render the pricing page
	return render(c, view.PricingPage(c))
}

func (h *Handler) ShowAccountPage(c *fiber.Ctx) error {
	sess, err := h.store.Get(c)
	if err != nil {
		return err
	}

	sessUserId := sess.Get("user_id")
	if sessUserId == nil {
		return c.Redirect("/auth/login")
	}

	userIdStr, ok := sessUserId.(string)
	if !ok {
		return c.Status(400).SendString("Invalid session user ID")
	}

	userId, err := uuid.Parse(userIdStr)
	if err != nil {
		return c.Status(400).SendString("Invalid user ID format")
	}

	user, err := h.repo.GetUserByID(userId)
	if err != nil {
		h.logger.ErrorContext(c.Context(), "Failed to get user by ID", "error", err)
		return c.Status(500).SendString("Failed to retrieve user information")
	}

	return render(c, view.AccountPage(c, user))
}

func (h *Handler) ShowDashboardPage(c *fiber.Ctx) error {
	sess, err := h.store.Get(c)
	if err != nil {
		return err
	}

	sessUserId := sess.Get("user_id")
	if sessUserId == nil {
		return c.Redirect("/auth/login")
	}

	userIdStr, ok := sessUserId.(string)
	if !ok {
		return c.Status(400).SendString("Invalid session user ID")
	}

	userId, err := uuid.Parse(userIdStr)
	if err != nil {
		return c.Status(400).SendString("Invalid user ID format")
	}

	user, err := h.repo.GetUserByID(userId)
	if err != nil {
		h.logger.ErrorContext(c.Context(), "Failed to get user by ID", "error", err)
		return c.Status(500).SendString("Failed to retrieve user information")
	}

	return render(c, view.DashboardPage(c, user))
}

func (h *Handler) CheckInbox(c *fiber.Ctx) error {
	sess, err := h.store.Get(c)
	if err != nil {
		return err
	}

	sessUserId := sess.Get("user_id")
	if sessUserId == nil {
		return c.Redirect("/auth/login")
	}

	userIdStr, ok := sessUserId.(string)
	if !ok {
		return c.Status(400).SendString("Invalid session user ID")
	}

	userId, err := uuid.Parse(userIdStr)
	if err != nil {
		return c.Status(400).SendString("Invalid user ID format")
	}

	user, err := h.repo.GetUserByID(userId)
	if err != nil {
		h.logger.ErrorContext(c.Context(), "Failed to get user by ID", "error", err)
		return c.Status(500).SendString("Failed to retrieve user information")
	}

	activationCode := c.FormValue("activation_code") // Get activation code from form
	if activationCode == "" {
		return c.Status(400).SendString("Activation code is required")
	}

	userRegistration, err := h.repo.GetUserRegistrationByUserID(userId)
	if err != nil {
		h.logger.ErrorContext(c.Context(), "Failed to get user registration by ID", "userid", userId, "error", err)
		return c.Status(500).SendString("Failed to retrieve user registration information")
	}
	if userRegistration.ActivationCode != activationCode {
		return c.Status(400).SendString("Invalid activation code")
	}

	if err := h.repo.DeleteUserRegistration(userRegistration.ID); err != nil {
		h.logger.ErrorContext(c.Context(), "Failed to delete user registration", "error", err)
		return c.Status(500).SendString("Failed to delete user registration")
	}

	user.EmailVerified = true // Mark email as verified

	if err := h.repo.UpdateUser(user); err != nil {
		h.logger.ErrorContext(c.Context(), "Failed to update user", "error", err)
		return c.Status(500).SendString("Failed to update user information")
	}

	return c.Redirect("/account")
}

func (h *Handler) CreateUser(c *fiber.Ctx) error {
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
		h.logger.ErrorContext(c.Context(), "Failed to check existing user", "error", err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Internal server error",
		})
	}

	// Hash the password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		h.logger.ErrorContext(c.Context(), "Failed to hash password", "error", err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to process password",
		})
	}

	// Create user model
	user := model.User{
		ID:            uuid.New(),
		Name:          strings.Split(email, "@")[0],
		Email:         email,
		PasswordHash:  string(passwordHash),
		EmailVerified: false,
		CreatedAt:     time.Now(),
	}

	if err := h.repo.CreateUser(user); err != nil {
		h.logger.ErrorContext(c.Context(), "Failed to create user", "error", err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to create user account",
		})
	}

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
	}

	if err := h.repo.CreateUserRegistration(userRegistration); err != nil {
		h.logger.ErrorContext(c.Context(), "Failed to create user registration", "error", err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Internal server error",
		})
	}

	// Log the signup attempt
	h.logger.InfoContext(c.Context(), "New user signup", "email", email, "newsletter", newsletter != "", "ip", c.IP())
	h.logger.DebugContext(c.Context(), "Activation code generated", "code", codeStr)

	// // Send confirmation email (in production, use a proper email service)
	// go func() {
	// 	if err := sendConfirmationEmail(email, codeStr); err != nil {
	// 		log.Printf("Failed to send confirmation email: %v", err)
	// 	}
	// }()

	// add user to session store
	sess, err := h.store.Get(c)
	if err != nil {
		h.logger.ErrorContext(c.Context(), "Failed to get session", "error", err)
		return c.Status(500).SendString("Failed to get session")
	}
	sess.Set("user_id", user.ID.String())
	if err := sess.Save(); err != nil {
		h.logger.ErrorContext(c.Context(), "Failed to save session", "error", err)
		return c.Status(500).SendString("Failed to save session")
	}

	// Redirect to check inbox page
	return c.Redirect("/auth/sign-up/check-inbox")
}

func (h *Handler) ConfirmUser(c *fiber.Ctx) error {
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
		h.logger.ErrorContext(c.Context(), "Failed to get user registration", "error", err)
		return c.Status(400).SendString("Invalid email or activation code")
	}

	if userRegistration.ActivationCode != activationCode {
		return c.Status(400).SendString("Invalid activation code")
	}

	if err := h.repo.DeleteUserRegistration(userRegistration.ID); err != nil {
		h.logger.ErrorContext(c.Context(), "Failed to delete user registration", "error", err)
		return c.Status(500).SendString("Failed to complete activation")
	}

	h.logger.InfoContext(c.Context(), "User activated successfully", "email", email)

	// Redirect to success page or login
	return c.Redirect("/?activated=true")
}

// ShowAdminPage displays the admin dashboard with user overview
func (h *Handler) ShowAdminPage(c *fiber.Ctx) error {
	h.logger.InfoContext(c.Context(), "Admin dashboard accessed")
	// Check if user is authenticated
	sess, err := h.store.Get(c)
	if err != nil {
		return err
	}

	sessUserId := sess.Get("user_id")
	if sessUserId == nil {
		return c.Redirect("/auth/login")
	}

	userIdStr, ok := sessUserId.(string)
	if !ok {
		return c.Status(400).SendString("Invalid session user ID")
	}

	userId, err := uuid.Parse(userIdStr)
	if err != nil {
		return c.Status(400).SendString("Invalid user ID format")
	}

	// Get current user to check admin privileges
	currentUser, err := h.repo.GetUserByID(userId)
	if err != nil {
		h.logger.ErrorContext(c.Context(), "Failed to get current user", "error", err)
		return c.Status(500).SendString("Failed to retrieve user information")
	}

	// Check if user is admin
	if !isAdminUser(currentUser.Email) {
		h.logger.WarnContext(c.Context(), "Unauthorized admin access attempt", "user_id", userId, "email", currentUser.Email, "ip", c.IP())
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
		h.logger.ErrorContext(c.Context(), "Failed to get user statistics", "error", err)
		return c.Status(500).SendString("Failed to retrieve user statistics")
	}

	// Get all users with pagination
	users, totalUsers, err := h.repo.GetAllUsers(limit, offset)
	if err != nil {
		h.logger.ErrorContext(c.Context(), "Failed to get users", "error", err)
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
	h.logger.InfoContext(c.Context(), "Admin dashboard accessed",
		"admin_user_id", userId,
		"admin_email", currentUser.Email,
		"total_users", stats.TotalUsers,
		"page", page,
		"ip", c.IP(),
	)

	return render(c, view.AdminPage(c, adminData))
}

// isAdminUser checks if the user has admin privileges
// Replace this with your actual admin authorization logic
func isAdminUser(email string) bool {
	// For demo purposes, you can hardcode admin emails
	// In production, use a proper role-based system
	adminEmails := []string{
		"admin@askfrank.com",
		"freek@askfrank.com",
		"freekieb6@hotmail.com", // Replace with your email
		// Add more admin emails as needed
	}

	for _, adminEmail := range adminEmails {
		if email == adminEmail {
			return true
		}
	}

	return false
}

// AdminActivateUser activates a user account (admin only)
func (h *Handler) AdminActivateUser(c *fiber.Ctx) error {
	// Check authentication
	sess, err := h.store.Get(c)
	if err != nil {
		return c.Status(500).SendString("Session error")
	}

	userId, ok := sess.Get("user_id").(string)
	if !ok || userId == "" {
		return c.Status(401).SendString("Unauthorized")
	}

	// Get current user to check admin privileges
	userUUID, err := uuid.Parse(userId)
	if err != nil {
		return c.Status(400).SendString("Invalid user ID")
	}

	currentUser, err := h.repo.GetUserByID(userUUID)
	if err != nil {
		return c.Status(500).SendString("Failed to get current user")
	}

	// Check if user is admin
	if !isAdminUser(currentUser.Email) {
		h.logger.WarnContext(c.Context(), "Non-admin user attempted to access admin function",
			"user_id", userId,
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
		h.logger.ErrorContext(c.Context(), "Failed to activate user",
			"error", err,
			"admin_user_id", userId,
			"target_user_id", targetUserID,
		)
		return c.Status(500).SendString("Failed to activate user")
	}

	// Log admin action
	h.logger.InfoContext(c.Context(), "User activated by admin",
		"admin_user_id", userId,
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
func (h *Handler) AdminDeleteUser(c *fiber.Ctx) error {
	// Check authentication
	sess, err := h.store.Get(c)
	if err != nil {
		return c.Status(500).SendString("Session error")
	}

	userId, ok := sess.Get("user_id").(string)
	if !ok || userId == "" {
		return c.Status(401).SendString("Unauthorized")
	}

	// Get current user to check admin privileges
	userUUID, err := uuid.Parse(userId)
	if err != nil {
		return c.Status(400).SendString("Invalid user ID")
	}

	currentUser, err := h.repo.GetUserByID(userUUID)
	if err != nil {
		return c.Status(500).SendString("Failed to get current user")
	}

	// Check if user is admin
	if !isAdminUser(currentUser.Email) {
		h.logger.WarnContext(c.Context(), "Non-admin user attempted to access admin function",
			"user_id", userId,
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
	if targetUUID == userUUID {
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
		h.logger.ErrorContext(c.Context(), "Failed to delete user",
			"error", err,
			"admin_user_id", userId,
			"target_user_id", targetUserID,
		)
		return c.Status(500).SendString("Failed to delete user")
	}

	// Log admin action
	h.logger.InfoContext(c.Context(), "User deleted by admin",
		"admin_user_id", userId,
		"admin_email", currentUser.Email,
		"target_user_id", targetUserID,
		"target_email", targetUser.Email,
		"ip", c.IP(),
	)

	// Return success response for HTMX (remove the table row)
	return c.Status(200).SendString("")
}

// ShowAdminUserView displays detailed view of a specific user for admins
func (h *Handler) ShowAdminUserView(c *fiber.Ctx) error {
	// Check if user is logged in and has admin privileges
	sess, err := h.store.Get(c)
	if err != nil {
		return c.Redirect("/auth/login")
	}

	sessUserId := sess.Get("user_id")
	if sessUserId == nil {
		return c.Redirect("/auth/login")
	}

	// Ensure user ID is a valid UUID
	userIdStr, ok := sessUserId.(string)
	if !ok || userIdStr == "" {
		return c.Status(400).SendString("Invalid session user ID")
	}

	userId, err := uuid.Parse(userIdStr)
	if err != nil {
		return c.Status(400).SendString("Invalid user ID format")
	}

	// Get current user to verify admin role
	currentUser, err := h.repo.GetUserByID(userId)
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
		h.logger.ErrorContext(c.Context(), "Failed to get user for admin view",
			"error", err,
			"admin_user_id", userId,
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

// Health returns the health status of the application
func (h *Handler) Health(c *fiber.Ctx) error {
	// Check database connectivity
	if err := h.repo.HealthCheck(c.Context()); err != nil {
		return c.Status(503).JSON(fiber.Map{
			"status": "unhealthy",
			"error":  "database connection failed",
		})
	}

	return c.JSON(fiber.Map{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
		"version":   os.Getenv("VERSION"),
	})
}

func render(c *fiber.Ctx, component templ.Component) error {
	c.Set("Content-Type", "text/html")
	return component.Render(c.Context(), c.Response().BodyWriter())
}
