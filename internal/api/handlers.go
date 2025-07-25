package api

import (
	"askfrank/internal/middleware"
	"askfrank/internal/model"
	"askfrank/internal/repository"
	"askfrank/resource/view"
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
}

func NewHandler(store *session.Store, repository repository.Repository, security *middleware.SecurityMiddleware) Handler {
	return Handler{store: store, repo: repository, security: security}
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
		slog.Error("Failed to get user by email", "error", err)
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
		slog.Error("Failed to get session", "error", err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to create session",
		})
	}
	sess.Set("user_id", user.ID.String())
	if err := sess.Save(); err != nil {
		slog.Error("Failed to save session", "error", err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to save session",
		})
	}

	// Log successful login
	slog.Info("User logged in successfully", "email", email, "user_id", user.ID, "ip", c.IP())

	return c.Redirect("/account")
}

func (h *Handler) Logout(c *fiber.Ctx) error {
	sess, err := h.store.Get(c)
	if err != nil {
		slog.Error("Failed to get session", "error", err)
		return c.Status(500).SendString("Failed to get session")
	}

	// Get user ID for logging before deleting
	userID := sess.Get("user_id")

	// Clear session
	sess.Delete("user_id")
	if err := sess.Save(); err != nil {
		slog.Error("Failed to save session", "error", err)
		return c.Status(500).SendString("Failed to save session")
	}

	// Log successful logout
	if userID != nil {
		slog.Info("User logged out successfully", "user_id", userID, "ip", c.IP())
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
		slog.Error("Failed to get user by ID", "error", err)
		return c.Status(500).SendString("Failed to retrieve user information")
	}

	return render(c, view.CheckInboxPage(c, user.Email))
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
		slog.Error("Failed to get user by ID", "error", err)
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
		slog.Error("Failed to get user by ID", "error", err)
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
		slog.Error("Failed to get user by ID", "error", err)
		return c.Status(500).SendString("Failed to retrieve user information")
	}

	activationCode := c.FormValue("activation_code") // Get activation code from form
	if activationCode == "" {
		return c.Status(400).SendString("Activation code is required")
	}

	userRegistration, err := h.repo.GetUserRegistrationByUserID(userId)
	if err != nil {
		slog.Error("Failed to get user registration by ID", "userid", userId, "error", err)
		return c.Status(500).SendString("Failed to retrieve user registration information")
	}
	if userRegistration.ActivationCode != activationCode {
		return c.Status(400).SendString("Invalid activation code")
	}

	if err := h.repo.DeleteUserRegistration(userRegistration.ID); err != nil {
		slog.Error("Failed to delete user registration", "error", err)
		return c.Status(500).SendString("Failed to delete user registration")
	}

	user.EmailVerified = true // Mark email as verified

	if err := h.repo.UpdateUser(user); err != nil {
		slog.Error("Failed to update user", "error", err)
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
		slog.Error("Failed to check existing user", "error", err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Internal server error",
		})
	}

	// Hash the password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		slog.Error("Failed to hash password", "error", err)
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
		slog.Error("Failed to create user", "error", err)
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
		slog.Error("Failed to create user registration", "error", err)
		return c.Status(500).JSON(fiber.Map{
			"error": "Internal server error",
		})
	}

	// Log the signup attempt
	slog.Info("New user signup", "email", email, "newsletter", newsletter != "", "ip", c.IP())

	// // Send confirmation email (in production, use a proper email service)
	// go func() {
	// 	if err := sendConfirmationEmail(email, codeStr); err != nil {
	// 		log.Printf("Failed to send confirmation email: %v", err)
	// 	}
	// }()

	// add user to session store
	sess, err := h.store.Get(c)
	if err != nil {
		slog.Error("Failed to get session", "error", err)
		return c.Status(500).SendString("Failed to get session")
	}
	sess.Set("user_id", user.ID.String())
	if err := sess.Save(); err != nil {
		slog.Error("Failed to save session", "error", err)
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
		slog.Error("Failed to get user registration", "error", err)
		return c.Status(400).SendString("Invalid email or activation code")
	}

	if userRegistration.ActivationCode != activationCode {
		return c.Status(400).SendString("Invalid activation code")
	}

	if err := h.repo.DeleteUserRegistration(userRegistration.ID); err != nil {
		slog.Error("Failed to delete user registration", "error", err)
		return c.Status(500).SendString("Failed to complete activation")
	}

	slog.Info("User activated successfully", "email", email)

	// Redirect to success page or login
	return c.Redirect("/?activated=true")
}

func render(c *fiber.Ctx, component templ.Component) error {
	c.Set("Content-Type", "text/html")
	return component.Render(c.Context(), c.Response().BodyWriter())
}
