package web

import (
	"encoding/gob"
	"hp/internal/database"
	"hp/internal/i18n"
	"hp/internal/web/views"
	"log/slog"
	"time"

	"github.com/a-h/templ"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func init() {
	gob.Register(uuid.UUID{}) // Register uuid.UUID for session storage
}

type PageHandler struct {
	logger       *slog.Logger
	translator   *i18n.Translator
	sessionStore *session.Store
	db           *database.PostgresDatabase
}

func NewPageHandler(logger *slog.Logger, translator *i18n.Translator, sessionStore *session.Store, db *database.PostgresDatabase) *PageHandler {
	return &PageHandler{logger: logger, translator: translator, sessionStore: sessionStore, db: db}
}

func (h *PageHandler) ShowHomePage(c *fiber.Ctx) error {
	return render(c, views.HomePage(c, h.translate))
}

func (h *PageHandler) ShowLoginPage(c *fiber.Ctx) error {
	sess, err := h.sessionStore.Get(c)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Failed to get session")
	}

	if sess.Get("user_id") != nil {
		return c.Redirect("/", fiber.StatusSeeOther) // Redirect if already logged in
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

	user, err := h.db.GetUserByEmail(c.Context(), email)
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

	// Set user ID in session
	sess.Set("user_id", user.ID)

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":   "success",
		"message":  "Login successful! Redirecting...",
		"redirect": "/",
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

	return c.Redirect("/login", fiber.StatusSeeOther)
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
	_, err = h.db.GetUserByEmail(c.Context(), email)
	if err == nil {
		// User already exists
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error": "An account with this email already exists",
		})
	}
	if err != database.ErrUserNotFound {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Something went wrong, please try again later",
		})
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to hash password, please try again later",
		})
	}

	user := database.User{
		ID:              uuid.New(),
		Name:            name,
		Email:           email,
		PasswordHash:    passwordHash,
		IsEmailVerified: false,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	if err := h.db.CreateUser(c.Context(), user); err != nil {
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

func render(c *fiber.Ctx, component templ.Component) error {
	c.Set("Content-Type", "text/html")
	return component.Render(c.Context(), c.Response().BodyWriter())
}

func (h *PageHandler) translate(c *fiber.Ctx, key string) string {
	lang := c.Locals("lang").(i18n.Language)
	return h.translator.T(lang, key)
}
