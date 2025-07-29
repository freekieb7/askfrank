package main

import (
	"askfrank/internal/api"
	"askfrank/internal/config"
	"askfrank/internal/database"
	"askfrank/internal/i18n"
	"askfrank/internal/middleware"
	"askfrank/internal/monitoring"
	"askfrank/internal/repository"
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"

	"github.com/a-h/templ"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/csrf"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/gofiber/fiber/v2/utils"
	"github.com/gofiber/storage/postgres/v3"
	_ "github.com/lib/pq"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize telemetry
	telemetry, err := monitoring.NewOpenTelemetry(cfg.Telemetry)
	if err != nil {
		log.Fatalf("Failed to initialize telemetry: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := telemetry.Shutdown(ctx); err != nil {
			slog.Error("Failed to shutdown telemetry", "error", err)
		}
	}()

	slog.Info("AskFrank Healthcare IT Platform starting",
		"version", os.Getenv("VERSION"),
		"environment", cfg.Server.Environment,
		"telemetry_enabled", cfg.Telemetry.Enabled,
	)

	// Initialize internationalization
	i18nInstance := i18n.New("en")
	err = i18nInstance.LoadTranslations("translations")
	if err != nil {
		log.Fatalf("Failed to load translations: %v", err)
	}

	// Initialize session store
	sessionStorage := postgres.New(postgres.Config{
		Host:     cfg.Database.Host,
		Port:     cfg.Database.Port,
		Database: cfg.Database.Name,
		Username: cfg.Database.User,
		Password: cfg.Database.Password,
		Table:    "sessions",
		Reset:    false, // Don't reset the table on startup
	})

	store := session.New(session.Config{
		Storage:        sessionStorage,
		KeyLookup:      "cookie:session_id",
		CookieDomain:   "",
		CookiePath:     "/",
		CookieSecure:   cfg.Server.Environment == "production",
		CookieHTTPOnly: true,
		CookieSameSite: "Lax",
		Expiration:     cfg.Auth.SessionExpiration,
	})

	// Connect to the database
	dataSourceName := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Database.Host, cfg.Database.Port, cfg.Database.User, cfg.Database.Password, cfg.Database.Name, cfg.Database.SSLMode)
	db, err := database.NewPostgresDatabase(dataSourceName)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Initialize repository
	repo := repository.NewPostgresRepository(db)

	// Initialize security middleware
	securityConfig := middleware.SecurityConfig{
		RecaptchaSecretKey: cfg.Security.ReCaptchaSecretKey,
		MaxSignupAttempts:  cfg.Security.MaxSignupAttempts,
		RateLimitWindow:    15 * time.Minute,
		BlockDuration:      cfg.Security.BlockDuration,
	}
	securityMiddleware := middleware.NewSecurityMiddleware(securityConfig)

	handler := api.NewHandler(store, repo, telemetry)

	// Set up Fiber app
	app := fiber.New(fiber.Config{
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	})

	// Add telemetry middleware (first to capture all requests)
	if cfg.Telemetry.Enabled {
		app.Use(monitoring.FiberMiddleware(cfg.Telemetry.ServiceName))
	}

	// Add security headers middleware
	// app.Use(middleware.SecurityHeadersMiddleware()) // todo enable after fixing script issues

	// Add input sanitization middleware
	app.Use(middleware.InputSanitizationMiddleware())

	// CSRF Protection with session-based configuration (recommended)
	app.Use(csrf.New(csrf.Config{
		KeyLookup:         "header:X-Csrf-Token",
		CookieName:        "askfrank-csrf_",
		CookieSameSite:    "Lax",
		CookieSecure:      cfg.Server.Environment == "production",
		CookieSessionOnly: true,
		CookieHTTPOnly:    true,
		Expiration:        1 * time.Hour,
		KeyGenerator:      utils.UUIDv4,
		Session:           store,
		SessionKey:        "fiber.csrf.token",
		ContextKey:        "token",
	}))

	// Add IP blocking middleware globally
	app.Use(securityMiddleware.IPBlockMiddleware())

	// Add i18n middleware
	app.Use(middleware.I18nMiddleware(i18nInstance, store))

	// Rate limiting for sign-up endpoints with configuration
	signupLimiter := limiter.New(limiter.Config{
		Max:        cfg.Security.MaxSignupAttempts,
		Expiration: cfg.Security.BlockDuration,
		KeyGenerator: func(c *fiber.Ctx) string {
			return c.IP() // Limit by IP address
		},
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(429).JSON(fiber.Map{
				"error": "Too many sign-up attempts. Please try again later.",
			})
		},
	})

	// Language switching endpoint
	app.Get("/lang/:lang", func(c *fiber.Ctx) error {
		lang := c.Params("lang")
		sess, err := store.Get(c)
		if err != nil {
			return err
		}

		// Validate language
		availableLangs := i18nInstance.GetAvailableLanguages()
		validLang := slices.Contains(availableLangs, lang)

		if validLang {
			sess.Set("lang", lang)
			if err := sess.Save(); err != nil {
				return err
			}
		}

		// Redirect back to referer or home
		referer := c.Get("Referer")
		if referer == "" {
			referer = "/"
		}
		return c.Redirect(referer)
	})

	app.Get("/", handler.ShowHomePage)

	app.Get("/health", func(c *fiber.Ctx) error {
		if err := repo.HealthCheck(c.Context()); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"status": "unhealthy",
				"error":  err.Error(),
			})
		}
		return c.JSON(fiber.Map{
			"status":            "healthy",
			"version":           os.Getenv("VERSION"),
			"environment":       cfg.Server.Environment,
			"telemetry_enabled": cfg.Telemetry.Enabled,
		})
	})

	// Login routes
	app.Get("/auth/login", handler.ShowLoginPage)
	app.Post("/auth/login", handler.Login)
	app.Post("/auth/logout", handler.Logout)

	// Auth routes with rate limiting and security validation
	app.Get("/auth/sign-up/create-user", handler.ShowCreateUserPage)
	app.Post("/auth/sign-up/create-user", signupLimiter, securityMiddleware.ValidateSignupForm, handler.CreateUser)
	app.Get("/auth/sign-up/check-inbox", handler.ShowCheckInboxPage)
	app.Post("/auth/sign-up/check-inbox", signupLimiter, handler.CheckInbox)
	app.Post("/auth/sign-up/confirm", handler.ConfirmUser)

	// Pricing routes
	app.Get("/pricing", handler.ShowPricingPage)

	// Account routes
	app.Get("/account", handler.ShowAccountPage)

	// Dashboard routes
	app.Get("/dashboard", handler.ShowDashboardPage)

	// Admin routes
	app.Get("/admin", handler.ShowAdminPage)
	app.Get("/admin/users/:id", handler.ShowAdminUserView)
	app.Post("/admin/users/:id/activate", handler.AdminActivateUser)
	app.Delete("/admin/users/:id", handler.AdminDeleteUser)

	port := cfg.Server.Port
	if port == "" {
		port = "8080"
	}

	// Setup graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		slog.Info("Gracefully shutting down AskFrank...")
		_ = app.Shutdown()
	}()

	slog.Info("AskFrank Healthcare IT Platform started",
		"port", port,
		"environment", cfg.Server.Environment,
		"security_features", map[string]interface{}{
			"rate_limiting":   cfg.Security.RateLimitEnabled,
			"csrf_protection": true,
			"telemetry":       cfg.Telemetry.Enabled,
		},
	)

	if err := app.Listen(":" + port); err != nil {
		slog.Error("Failed to start server", "error", err)
	}

	slog.Info("AskFrank Healthcare IT Platform stopped")
}

func Render(c *fiber.Ctx, component templ.Component) error {
	c.Set("Content-Type", "text/html")
	return component.Render(c.Context(), c.Response().BodyWriter())
}
