package main

import (
	"askfrank/internal/api"
	"askfrank/internal/database"
	"askfrank/internal/i18n"
	"askfrank/internal/middleware"
	"askfrank/internal/repository"
	"fmt"
	"log"
	"os"
	"slices"
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

const (
	host     = "localhost"
	port     = 5432
	user     = "postgres"
	password = "postgres"
	dbname   = "postgres"
)

func main() {
	// Initialize internationalization
	i18nInstance := i18n.New("en")
	err := i18nInstance.LoadTranslations("translations")
	if err != nil {
		log.Fatalf("Failed to load translations: %v", err)
	}

	// Initialize session store
	sessionStorage := postgres.New(postgres.Config{
		Host:     host,
		Port:     port,
		Database: dbname,
		Username: user,
		Password: password,
		Table:    "sessions",
		Reset:    false, // Don't reset the table on startup
	})

	store := session.New(session.Config{
		Storage:        sessionStorage,
		KeyLookup:      "cookie:session_id",
		CookieDomain:   "",
		CookiePath:     "/",
		CookieSecure:   false,
		CookieHTTPOnly: true,
		CookieSameSite: "Lax",
		Expiration:     24 * 60 * 60, // 24 hours
	})

	// Connect to the database
	dataSourceName := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable", host, port, user, password, dbname)
	db, err := database.NewDatabase(dataSourceName)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Initialize repository
	repo := repository.NewRepository(db)

	// Run database migrations
	if err := repo.Migrate(); err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}

	// Initialize security middleware
	securityConfig := middleware.DefaultSecurityConfig()
	securityMiddleware := middleware.NewSecurityMiddleware(securityConfig)

	handler := api.NewHandler(store, repo, securityMiddleware)

	// Set up Fiber app
	app := fiber.New()

	// CSRF Protection
	app.Use(csrf.New(csrf.Config{
		KeyLookup:      "form:csrf_token",
		CookieName:     "csrf_",
		CookieSameSite: "Lax",
		CookieSecure:   false, // Set to true in production with HTTPS
		Expiration:     1 * time.Hour,
		KeyGenerator:   utils.UUIDv4,
		ContextKey:     "token", // This makes the token available in c.Locals("token")
	}))

	// Middleware to expose CSRF token to all templates
	app.Use(func(c *fiber.Ctx) error {
		return c.Next()
	}) // Add IP blocking middleware globally
	app.Use(securityMiddleware.IPBlockMiddleware())

	// Add i18n middleware
	app.Use(middleware.I18nMiddleware(i18nInstance, store))

	// Rate limiting for sign-up endpoints
	signupLimiter := limiter.New(limiter.Config{
		Max:        5,                // 5 attempts
		Expiration: 15 * time.Minute, // per 15 minutes
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

	// Account routes
	app.Get("/account", handler.ShowAccountPage)

	// Dashboard routes
	app.Get("/dashboard", handler.ShowDashboardPage)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Starting server on :%s", port)
	log.Panic(app.Listen(":" + port))
}

func Render(c *fiber.Ctx, component templ.Component) error {
	c.Set("Content-Type", "text/html")
	return component.Render(c.Context(), c.Response().BodyWriter())
}
