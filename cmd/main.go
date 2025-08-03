package main

import (
	"context"
	"hp/internal/api"
	"hp/internal/config"
	"hp/internal/database"
	"hp/internal/i18n"
	"hp/internal/middleware"
	"hp/internal/web"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/csrf"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/gofiber/fiber/v2/utils"
	"github.com/gofiber/storage/postgres/v3"
)

func main() {
	if err := run(context.Background()); err != nil {
		panic(err)
	}
}

func run(ctx context.Context) error {
	cfg := config.NewConfig()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	translator := i18n.NewTranslator(i18n.NL)
	if err := translator.LoadTranslations(); err != nil {
		logger.Error("Failed to load translations", "error", err)
	}

	db := database.NewDatabase(cfg.Database)

	sessionStore := session.New(session.Config{
		Expiration: 24 * time.Hour,
		Storage: postgres.New(postgres.Config{
			DB:         db.Pool,
			Table:      "tbl_session",
			Reset:      false,
			GCInterval: 10 * time.Second,
		}),
		CookieHTTPOnly: true,
		CookieSecure:   cfg.Server.Environment == "production",
		CookieSameSite: "Lax",
	})

	// Set up Fiber app
	app := fiber.New(fiber.Config{
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	})

	pageHandler := web.NewPageHandler(logger, translator, sessionStore, db)
	healthHandler := api.NewHealthHandler(db)

	// Middleware
	// app.Use(middleware.Logger())
	// app.Use(middleware.Recover())
	// app.Use(middleware.RequestID())
	// app.Use(middleware.CORS())
	app.Use(middleware.Localization())
	app.Use(csrf.New(csrf.Config{
		KeyLookup:         "header:X-Csrf-Token",
		CookieName:        "hp-csrf_",
		CookieSameSite:    "Lax",
		CookieSecure:      cfg.Server.Environment == "production",
		CookieSessionOnly: true,
		CookieHTTPOnly:    true,
		Expiration:        1 * time.Hour,
		KeyGenerator:      utils.UUIDv4,
		Session:           sessionStore,
		SessionKey:        "fiber.csrf.token",
		ContextKey:        "csrf_token",
	}))

	// Static file serving
	app.Static("/static", "./internal/web/static")

	// Routes
	app.Get("/", middleware.Authenticated(sessionStore), pageHandler.ShowHomePage)

	app.Get("/login", pageHandler.ShowLoginPage)
	app.Post("/login", pageHandler.Login)

	app.Post("/logout", pageHandler.Logout)

	app.Get("/register", pageHandler.ShowRegisterPage)
	app.Post("/register", pageHandler.Register)

	app.Get("/api/health", healthHandler.Healthy)

	// Start the server
	go func() {
		if err := app.Listen(cfg.Server.Host + ":" + cfg.Server.Port); err != nil {
			panic(err)
		}
	}()

	c := make(chan os.Signal, 1)                    // Create channel to signify a signal being sent
	signal.Notify(c, os.Interrupt, syscall.SIGTERM) // When an interrupt or termination signal is sent, notify the channel

	<-c // This blocks the main thread until an interrupt is received
	err := app.Shutdown()
	if err != nil {
		slog.Error("Error shutting down", "error", err)
	}

	slog.Info("Running cleanup tasks...")

	// Your cleanup tasks go here
	// db.Close()
	// redisConn.Close()
	slog.Info("Fiber was successful shutdown.")

	return nil
}
