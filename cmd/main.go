package main

import (
	"context"
	"fmt"
	"hp/internal/api"
	"hp/internal/config"
	"hp/internal/daemon"
	"hp/internal/database"
	"hp/internal/i18n"
	"hp/internal/middleware"
	"hp/internal/openfga"
	"hp/internal/web"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/compress"
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
	ctx, cancel := context.WithCancel(ctx)

	sigChan := make(chan os.Signal, 1)                                    // Create channel to signify a signal being sent
	signal.Notify(sigChan, os.Interrupt, syscall.SIGINT, syscall.SIGTERM) // When an interrupt or termination signal is sent, notify the channel
	go func() {
		sig := <-sigChan
		fmt.Println("Received signal:", sig)
		cancel()
	}()

	cfg := config.NewConfig()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	fgaClient, err := openfga.NewClient(cfg.OpenFGA)
	if err != nil {
		logger.Error("Failed to create OpenFGA client", "error", err)
		return err
	}
	authorization := openfga.NewAuthorizationService(&fgaClient)

	translator := i18n.NewTranslator(i18n.NL)
	if err := translator.LoadTranslations(); err != nil {
		logger.Error("Failed to load translations", "error", err)
	}

	db := database.NewPostgresDatabase(logger)
	if err := db.Init(cfg.Database); err != nil {
		logger.Error("Failed to initialize database", "error", err)
		return err
	}
	defer db.Close()

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

	pageHandler := web.NewPageHandler(logger, &translator, sessionStore, &db, &authorization)
	apiHandler := api.NewApiHandler(logger, &authorization, &db, sessionStore)

	// Middleware
	// Enable gzip compression
	if cfg.Server.Environment == "production" {
		app.Use(compress.New(compress.Config{
			Level: compress.LevelBestSpeed,
		}))
	}

	// app.Use(middleware.Logger())
	// app.Use(middleware.Recover())
	// app.Use(middleware.RequestID())
	// app.Use(middleware.CORS())
	app.Use(middleware.Localization())

	csrfMiddleware := csrf.New(csrf.Config{
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
	})

	// Routes
	app.Get("/", csrfMiddleware, middleware.AuthenticatedSession(sessionStore), pageHandler.ShowHomePage)
	app.Get("/billing", csrfMiddleware, middleware.AuthenticatedSession(sessionStore), pageHandler.ShowBillingPage)
	app.Post("/billing/update", csrfMiddleware, middleware.AuthenticatedSession(sessionStore), pageHandler.UpdateBilling)
	app.Get("/drive", csrfMiddleware, middleware.AuthenticatedSession(sessionStore), pageHandler.ShowMyDrivePage)
	app.Get("/drive/shared", csrfMiddleware, middleware.AuthenticatedSession(sessionStore), pageHandler.ShowSharedFilePage)
	// app.Get("/drive/recent", csrfMiddleware, middleware.AuthenticatedSession(sessionStore), pageHandler.ShowRecentFilePage)
	app.Get("/drive/folder/:folder_id", csrfMiddleware, middleware.AuthenticatedSession(sessionStore), pageHandler.ShowFolderPage)

	app.Get("/login", csrfMiddleware, pageHandler.ShowLoginPage)
	app.Post("/login", csrfMiddleware, pageHandler.Login)

	app.Post("/logout", csrfMiddleware, middleware.AuthenticatedSession(sessionStore), pageHandler.Logout)

	app.Get("/register", csrfMiddleware, pageHandler.ShowRegisterPage)
	app.Post("/register", csrfMiddleware, pageHandler.Register)

	// Static file serving with compression and caching
	app.Static("/static", "./internal/web/static", fiber.Static{
		Compress:  true,
		ByteRange: true,
		Browse:    false,
		MaxAge:    3600, // 1 hour cache
	})

	app.Get("/api/health", apiHandler.Healthy)
	app.All("/api/stripe/webhook", apiHandler.StripeWebhook)

	app.Get("/api/auth/v1/authorize", apiHandler.Authorize)     // OAuth2 authorization endpoint
	app.Post("/api/auth/v1/oauth/token", apiHandler.OAuthToken) // OAuth2 token endpoint

	app.Get("/api/auth/v1/clients", middleware.AuthenticatedToken(&db), apiHandler.ListClients)
	app.Post("/api/auth/v1/clients", middleware.AuthenticatedToken(&db), apiHandler.CreateClient)
	app.Get("/api/auth/v1/clients/:client_id", middleware.AuthenticatedToken(&db), apiHandler.GetClient)
	app.Delete("/api/auth/v1/clients/:client_id", middleware.AuthenticatedToken(&db), apiHandler.DeleteClient)

	app.Get("/api/drive/v1/files", middleware.AuthenticatedToken(&db), apiHandler.ListFiles)                      // List files and folders (supports search query filter).
	app.Post("/api/drive/v1/files", middleware.AuthenticatedToken(&db), apiHandler.CreateFile)                    // Create a folder.
	app.Get("/api/drive/v1/files/:file_id", middleware.AuthenticatedToken(&db), apiHandler.GetFile)               // Get metadata for a specific file.
	app.Delete("/api/drive/v1/files/:file_id", middleware.AuthenticatedToken(&db), apiHandler.DeleteFile)         // Permanently delete a file.
	app.Get("/api/drive/v1/files/:file_id/download", middleware.AuthenticatedToken(&db), apiHandler.DownloadFile) // Download a file.
	app.Post("/api/drive/v1/files/:file_id/share", middleware.AuthenticatedToken(&db), apiHandler.ShareFile)      // Share a file with another user.

	// app.Patch("/api/drive/v1/files/:file_id", middleware.AuthenticatedToken(&db), apiHandler.UpdateFile) // Update metadata.
	app.Post("/api/drive/v1/upload", middleware.AuthenticatedToken(&db), apiHandler.UploadFile) // Upload a file.

	// GET /drive/v3/files/{fileId}/permissions — List permissions for a file.
	// POST /drive/v3/files/{fileId}/permissions — Add sharing permissions.
	// DELETE /drive/v3/files/{fileId}/permissions/{permissionId} — Remove permission.

	// GET /drive/v3/files/{fileId}/comments — List comments.
	// POST /drive/v3/files/{fileId}/comments — Add new comment.
	// PATCH /drive/v3/files/{fileId}/comments/{commentId} — Update comment.
	// DELETE /drive/v3/files/{fileId}/comments/{commentId} — Delete comment.

	// Nested under comments:
	// GET /drive/v3/files/{fileId}/comments/{commentId}/replies — List replies.
	// POST /…/replies — Create reply.
	// PATCH / DELETE for reply operations.

	// GET /drive/v3/changes/startPageToken — Obtain token for listing incremental changes.
	// GET /drive/v3/changes — List changes since token.
	// POST /drive/v3/changes/watch — Subscribe to drive changes via push notifications.

	// For Shared Drives:
	// GET /drive/v3/drives — List drives.
	// GET /drive/v3/drives/{driveId} — Get metadata for a shared drive.
	// POST /drives — Create new shared drive.
	// PATCH, DELETE, hide, unhide actions supported.

	// GET /drive/v3/apps — List installed Drive apps for the user.
	// GET /drive/v3/apps/{appId} — Retrieve metadata for a Drive app.

	// Start the server
	go func() {
		if err := app.Listen(cfg.Server.Host + ":" + cfg.Server.Port); err != nil {
			panic(err)
		}
	}()

	manager := daemon.NewDaemonManager()
	manager.Add("cleanup", daemon.CleanupTask(&db, logger))

	fmt.Println("Starting supervised daemons...")
	manager.Start(ctx)

	go func() {
		manager.Wait()
		fmt.Println("All daemons stopped")
	}()

	<-sigChan // This blocks the main thread until an interrupt is received
	err = app.Shutdown()
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
