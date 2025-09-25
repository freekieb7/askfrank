package main

import (
	"context"
	"fmt"
	"hp/internal/config"
	"hp/internal/daemon"
	"hp/internal/database"
	"hp/internal/i18n"
	"hp/internal/session"
	"hp/internal/stripe"
	"hp/internal/web"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

func main() {
	if err := run(context.Background()); err != nil {
		panic(err)
	}
}

func run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		fmt.Println("Received signal:", sig)
		cancel()
	}()

	cfg := config.NewConfig()

	// Set up logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// // Set up OpenFGA client
	// fgaClient, err := openfga.NewClient(cfg.OpenFGA)
	// if err != nil {
	// 	logger.Error("Failed to create OpenFGA client", "error", err)
	// 	return err
	// }
	// authorization := openfga.NewAuthorizationService(&fgaClient)

	// Set up Stripe client
	stripeClient := stripe.NewClient(cfg.Stripe.APIKey)

	// Set up i18n translator
	translator := i18n.NewTranslator(i18n.NL)
	if err := translator.LoadTranslations(); err != nil {
		logger.Error("Failed to load translations", "error", err)
	}

	// Set up Postgres connection
	pg := database.NewPostgres()
	db := database.NewDatabase(&pg, logger)
	dsn := "host=" + cfg.Database.Host +
		" port=" + strconv.Itoa(cfg.Database.Port) +
		" user=" + cfg.Database.User +
		" password=" + cfg.Database.Password +
		" dbname=" + cfg.Database.Name +
		" sslmode=" + cfg.Database.SSLMode

	if err := db.Connect(dsn); err != nil {
		logger.Error("Failed to initialize database", "error", err)
		return err
	}
	defer db.Close()

	// Set up session store
	sessionStore := session.New(
		&db,
		session.Config{
			CookieHTTPOnly: true,
			CookieSecure:   cfg.Server.Environment == config.EnvironmentProduction,
			CookieSameSite: http.SameSiteLaxMode,
			CookieName:     "SID",
			Path:           "/",
			Domain:         "",                                // Add this - leave empty for current domain or set explicitly
			CookieMaxAge:   int(24 * time.Hour / time.Second), // Add explicit MaxAge
		})

	// Set up Fiber app
	router := web.NewRouter()
	// app := fiber.New(fiber.Config{
	// 	ReadTimeout:  cfg.Server.ReadTimeout,
	// 	WriteTimeout: cfg.Server.WriteTimeout,
	// })

	pageHandler := web.NewPageHandler(logger, &translator, &sessionStore, &db, &stripeClient)
	apiHandler := web.NewApiHandler(logger, &db, &sessionStore)

	// Middleware
	// Enable gzip compression
	// if cfg.Server.Environment == config.EnvironmentProduction {
	// 	app.Use(compress.New(compress.Config{
	// 		Level: compress.LevelBestSpeed,
	// 	}))
	// }

	// app.Use(middleware.Logger())
	// app.Use(middleware.Recover())
	// app.Use(middleware.RequestID())
	// app.Use(middleware.CORS())
	// app.Use(middleware.Localization())

	// csrfMiddleware := csrf.New(csrf.Config{
	// 	KeyLookup:         "header:X-CSRF-Token",
	// 	CookieName:        "hp-csrf_",
	// 	CookieSameSite:    "Lax",
	// 	CookieSecure:      cfg.Server.Environment == "production",
	// 	CookieSessionOnly: true,
	// 	CookieHTTPOnly:    true,
	// 	Expiration:        1 * time.Hour,
	// 	KeyGenerator:      utils.UUIDv4,
	// 	Session:           sessionStore,
	// 	SessionKey:        "fiber.csrf.token",
	// 	ContextKey:        "csrf_token",
	// })

	// Routes
	router.Static("/static", "./internal/web/static")
	router.Group("", func(group *web.Router) {
		// Public routes
		group.GET("/login", pageHandler.ShowLoginPage)
		group.POST("/login", pageHandler.Login)

		group.GET("/register", pageHandler.ShowRegisterPage)
		group.POST("/register", pageHandler.Register)
		group.GET("/docs", pageHandler.ShowDocsPage)

		// Protected routes
		group.Group("", func(group *web.Router) {
			group.GET("/dashboard", pageHandler.ShowHomePage)
			group.POST("/logout", pageHandler.Logout)

			group.Group("/billing", func(billingGroup *web.Router) {
				// billingGroup.Use(middleware.AuthenticatedSession(sessionStore))
				billingGroup.GET("", pageHandler.ShowBillingPage)
				// billingGroup.POST("/update", pageHandler.UpdateBilling)
			})
			group.Group("/drive", func(driveGroup *web.Router) {
				driveGroup.GET("", pageHandler.ShowMyDrivePage)
				driveGroup.POST("/create_folder", pageHandler.CreateFolder)
				driveGroup.POST("/upload_file", pageHandler.UploadFile)
				driveGroup.GET("/shared", pageHandler.ShowSharedFilePage)
				// driveGroup.GET("/recent", pageHandler.ShowRecentFilePage)
				driveGroup.GET("/folder/:folder_id", pageHandler.ShowFolderPage)
			})

			// Calendar routes
			group.Group("/calendar", func(calendarGroup *web.Router) {
				calendarGroup.GET("", pageHandler.ShowCalendarPage)
				// calendarGroup.GET("/events/:id", pageHandler.GetCalendarEvent)
				// calendarGroup.POST("/events", pageHandler.CreateCalendarEvent)
				// calendarGroup.POST("/events/:id/delete", pageHandler.DeleteCalendarEvent)
				// calendarGroup.POST("/events/:id/invite", pageHandler.InviteToCalendarEvent)
			})

			// Developer routes
			group.Group("/developers", func(devGroup *web.Router) {
				devGroup.Group("/clients", func(clientGroup *web.Router) {
					clientGroup.GET("", pageHandler.ShowOAuthClientsPage)
					clientGroup.POST("", pageHandler.CreateOAuthClient)
					clientGroup.GET("/:id", pageHandler.GetOAuthClient)
					clientGroup.POST("/:id/delete", pageHandler.DeleteOAuthClient)
				})

				devGroup.Group("/webhooks", func(webhookGroup *web.Router) {
					webhookGroup.GET("", pageHandler.ShowWebhooksPage)
					webhookGroup.POST("", pageHandler.CreateWebhookSubscription)
					// webhookGroup.GET("/:id", pageHandler.GetWebhook)
					webhookGroup.POST("/:id/delete", pageHandler.DeleteWebhook)
				})

				devGroup.GET("/logs", pageHandler.ShowAuditLogsPage)

			})

			// Add UI routes for video chat
			group.GET("/meetings/:id", pageHandler.ShowMeetingPage)
			group.GET("/meetings", pageHandler.ShowCreateMeetingPage)
		}, web.AuthenticatedSessionMiddleware(&sessionStore))

	}, web.SessionMiddleware(&sessionStore), web.LocalizationMiddleware(), web.CSRFMiddleware(logger, &sessionStore))

	// API routes (for testing and integration)
	router.Group("/api", func(apiGroup *web.Router) {
		// Public API routes
		apiGroup.GET("/health", apiHandler.Healthy)

		// Protected API routes (require session authentication)
		apiGroup.Group("", func(protectedApiGroup *web.Router) {
			// Webhook testing endpoint
			protectedApiGroup.POST("/webhook/test", apiHandler.TriggerTestWebhookEvent)
		}, web.AuthenticatedSessionMiddleware(&sessionStore))
	})

	// // WebRTC signaling
	// app.Use("/ws/rtc", func(c *fiber.Ctx) error {
	// 	// Check if websocket request
	// 	if websocket.IsWebSocketUpgrade(c) {
	// 		// Get user from session to authenticate
	// 		sess, err := sessionStore.Get(c)
	// 		if err != nil {
	// 			return c.Status(fiber.StatusUnauthorized).SendString("Unauthorized")
	// 		}

	// 		userID := sess.Get("user_id")
	// 		if userID == nil {
	// 			return c.Status(fiber.StatusUnauthorized).SendString("Unauthorized")
	// 		}

	// 		c.Locals("user_id", userID)
	// 		return c.Next()
	// 	}
	// 	return c.Status(fiber.StatusUpgradeRequired).SendString("Upgrade required")
	// })

	// signalingServer := rtc.NewSignalingServer(logger)
	// app.Get("/ws/rtc", websocket.New(func(c *websocket.Conn) {
	// 	signalingServer.HandleConnection(c)
	// }))

	// // Static file serving with compression and caching
	// app.Static("/static", "./internal/web/static", fiber.Static{
	// 	Compress:  true,
	// 	ByteRange: true,
	// 	Browse:    false,
	// 	MaxAge:    3600, // 1 hour cache
	// })

	// app.Get("/api/health", apiHandler.Healthy)
	// app.All("/api/stripe/webhook", apiHandler.StripeWebhook)

	// app.Get("/api/auth/v1/authorize", apiHandler.Authorize)     // OAuth2 authorization endpoint
	// app.Post("/api/auth/v1/oauth/token", apiHandler.OAuthToken) // OAuth2 token endpoint

	// app.Get("/api/auth/v1/clients", middleware.AuthenticatedToken(&db), apiHandler.ListClients)
	// app.Post("/api/auth/v1/clients", middleware.AuthenticatedToken(&db), apiHandler.CreateClient)
	// app.Get("/api/auth/v1/clients/:client_id", middleware.AuthenticatedToken(&db), apiHandler.GetClient)
	// app.Delete("/api/auth/v1/clients/:client_id", middleware.AuthenticatedToken(&db), apiHandler.DeleteClient)

	// app.Get("/api/drive/v1/files", middleware.AuthenticatedToken(&db), apiHandler.ListFiles)                      // List files and folders (supports search query filter).
	// app.Post("/api/drive/v1/files", middleware.AuthenticatedToken(&db), apiHandler.CreateFile)                    // Create a folder.
	// app.Get("/api/drive/v1/files/:file_id", middleware.AuthenticatedToken(&db), apiHandler.GetFile)               // Get metadata for a specific file.
	// app.Delete("/api/drive/v1/files/:file_id", middleware.AuthenticatedToken(&db), apiHandler.DeleteFile)         // Permanently delete a file.
	// app.Get("/api/drive/v1/files/:file_id/download", middleware.AuthenticatedToken(&db), apiHandler.DownloadFile) // Download a file.
	// app.Post("/api/drive/v1/files/:file_id/share", middleware.AuthenticatedToken(&db), apiHandler.ShareFile)      // Share a file with another user.

	// // app.Patch("/api/drive/v1/files/:file_id", middleware.AuthenticatedToken(&db), apiHandler.UpdateFile) // Update metadata.
	// app.Post("/api/drive/v1/upload", middleware.AuthenticatedToken(&db), apiHandler.UploadFile) // Upload a file.

	// // GET /drive/v3/files/{fileId}/permissions — List permissions for a file.
	// // POST /drive/v3/files/{fileId}/permissions — Add sharing permissions.
	// // DELETE /drive/v3/files/{fileId}/permissions/{permissionId} — Remove permission.

	// // GET /drive/v3/files/{fileId}/comments — List comments.
	// // POST /drive/v3/files/{fileId}/comments — Add new comment.
	// // PATCH /drive/v3/files/{fileId}/comments/{commentId} — Update comment.
	// // DELETE /drive/v3/files/{fileId}/comments/{commentId} — Delete comment.

	// // Nested under comments:
	// // GET /drive/v3/files/{fileId}/comments/{commentId}/replies — List replies.
	// // POST /…/replies — Create reply.
	// // PATCH / DELETE for reply operations.

	// // GET /drive/v3/changes/startPageToken — Obtain token for listing incremental changes.
	// // GET /drive/v3/changes — List changes since token.
	// // POST /drive/v3/changes/watch — Subscribe to drive changes via push notifications.

	// // For Shared Drives:
	// // GET /drive/v3/drives — List drives.
	// // GET /drive/v3/drives/{driveId} — Get metadata for a shared drive.
	// // POST /drives — Create new shared drive.
	// // PATCH, DELETE, hide, unhide actions supported.

	// // GET /drive/v3/apps — List installed Drive apps for the user.
	// // GET /drive/v3/apps/{appId} — Retrieve metadata for a Drive app.

	// Start the server
	server := web.NewServer(logger, router)
	go func() {
		if err := server.ListenAndServe(cfg.Server.Host + ":" + cfg.Server.Port); err != nil {
			panic(err)
		}
	}()

	manager := daemon.NewDaemonManager()
	manager.Add("cleanup", daemon.CleanupTask(&db, logger))
	manager.Add("webhooks", daemon.SendWebhookDeliveriesTask(&db, logger))

	logger.Info("Starting supervised daemons...")
	manager.Start(ctx)

	go func() {
		manager.Wait()
		logger.Info("All daemons stopped")
	}()

	<-sigChan // This blocks the main thread until an interrupt is received
	// err := app.Shutdown()
	// if err != nil {
	// 	slog.Error("Error shutting down", "error", err)
	// }

	logger.Info("Running cleanup tasks...")

	// Your cleanup tasks go here
	// db.Close()
	// redisConn.Close()
	logger.Info("Fiber was successful shutdown.")

	return nil
}
