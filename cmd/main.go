package main

import (
	"context"
	"fmt"
	"hp/internal/audit"
	"hp/internal/auth"
	"hp/internal/calendar"
	"hp/internal/config"
	"hp/internal/daemon"
	"hp/internal/database"
	"hp/internal/drive"
	"hp/internal/i18n"
	"hp/internal/notifications"
	"hp/internal/oauth"
	"hp/internal/session"
	"hp/internal/user"
	"hp/internal/web"
	"hp/internal/web/api"
	"hp/internal/web/page"
	"hp/internal/webhook"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
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

	// Set up i18n translator
	translator := i18n.NewTranslator(i18n.NL)
	if err := translator.LoadTranslations(); err != nil {
		logger.Error("Failed to load translations", "error", err)
	}

	// Set up Postgres connection
	db := database.NewDatabase()

	if err := db.Connect(ctx, cfg.Database.URL); err != nil {
		logger.Error("Failed to initialize database", "error", err)
		return err
	}
	defer db.Close()

	// Set up session store
	sessionStore := session.New(&db, session.Config{
		CookieName:     "SID",
		CookieHTTPOnly: true,
		CookieSecure:   cfg.Server.Environment == config.EnvironmentProduction,
		CookieSameSite: http.SameSiteLaxMode,
		Domain:         "",
		Path:           "/",
		ExpiresIn:      30 * 24 * time.Hour,
	})

	auditor := audit.NewAuditor(logger, &db)
	webhookManager := webhook.NewManager(logger, &db)
	notifier := notifications.NewManager(logger, &db)
	authenticator := auth.NewAuthenticator(logger, &db, &auditor, &webhookManager, &notifier)
	userManager := user.NewManager(logger, &db, &auditor, &webhookManager, &notifier)
	driveManager := drive.NewManager(logger, &db, &auditor, &notifier)
	oauthManager := oauth.NewManager(logger, &db, &auditor)
	planner := calendar.NewManager(logger, &db, &auditor, &notifier)
	webhookManager = webhook.NewManager(logger, &db)

	// Set up signaling server for WebRTC
	// signalingServer := rtc.NewSignalingServer(logger)

	// Set up Fiber app
	router := web.NewRouter()

	pageHandler := page.NewPageHandler(logger, &translator, &sessionStore, &userManager, &webhookManager, &authenticator, &notifier, &driveManager, &oauthManager, &planner, &auditor)
	apiHandler := api.NewAPIHandler(logger, &db, &userManager, &oauthManager)
	oauthHandler := api.NewOAuthHandler(logger, &db, &sessionStore, &oauthManager)
	// meetingHandler := web.NewMeetingHandler(logger, signalingServer, &sessionStore)
	// chatHandler := web.NewChatHandler(logger)

	// Middleware
	// Enable gzip compression
	// if cfg.Server.Environment == config.EnvironmentProduction {
	// 	app.Use(compress.New(compress.Config{
	// 		Level: compress.LevelBestSpeed,
	// 	}))
	// }

	// app.Use(middleware.CORS())

	// Routes
	router.Static("/static", "./internal/web/page/static")
	router.GET("/", pageHandler.ShowHomePage)

	router.Group("", func(group *web.Router) {
		// Public routes
		group.GET("/docs", pageHandler.ShowDocsPage)

		group.Group("/login", func(group *web.Router) {
			group.GET("", pageHandler.ShowLoginPage)
			group.POST("", pageHandler.Login)
		})

		group.Group("/register", func(group *web.Router) {
			group.GET("", pageHandler.ShowRegisterPage)
			group.POST("", pageHandler.Register)
		})

		// Protected routes
		group.Group("", func(group *web.Router) {
			group.GET("/dashboard", pageHandler.ShowDashboardPage)
			group.POST("/logout", pageHandler.Logout)

			// group.Group("/billing", func(billingGroup *web.Router) {
			// billingGroup.Use(middleware.AuthenticatedSession(sessionStore))
			// billingGroup.GET("", pageHandler.ShowBillingPage)
			// billingGroup.POST("/change_subscription", pageHandler.ChangeSubscription)
			// })
			// group.Group("/drive", func(driveGroup *web.Router) {
			// driveGroup.GET("", pageHandler.ShowMyDrivePage)
			// driveGroup.POST("/create_folder", pageHandler.CreateFolder)
			// driveGroup.POST("/upload_file", pageHandler.UploadFile)
			// driveGroup.GET("/shared", pageHandler.ShowSharedFilePage)
			// driveGroup.GET("/recent", pageHandler.ShowRecentFilePage)
			// driveGroup.GET("/folder/{folder_id}", pageHandler.ShowFolderPage)
			// })

			// Calendar routes
			// group.Group("/calendar", func(calendarGroup *web.Router) {
			// calendarGroup.GET("", pageHandler.ShowCalendarPage)
			// calendarGroup.GET("/events/:id", pageHandler.GetCalendarEvent)
			// calendarGroup.POST("/events", pageHandler.CreateCalendarEvent)
			// calendarGroup.POST("/events/:id/delete", pageHandler.DeleteCalendarEvent)
			// calendarGroup.POST("/events/:id/invite", pageHandler.InviteToCalendarEvent)
			// })

			// Developer routes
			group.Group("/developers", func(group *web.Router) {
				group.Group("/clients", func(group *web.Router) {
					group.GET("", pageHandler.ShowClientsPage)
					group.POST("/create-client", pageHandler.CreateClient)
					group.POST("/delete-client", pageHandler.DeleteClient)
				})

				// devGroup.Group("/webhooks", func(webhookGroup *web.Router) {
				// webhookGroup.GET("", pageHandler.ShowWebhooksPage)
				// webhookGroup.POST("", pageHandler.CreateWebhookSubscription)
				// webhookGroup.GET("/:id", pageHandler.GetWebhook)
				// webhookGroup.POST("/{webhook_id}/delete", pageHandler.DeleteWebhook)
				// })

				// devGroup.GET("/logs", pageHandler.ShowAuditLogsPage)
			})

			// group.Group("/chat", func(chatGroup *web.Router) {
			// chatGroup.GET("", pageHandler.ShowChatPage)
			// })

			// Add UI routes for video chat
			// group.Group("/meetings", func(meetingsGroup *web.Router) {
			// meetingsGroup.GET("", pageHandler.ShowMeetingsPage)
			// meetingsGroup.GET("/{meeting_id}", pageHandler.ShowMeetingPage)
			// })
		}, page.AuthenticatedMiddleware(&sessionStore))

	}, page.SessionMiddleware(&cfg, logger, &sessionStore), page.CSRFMiddleware(logger, &sessionStore))

	// WebSocket routes (need authentication but not CSRF protection)
	// router.Group("/ws", func(wsGroup *web.Router) {
	// 	wsGroup.GET("/rtc", meetingHandler.HandleRTCConnection)
	// 	wsGroup.GET("/chat", chatHandler.HandleChatWebSocket)
	// }, web.SessionMiddleware(&sessionStore), web.AuthenticatedSessionMiddleware(&sessionStore))

	// API routes (for testing and integration)
	router.Group("/api", func(apiGroup *web.Router) {
		// Public API routes
		apiGroup.GET("/health", apiHandler.Healthy, api.AuthenticatedMiddleware(&db))
		apiGroup.GET("/clients", apiHandler.ListClients, api.AuthenticatedMiddleware(&db), api.AuthorizedMiddleware(logger, &db, []oauth.Scope{oauth.ScopeClientsRead}))

		// 	// Protected API routes (require session authentication)
		// 	apiGroup.Group("", func(protectedApiGroup *web.Router) {
		// 		// Notification endpoints
		// 		protectedApiGroup.POST("/notifications/:id/read", apiHandler.MarkNotificationAsRead)
		// 		protectedApiGroup.POST("/notifications/mark-all-read", apiHandler.MarkAllNotificationsAsRead)
		// 		protectedApiGroup.GET("/notifications", apiHandler.GetNotifications)

		// 		// Calendar endpoints
		// 		protectedApiGroup.GET("/calendar/events", apiHandler.GetCalendarEvents)
		// 		protectedApiGroup.POST("/calendar/events", apiHandler.CreateCalendarEvent)
		// 		protectedApiGroup.PUT("/calendar/events/:id", apiHandler.UpdateCalendarEvent)
		// 		protectedApiGroup.DELETE("/calendar/events/:id", apiHandler.DeleteCalendarEvent)
		// 	}, web.AuthenticatedSessionMiddleware(&sessionStore))
	}, api.ContentNegotiationMiddleware())

	// // Static file serving with compression and caching
	// app.Static("/static", "./internal/web/static", fiber.Static{
	// 	Compress:  true,
	// 	ByteRange: true,
	// 	Browse:    false,
	// 	MaxAge:    3600, // 1 hour cache
	// })

	router.Group("/oauth", func(group *web.Router) {
		group.GET("/authorize", oauthHandler.Authorize, page.SessionMiddleware(&cfg, logger, &sessionStore)) // OAuth2 authorization endpoint
		group.POST("/token", oauthHandler.Token, api.ContentNegotiationMiddleware())                         // OAuth2 token endpoint
	})
	// app.Get("/api/health", apiHandler.Healthy)

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
		logger.Info("Starting HTTP server...", "addr", cfg.Server.Host+":"+cfg.Server.Port)
		if err := server.ListenAndServe(cfg.Server.Host + ":" + cfg.Server.Port); err != nil {
			panic(err)
		}
	}()

	manager := daemon.NewDaemonManager()
	// manager.Add("cleanup", daemon.CleanupTask(&db, logger))
	// manager.Add("webhooks", daemon.SendWebhookDeliveriesTask(&db, logger))

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
