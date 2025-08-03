package api

import (
	"hp/internal/database"
	"log/slog"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stripe/stripe-go/v82/webhook"
)

type ApiHandler struct {
	db *database.PostgresDatabase
}

func NewApiHandler(db *database.PostgresDatabase) *ApiHandler {
	return &ApiHandler{
		db: db,
	}
}

func (h *ApiHandler) Healthy(c *fiber.Ctx) error {
	// Check database connection
	if err := h.db.Ping(c.Context()); err != nil {
		slog.Error("Database connection failed", "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "unhealthy",
			"message": "Database connection failed",
		})
	}

	// Additional health checks can be added here

	return c.JSON(fiber.Map{
		"status":  "healthy",
		"message": "Service is healthy",
	})
}

func (h *ApiHandler) StripeWebhook(c *fiber.Ctx) error {
	// Handle Stripe webhook events
	// This is a placeholder for actual webhook handling logic
	endpointSecret := "whsec_r0fySCr2f4JP6Sm2lXYK8HXJkRApaRhC"
	event, err := webhook.ConstructEvent(c.Body(), c.Get("Stripe-Signature"), endpointSecret)
	if err != nil {
		slog.Error("Failed to construct webhook event", "error", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Invalid webhook payload",
		})
	}
	// Process the event based on its type
	switch event.Type {
	case "customer.subscription.created":
		// Handle successful customer subscription creation
		slog.Info("Customer subscription created", "event", event)
	case "customer.subscription.updated":
		// Handle customer subscription updated
		slog.Info("Customer subscription updated", "event", event)
	case "customer.subscription.deleted":
		// Handle customer subscription deletion
		slog.Info("Customer subscription deleted", "event", event)
	case "invoice.payment_succeeded":
		// Handle successful invoice payment
		slog.Info("Invoice payment succeeded", "event", event)
	case "invoice.payment_failed":
		// Handle failed invoice payment
		slog.Info("Invoice payment failed", "event", event)
	default:
		slog.Info("Unhandled event type", "type", event.Type)
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "Webhook received successfully",
	})
}

type CreateFolderRequest struct {
	Name     string     `json:"name"`
	ParentID *uuid.UUID `json:"parent_id"`
}

func (h *ApiHandler) CreateFolder(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)

	var req CreateFolderRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status": "error",
			"error":  "Invalid request body",
		})
	}

	// Validate folder name
	if req.Name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status": "error",
			"error":  "Folder name is required",
		})
	}

	if len(req.Name) > 100 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status": "error",
			"error":  "Folder name too long (max 100 characters)",
		})
	}

	// Create folder object
	folder := database.Folder{
		ID:      uuid.New(),
		Name:    req.Name,
		OwnerID: userID,
		ParentID: uuid.NullUUID{Valid: req.ParentID != nil, UUID: func() uuid.UUID {
			if req.ParentID != nil {
				return *req.ParentID
			}
			return uuid.UUID{}
		}()},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Save folder to database
	if err := h.db.CreateFolder(c.Context(), folder); err != nil {
		slog.Error("Failed to create folder", "error", err, "user_id", userID)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status": "error",
			"error":  "Failed to create folder",
		})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"status": "success",
		"folder": fiber.Map{
			"id":   folder.ID,
			"name": folder.Name,
		},
	})
}
