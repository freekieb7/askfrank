package api

import (
	"askfrank/internal/monitoring"
	"askfrank/internal/repository"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/google/uuid"
)

type ApiHandler struct {
	store     *session.Store
	repo      repository.Repository
	telemetry monitoring.Telemetry
}

func NewApiHandler(repository repository.Repository) ApiHandler {
	return ApiHandler{repo: repository}
}

// Health returns the health status of the application
func (h *ApiHandler) Health(c *fiber.Ctx) error {
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

func (h *ApiHandler) GetAllFolders(c *fiber.Ctx) error {
	// Retrieve all folders for the authenticated user
	userID := c.Locals("userID").(string) // Assuming userID is stored in Locals after authentication
	if userID == "" {
		return c.Status(401).JSON(fiber.Map{
			"status": "error",
			"error":  "unauthorized",
		})
	}
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{
			"status": "error",
			"error":  "invalid user ID",
		})
	}

	folders, err := h.repo.GetFoldersByUserID(userUUID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"status": "error",
			"error":  err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"status":  "success",
		"folders": folders,
	})
}
