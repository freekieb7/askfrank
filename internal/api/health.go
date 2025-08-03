package api

import (
	"hp/internal/database"
	"log/slog"

	"github.com/gofiber/fiber/v2"
)

type HealthHandler struct {
	db *database.PostgresDatabase
}

func NewHealthHandler(db *database.PostgresDatabase) *HealthHandler {
	return &HealthHandler{
		db: db,
	}
}

func (h *HealthHandler) Healthy(c *fiber.Ctx) error {
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
