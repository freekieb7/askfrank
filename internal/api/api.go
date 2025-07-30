package api

import (
	"askfrank/internal/repository"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
)

type ApiHandler struct {
	repo repository.Repository
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
