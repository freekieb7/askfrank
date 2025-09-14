package middleware

import (
	"log/slog"

	"github.com/gofiber/fiber/v2"
)

func Logger() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Check if the user is authenticated
		slog.Info("Request", "method", c.Method(), "url", c.OriginalURL(), "ip", c.IP())

		return c.Next()
	}
}
