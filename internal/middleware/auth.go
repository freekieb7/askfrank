package middleware

import (
	"hp/internal/database"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
)

func AuthenticatedSession(sessionStore *session.Store) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Check if the user is authenticated
		session, err := sessionStore.Get(c)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).SendString("Session error")
		}
		if session.Get("user_id") == nil {
			// User is not authenticated, redirect to login
			return c.Redirect("/login", fiber.StatusFound)
		}

		c.Locals("user_id", session.Get("user_id"))

		return c.Next()
	}
}

func AuthenticatedToken(db *database.PostgresDatabase) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Check if the user is authenticated via token (e.g., Bearer token)
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(fiber.StatusUnauthorized).SendString("Missing Authorization header")
		}

		// Here you would typically validate the token and extract user information
		// For simplicity, we'll just check if it starts with "Bearer "
		if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
			return c.Status(fiber.StatusUnauthorized).SendString("Invalid Authorization header")
		}

		token := authHeader[7:]
		// Validate the token (this is a placeholder, implement your own logic)
		if token != "valid-token" {
			return c.Status(fiber.StatusUnauthorized).SendString("Invalid token")
		}

		// Assuming the token is valid and corresponds to a user ID
		c.Locals("user_id", "user-id-from-token")

		return c.Next()
	}

}
