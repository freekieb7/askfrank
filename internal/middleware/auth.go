package middleware

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
)

func Authenticated(sessionStore *session.Store) fiber.Handler {
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
