package middleware

import (
	"hp/internal/i18n"

	"github.com/gofiber/fiber/v2"
)

func Localization() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Set default language to Dutch
		c.Locals("lang", i18n.NL)
		return c.Next()
	}
}
