package translate

import "github.com/gofiber/fiber/v2"

type Translate func(*fiber.Ctx, string) string
