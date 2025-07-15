package main

import (
	"log"

	"askfrank/templates"

	"github.com/a-h/templ"
	"github.com/gofiber/fiber/v2"
)

func main() {
	app := fiber.New()

	app.Get("/:name?", func(c *fiber.Ctx) error {
		name := c.Params("name")
		c.Locals("name", name)
		if name == "" {
			name = "World"
		}
		return Render(c, templates.Home(name))
	})
	app.Use(NotFoundMiddleware)

	log.Fatal(app.Listen(":3000"))
}

func NotFoundMiddleware(c *fiber.Ctx) error {
	c.Status(fiber.StatusNotFound)
	return Render(c, templates.NotFound())
}

func Render(c *fiber.Ctx, component templ.Component) error {
	c.Set("Content-Type", "text/html")
	return component.Render(c.Context(), c.Response().BodyWriter())
}
