package web

import (
	"hp/internal/i18n"
	"hp/internal/web/views"

	"github.com/a-h/templ"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
)

type PageHandler struct {
	translator   *i18n.Translator
	sessionStore *session.Store
}

func NewPageHandler(translator *i18n.Translator, sessionStore *session.Store) *PageHandler {
	return &PageHandler{translator: translator, sessionStore: sessionStore}
}

func (h *PageHandler) ShowHomePage(c *fiber.Ctx) error {
	return render(c, views.HomePage(c, h.translate))
}

func (h *PageHandler) ShowLoginPage(c *fiber.Ctx) error {
	sess, err := h.sessionStore.Get(c)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Failed to get session")
	}

	if sess.Get("user_id") != nil {
		return c.Redirect("/", fiber.StatusSeeOther) // Redirect if already logged in
	}

	return render(c, views.LoginPage(c, h.translate))
}

func (h *PageHandler) Login(c *fiber.Ctx) error {
	sess, err := h.sessionStore.Get(c)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Failed to get session")
	}
	defer sess.Save()

	sess.Set("user_id", "example_user_id") // Set user ID or other session data

	return c.Redirect("/", fiber.StatusSeeOther)
}

func (h *PageHandler) Logout(c *fiber.Ctx) error {
	sess, err := h.sessionStore.Get(c)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Failed to get session")
	}
	defer sess.Save()

	sess.Destroy() // Clear the session

	return c.Redirect("/login", fiber.StatusSeeOther)
}

func (h *PageHandler) ShowRegisterPage(c *fiber.Ctx) error {
	return render(c, views.RegisterPage(c, h.translate))
}

func render(c *fiber.Ctx, component templ.Component) error {
	c.Set("Content-Type", "text/html")
	return component.Render(c.Context(), c.Response().BodyWriter())
}

func (h *PageHandler) translate(c *fiber.Ctx, key string) string {
	lang := c.Locals("lang").(i18n.Language)
	return h.translator.T(lang, key)
}
