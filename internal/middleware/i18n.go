package middleware

import (
	"slices"
	"strings"

	"askfrank/internal/i18n"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
)

func I18nMiddleware(i18nInstance *i18n.I18n, store *session.Store) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get session
		sess, err := store.Get(c)
		if err != nil {
			return err
		}

		// Get language from session first, then URL parameter (for initial setup), then header, or default to English
		lang, ok := sess.Get("lang").(string)
		if !ok || lang == "" {
			// Check URL parameter for initial language setting
			lang = c.Query("lang")
			if lang == "" {
				// Check Accept-Language header
				acceptLang := c.Get("Accept-Language")
				if strings.HasPrefix(acceptLang, "nl") {
					lang = "nl"
				} else {
					lang = "en"
				}
			}
		}

		// Validate language
		availableLangs := i18nInstance.GetAvailableLanguages()
		validLang := slices.Contains(availableLangs, lang)
		if !validLang {
			lang = "en" // Default to English
		}

		// Store language in session if it changed
		if currentLang, ok := sess.Get("lang").(string); !ok || currentLang != lang {
			sess.Set("lang", lang)
			if err := sess.Save(); err != nil {
				return err
			}
		}

		// Store language and i18n instance in Fiber's Locals
		c.Locals("lang", lang)
		c.Locals("i18n", i18nInstance)

		return c.Next()
	}
}

func GetLang(c *fiber.Ctx) string {
	if lang, ok := c.Locals("lang").(string); ok {
		return lang
	}
	return "en"
}

func GetI18n(c *fiber.Ctx) *i18n.I18n {
	if i18nInstance, ok := c.Locals("i18n").(*i18n.I18n); ok {
		return i18nInstance
	}
	return nil
}

func T(c *fiber.Ctx, key string) string {
	lang := GetLang(c)
	i18nInstance := GetI18n(c)
	if i18nInstance != nil {
		return i18nInstance.T(lang, key)
	}
	return key
}
