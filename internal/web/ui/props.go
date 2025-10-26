package ui

import (
	"context"

	"github.com/freekieb7/askfrank/internal/config"
	"github.com/freekieb7/askfrank/internal/i18n"
	"github.com/freekieb7/askfrank/internal/session"
	"github.com/freekieb7/askfrank/internal/web/ui/translate"
	"github.com/freekieb7/askfrank/internal/web/ui/views/component"
)

func LayoutProps(ctx context.Context, title string, translator *i18n.Translator) component.LayoutProps {
	sess := ctx.Value(config.SessionContextKey).(session.Session)

	return component.LayoutProps{
		Title: title,
		Translator: translate.Translator{
			Translator: translator,
			Language:   sess.Data.Language,
		},
		CSRFToken: sess.Data.CsrfToken,
		// Description: "Your healthcare platform",
		// Keywords:    []string{"healthcare", "platform", "askfrank"},
	}
}
