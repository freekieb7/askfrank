package ui

import (
	"context"

	"github.com/a-h/templ"
	"github.com/freekieb7/askfrank/internal/http"
)

func Render(ctx context.Context, res *http.Response, component templ.Component) error {
	res.SetHeader("Content-Type", "text/html")
	return component.Render(ctx, res)
}
