package telemetry

import (
	"context"

	"github.com/gofiber/fiber/v2"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// FiberMiddleware returns a Fiber middleware that creates spans for HTTP requests
func FiberMiddleware(serviceName string) fiber.Handler {
	tracer := otel.Tracer(serviceName)
	propagator := otel.GetTextMapPropagator()

	return func(c *fiber.Ctx) error {
		// Extract trace context from headers
		ctx := propagator.Extract(c.Context(), &fiberCarrier{c: c})

		// Start span
		spanName := c.Method() + " " + c.Route().Path
		if spanName == " " {
			spanName = c.Method() + " " + c.Path()
		}

		ctx, span := tracer.Start(ctx, spanName,
			trace.WithAttributes(
				attribute.String("http.method", c.Method()),
				attribute.String("http.url", c.OriginalURL()),
				attribute.String("http.route", c.Route().Path),
				attribute.String("http.user_agent", c.Get("User-Agent")),
				attribute.String("http.remote_addr", c.IP()),
			),
		)
		defer span.End()

		// Store context in locals for access in handlers
		c.Locals("otel.ctx", ctx)
		c.Locals("otel.span", span)

		// Continue with request
		err := c.Next()

		// Set span status and attributes based on response
		statusCode := c.Response().StatusCode()
		span.SetAttributes(
			attribute.Int("http.status_code", statusCode),
			attribute.Int("http.response_size", len(c.Response().Body())),
		)

		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		} else if statusCode >= 400 {
			span.SetStatus(codes.Error, "HTTP "+string(rune(statusCode)))
		} else {
			span.SetStatus(codes.Ok, "")
		}

		return err
	}
}

// GetSpanFromFiber extracts the span from Fiber context
func GetSpanFromFiber(c *fiber.Ctx) trace.Span {
	if span, ok := c.Locals("otel.span").(trace.Span); ok {
		return span
	}
	return trace.SpanFromContext(context.Background())
}

// GetContextFromFiber extracts the OpenTelemetry context from Fiber context
func GetContextFromFiber(c *fiber.Ctx) context.Context {
	if ctx, ok := c.Locals("otel.ctx").(context.Context); ok {
		return ctx
	}
	return context.Background()
}

// fiberCarrier adapts Fiber context to OpenTelemetry propagation.TextMapCarrier
type fiberCarrier struct {
	c *fiber.Ctx
}

func (fc *fiberCarrier) Get(key string) string {
	return fc.c.Get(key)
}

func (fc *fiberCarrier) Set(key, value string) {
	fc.c.Set(key, value)
}

func (fc *fiberCarrier) Keys() []string {
	keys := make([]string, 0)
	fc.c.Request().Header.VisitAll(func(key, value []byte) {
		keys = append(keys, string(key))
	})
	return keys
}
