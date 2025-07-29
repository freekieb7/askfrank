package logger

import (
	"context"
	"io"
	"log/slog"
	"os"

	"askfrank/internal/config"
	"askfrank/internal/monitoring"
)

// Logger wraps slog.Logger with additional functionality
type Logger struct {
	*slog.Logger
	config config.Config
}

// New creates a new logger instance
func New(cfg config.Config) *Logger {
	var handler slog.Handler

	// Create different handlers based on environment
	if cfg.Server.Environment == "production" {
		// In production, use JSON format and send to OpenTelemetry
		otelHandler := monitoring.NewOTelHandler(&slog.HandlerOptions{
			Level:     slog.LevelInfo,
			AddSource: true,
		})

		// Also create a console handler for local debugging
		consoleHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level:     slog.LevelInfo,
			AddSource: true,
		})

		// Use a multi-handler to send logs to both OpenTelemetry and console
		handler = NewMultiHandler(otelHandler, consoleHandler)
	} else {
		// In development, use text format for better readability
		otelHandler := monitoring.NewOTelHandler(&slog.HandlerOptions{
			Level:     slog.LevelDebug,
			AddSource: true,
		})

		consoleHandler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level:     slog.LevelDebug,
			AddSource: true,
		})

		handler = NewMultiHandler(otelHandler, consoleHandler)
	}

	logger := slog.New(handler).With(
		"service", cfg.Telemetry.ServiceName,
		"version", cfg.Telemetry.ServiceVersion,
		"environment", cfg.Telemetry.Environment,
	)

	// Set as default logger
	slog.SetDefault(logger)

	return &Logger{
		Logger: logger,
		config: cfg,
	}
}

// WithRequest creates a logger with request context
func (l *Logger) WithRequest(ctx context.Context, requestID string) *slog.Logger {
	return l.With(
		"request_id", requestID,
		"user_agent", getUserAgent(ctx),
		"ip_address", getIPAddress(ctx),
	)
}

// WithUser creates a logger with user context
func (l *Logger) WithUser(userID, email string) *slog.Logger {
	return l.With(
		"user_id", userID,
		"user_email", email,
	)
}

// WithError creates a logger with error context
func (l *Logger) WithError(err error) *slog.Logger {
	return l.With(
		"error", err.Error(),
		"error_type", getErrorType(err),
	)
}

// Helper functions
func getUserAgent(ctx context.Context) string {
	if ua := ctx.Value("user_agent"); ua != nil {
		if uaStr, ok := ua.(string); ok {
			return uaStr
		}
	}
	return "unknown"
}

func getIPAddress(ctx context.Context) string {
	if ip := ctx.Value("ip_address"); ip != nil {
		if ipStr, ok := ip.(string); ok {
			return ipStr
		}
	}
	return "unknown"
}

func getErrorType(err error) string {
	if err == nil {
		return ""
	}
	errStr := err.Error()
	if len(errStr) > 50 {
		return errStr[:50]
	}
	return errStr
}

// MultiHandler sends logs to multiple handlers
type MultiHandler struct {
	handlers []slog.Handler
}

// NewMultiHandler creates a new multi-handler
func NewMultiHandler(handlers ...slog.Handler) *MultiHandler {
	return &MultiHandler{handlers: handlers}
}

// Enabled reports whether any handler handles records at the given level
func (h *MultiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, handler := range h.handlers {
		if handler.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

// Handle handles the Record by sending it to all handlers
func (h *MultiHandler) Handle(ctx context.Context, record slog.Record) error {
	for _, handler := range h.handlers {
		if handler.Enabled(ctx, record.Level) {
			if err := handler.Handle(ctx, record); err != nil {
				// Log error but continue with other handlers
				slog.Error("Failed to handle log record", "error", err)
			}
		}
	}
	return nil
}

// WithAttrs returns a new MultiHandler with the given attributes
func (h *MultiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	var newHandlers []slog.Handler
	for _, handler := range h.handlers {
		newHandlers = append(newHandlers, handler.WithAttrs(attrs))
	}
	return &MultiHandler{handlers: newHandlers}
}

// WithGroup returns a new MultiHandler with the given group
func (h *MultiHandler) WithGroup(name string) slog.Handler {
	var newHandlers []slog.Handler
	for _, handler := range h.handlers {
		newHandlers = append(newHandlers, handler.WithGroup(name))
	}
	return &MultiHandler{handlers: newHandlers}
}

// SilenceLogger redirects logs to discard (useful for testing)
func SilenceLogger(w io.Writer) {
	handler := slog.NewTextHandler(w, &slog.HandlerOptions{
		Level: slog.LevelError, // Only show errors
	})
	slog.SetDefault(slog.New(handler))
}
