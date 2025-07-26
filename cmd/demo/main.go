package main

import (
	"askfrank/internal/config"
	"askfrank/internal/logger"
	"askfrank/internal/telemetry"
	"context"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		slog.Error("Failed to load configuration", "error", err)
		return
	}

	// Initialize telemetry
	tel, err := telemetry.New(cfg.Telemetry)
	if err != nil {
		slog.Error("Failed to initialize telemetry", "error", err)
		return
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := tel.Shutdown(ctx); err != nil {
			slog.Error("Failed to shutdown telemetry", "error", err)
		}
	}()

	// Initialize structured logger
	logger.New(*cfg)
	slog.Info("Demo application started", "environment", cfg.Server.Environment)

	// Demo telemetry and logging integration
	tracer := otel.Tracer("askfrank.demo")
	ctx, span := tracer.Start(context.Background(), "demo.operation")
	defer span.End()

	span.SetAttributes(
		attribute.String("demo.type", "telemetry_test"),
		attribute.String("demo.version", "1.0.0"),
	)

	// Structured logging with trace context
	logger := slog.With(
		"operation", "demo",
		"trace_id", span.SpanContext().TraceID().String(),
		"span_id", span.SpanContext().SpanID().String(),
	)

	logger.InfoContext(ctx, "Demo operation started")

	// Simulate some work
	time.Sleep(100 * time.Millisecond)

	logger.InfoContext(ctx, "Demo operation processing", "status", "working")

	// Simulate more work
	time.Sleep(100 * time.Millisecond)

	logger.InfoContext(ctx, "Demo operation completed", "status", "success", "duration_ms", 200)

	slog.Info("Demo completed successfully")

	// Wait a bit for telemetry to be sent
	time.Sleep(2 * time.Second)
}
