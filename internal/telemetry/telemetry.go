package telemetry

import (
	"context"
	"fmt"
	"log/slog"

	"askfrank/internal/config"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	oteltrace "go.opentelemetry.io/otel/trace"
)

type Telemetry struct {
	tracerProvider *trace.TracerProvider
	config         config.TelemetryConfig
}

// New creates a new telemetry instance with OTLP exporter
func New(cfg config.TelemetryConfig) (*Telemetry, error) {
	if !cfg.Enabled || cfg.ExporterURL == "" {
		slog.Info("Telemetry disabled or no exporter URL provided")
		return &Telemetry{config: cfg}, nil
	}

	// Create resource with service information
	res := resource.NewSchemaless(
		attribute.String("service.name", cfg.ServiceName),
		attribute.String("service.version", cfg.ServiceVersion),
		attribute.String("deployment.environment", cfg.Environment),
	)

	// Create OTLP HTTP exporter
	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(cfg.ExporterURL),
	}

	// Add authentication headers for Grafana Cloud
	if cfg.APIKey != "" {
		headers := map[string]string{
			"Authorization": "Basic " + cfg.APIKey,
		}
		if cfg.InstanceID != "" {
			headers["X-Scope-OrgID"] = cfg.InstanceID
		}
		opts = append(opts, otlptracehttp.WithHeaders(headers))
	}

	exporter, err := otlptracehttp.New(context.Background(), opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP exporter: %w", err)
	}

	// Create tracer provider with batch processor
	tp := trace.NewTracerProvider(
		trace.WithBatcher(exporter),
		trace.WithResource(res),
		trace.WithSampler(trace.TraceIDRatioBased(cfg.SamplingRatio)),
	)

	// Set global tracer provider and propagator
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	slog.Info("Telemetry initialized successfully",
		"service", cfg.ServiceName,
		"version", cfg.ServiceVersion,
		"environment", cfg.Environment,
		"endpoint", cfg.ExporterURL,
		"sampling_ratio", cfg.SamplingRatio,
	)

	return &Telemetry{
		tracerProvider: tp,
		config:         cfg,
	}, nil
}

// Shutdown gracefully shuts down the telemetry
func (t *Telemetry) Shutdown(ctx context.Context) error {
	if t.tracerProvider == nil {
		return nil
	}
	return t.tracerProvider.Shutdown(ctx)
}

// Tracer returns a tracer for the given name
func (t *Telemetry) Tracer(name string) oteltrace.Tracer {
	return otel.Tracer(name)
}

// IsEnabled returns whether telemetry is enabled
func (t *Telemetry) IsEnabled() bool {
	return t.config.Enabled && t.tracerProvider != nil
}
