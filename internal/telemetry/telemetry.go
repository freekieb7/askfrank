package telemetry

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"time"

	"askfrank/internal/config"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/propagation"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	oteltrace "go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

type Telemetry struct {
	tracerProvider *trace.TracerProvider
	loggerProvider *sdklog.LoggerProvider
	config         config.TelemetryConfig
}

// New creates a new telemetry instance with OTLP gRPC exporters for traces and logs
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

	// Create trace exporter
	traceExporter, err := createTraceExporter(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create trace exporter: %w", err)
	}

	// Create log exporter
	logExporter, err := createLogExporter(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create log exporter: %w", err)
	}

	// Create tracer provider
	tp := trace.NewTracerProvider(
		trace.WithBatcher(traceExporter),
		trace.WithResource(res),
		trace.WithSampler(trace.TraceIDRatioBased(cfg.SamplingRatio)),
	)

	// Create logger provider
	lp := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewBatchProcessor(logExporter)),
		sdklog.WithResource(res),
	)

	// Set global providers and propagator
	otel.SetTracerProvider(tp)
	global.SetLoggerProvider(lp)
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
		loggerProvider: lp,
		config:         cfg,
	}, nil
}

// createTraceExporter creates the OTLP trace exporter
func createTraceExporter(cfg config.TelemetryConfig) (trace.SpanExporter, error) {
	opts := createGRPCOptions(cfg)
	return otlptracegrpc.New(context.Background(), opts...)
}

// createLogExporter creates the OTLP log exporter
func createLogExporter(cfg config.TelemetryConfig) (sdklog.Exporter, error) {
	opts := createLogGRPCOptions(cfg)
	return otlploggrpc.New(context.Background(), opts...)
}

// createGRPCOptions creates common gRPC options for trace exporters
func createGRPCOptions(cfg config.TelemetryConfig) []otlptracegrpc.Option {
	// Clean the endpoint URL
	endpoint := strings.TrimPrefix(cfg.ExporterURL, "grpc://")
	endpoint = strings.TrimPrefix(endpoint, "http://")
	endpoint = strings.TrimPrefix(endpoint, "https://")

	// Determine if this is a local endpoint (Alloy) or Grafana Cloud
	isLocal := strings.Contains(endpoint, "127.0.0.1") ||
		strings.Contains(endpoint, "localhost") ||
		!strings.Contains(endpoint, "grafana.net")

	if isLocal {
		// Local Alloy configuration
		slog.Info("Configuring trace telemetry for local Alloy", "endpoint", endpoint)
		return []otlptracegrpc.Option{
			otlptracegrpc.WithEndpoint(endpoint),
			otlptracegrpc.WithTLSCredentials(insecure.NewCredentials()),
		}
	} else {
		// Grafana Cloud configuration
		if cfg.APIKey == "" || cfg.InstanceID == "" {
			slog.Error("Grafana Cloud API key and instance ID are required for remote endpoint")
			return nil
		}

		// Create credentials with authentication
		creds := credentials.NewTLS(&tls.Config{})

		// Create gRPC connection options with auth
		dialOpts := []grpc.DialOption{
			grpc.WithTransportCredentials(creds),
			grpc.WithUnaryInterceptor(func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
				// Add authentication headers
				ctx = metadata.AppendToOutgoingContext(ctx,
					"authorization", fmt.Sprintf("Basic %s:%s", cfg.InstanceID, cfg.APIKey),
				)
				return invoker(ctx, method, req, reply, cc, opts...)
			}),
		}

		slog.Info("Configuring trace telemetry for Grafana Cloud", "endpoint", endpoint)
		return []otlptracegrpc.Option{
			otlptracegrpc.WithEndpoint(endpoint),
			otlptracegrpc.WithTLSCredentials(creds),
			otlptracegrpc.WithDialOption(dialOpts...),
		}
	}
}

// createLogGRPCOptions creates gRPC options for log exporters
func createLogGRPCOptions(cfg config.TelemetryConfig) []otlploggrpc.Option {
	// Clean the endpoint URL
	endpoint := strings.TrimPrefix(cfg.ExporterURL, "grpc://")
	endpoint = strings.TrimPrefix(endpoint, "http://")
	endpoint = strings.TrimPrefix(endpoint, "https://")

	// Determine if this is a local endpoint (Alloy) or Grafana Cloud
	isLocal := strings.Contains(endpoint, "127.0.0.1") ||
		strings.Contains(endpoint, "localhost") ||
		!strings.Contains(endpoint, "grafana.net")

	if isLocal {
		// Local Alloy configuration
		slog.Info("Configuring log telemetry for local Alloy", "endpoint", endpoint)
		return []otlploggrpc.Option{
			otlploggrpc.WithEndpoint(endpoint),
			otlploggrpc.WithTLSCredentials(insecure.NewCredentials()),
		}
	} else {
		// Grafana Cloud configuration
		if cfg.APIKey == "" || cfg.InstanceID == "" {
			slog.Error("Grafana Cloud API key and instance ID are required for remote endpoint")
			return nil
		}

		// Create credentials with authentication
		creds := credentials.NewTLS(&tls.Config{})

		// Create gRPC connection options with auth
		dialOpts := []grpc.DialOption{
			grpc.WithTransportCredentials(creds),
			grpc.WithUnaryInterceptor(func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
				// Add authentication headers
				ctx = metadata.AppendToOutgoingContext(ctx,
					"authorization", fmt.Sprintf("Basic %s:%s", cfg.InstanceID, cfg.APIKey),
				)
				return invoker(ctx, method, req, reply, cc, opts...)
			}),
		}

		slog.Info("Configuring log telemetry for Grafana Cloud", "endpoint", endpoint)
		return []otlploggrpc.Option{
			otlploggrpc.WithEndpoint(endpoint),
			otlploggrpc.WithTLSCredentials(creds),
			otlploggrpc.WithDialOption(dialOpts...),
		}
	}
}

// Shutdown gracefully shuts down the telemetry
func (t *Telemetry) Shutdown(ctx context.Context) error {
	var errs []error

	if t.tracerProvider != nil {
		if err := t.tracerProvider.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("trace provider shutdown: %w", err))
		}
	}

	if t.loggerProvider != nil {
		if err := t.loggerProvider.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("log provider shutdown: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("telemetry shutdown errors: %v", errs)
	}

	return nil
}

// Tracer returns a tracer for the given name
func (t *Telemetry) Tracer(name string) oteltrace.Tracer {
	return otel.Tracer(name)
}

// Logger returns a slog.Logger configured to send logs to OpenTelemetry if enabled, otherwise to stderr.
func (t *Telemetry) Logger() *slog.Logger {
	if t.IsEnabled() {
		return slog.New(NewOTelHandler(&slog.HandlerOptions{AddSource: true}))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{AddSource: true}))
}

// IsEnabled returns whether telemetry is enabled
func (t *Telemetry) IsEnabled() bool {
	return t.config.Enabled && t.tracerProvider != nil
}

// OTelHandler is a slog.Handler that sends logs to OpenTelemetry
type OTelHandler struct {
	logger log.Logger
	opts   *slog.HandlerOptions
}

// NewOTelHandler creates a new OpenTelemetry slog handler
func NewOTelHandler(opts *slog.HandlerOptions) *OTelHandler {
	if opts == nil {
		opts = &slog.HandlerOptions{}
	}

	return &OTelHandler{
		logger: global.GetLoggerProvider().Logger("askfrank.slog"),
		opts:   opts,
	}
}

// Enabled reports whether the handler handles records at the given level
func (h *OTelHandler) Enabled(ctx context.Context, level slog.Level) bool {
	if h.opts.Level != nil {
		return level >= h.opts.Level.Level()
	}
	return level >= slog.LevelInfo
}

// Handle handles the Record
func (h *OTelHandler) Handle(ctx context.Context, record slog.Record) error {
	// Convert slog level to OpenTelemetry log level
	otelLevel := convertSlogLevel(record.Level)

	// Create log record
	logRecord := log.Record{}
	logRecord.SetTimestamp(record.Time)
	logRecord.SetBody(log.StringValue(record.Message))
	logRecord.SetSeverity(otelLevel)
	logRecord.SetSeverityText(record.Level.String())

	// Add trace context if available
	if span := oteltrace.SpanFromContext(ctx); span.SpanContext().IsValid() {
		spanCtx := span.SpanContext()
		logRecord.AddAttributes(
			log.String("trace_id", spanCtx.TraceID().String()),
			log.String("span_id", spanCtx.SpanID().String()),
			log.String("trace_flags", spanCtx.TraceFlags().String()),
		)
	}

	// Add source information
	if h.opts.AddSource {
		fs := runtime.CallersFrames([]uintptr{record.PC})
		f, _ := fs.Next()
		if f.File != "" {
			logRecord.AddAttributes(
				log.String("code.filepath", f.File),
				log.String("code.function", f.Function),
				log.Int("code.lineno", f.Line),
			)
		}
	}

	// Add all attributes from the slog record
	record.Attrs(func(attr slog.Attr) bool {
		logRecord.AddAttributes(convertSlogAttr(attr))
		return true
	})

	// Emit the log record
	h.logger.Emit(ctx, logRecord)

	return nil
}

// WithAttrs returns a new Handler whose attributes consist of both the receiver's attributes and the arguments
func (h *OTelHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	// For simplicity, we'll create a new handler
	// In a production implementation, you might want to store these attrs
	return &OTelHandler{
		logger: h.logger,
		opts:   h.opts,
	}
}

// WithGroup returns a new Handler with the given group appended to the receiver's existing groups
func (h *OTelHandler) WithGroup(name string) slog.Handler {
	// For simplicity, we'll create a new handler
	// In a production implementation, you might want to handle groups
	return &OTelHandler{
		logger: h.logger,
		opts:   h.opts,
	}
}

// convertSlogLevel converts slog.Level to log.Severity
func convertSlogLevel(level slog.Level) log.Severity {
	switch {
	case level >= slog.LevelError:
		return log.SeverityError
	case level >= slog.LevelWarn:
		return log.SeverityWarn
	case level >= slog.LevelInfo:
		return log.SeverityInfo
	default:
		return log.SeverityDebug
	}
}

// convertSlogAttr converts slog.Attr to log.KeyValue
func convertSlogAttr(attr slog.Attr) log.KeyValue {
	switch attr.Value.Kind() {
	case slog.KindString:
		return log.String(attr.Key, attr.Value.String())
	case slog.KindInt64:
		return log.Int64(attr.Key, attr.Value.Int64())
	case slog.KindFloat64:
		return log.Float64(attr.Key, attr.Value.Float64())
	case slog.KindBool:
		return log.Bool(attr.Key, attr.Value.Bool())
	case slog.KindDuration:
		return log.Int64(attr.Key, attr.Value.Duration().Nanoseconds())
	case slog.KindTime:
		return log.String(attr.Key, attr.Value.Time().Format(time.RFC3339))
	default:
		return log.String(attr.Key, attr.Value.String())
	}
}
