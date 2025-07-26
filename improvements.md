# 🚀 AskFrank Project Improvements Documentation

## Overview

This document outlines comprehensive improvements implemented in the AskFrank healthcare IT platform to enhance security, maintainability, performance, and developer experience.

## 📋 Table of Contents

1. [Project Structure Improvements](#project-structure-improvements)
2. [Security Enhancements](#security-enhancements)
3. [Code Organization](#code-organization)
4. [Testing Framework](#testing-framework)
5. [Configuration Management](#configuration-management)
6. [Observability & Monitoring](#observability--monitoring)
7. [Performance Optimizations](#performance-optimizations)
8. [DevOps & CI/CD](#devops--cicd)
9. [API Design](#api-design)
10. [Development Workflow](#development-workflow)

---

## 🏗️ Project Structure Improvements

### Current Structure
```
askfrank/
├── internal/
│   ├── api/           # HTTP handlers
│   ├── database/      # Database connection
│   ├── i18n/         # Internationalization
│   ├── middleware/   # Middleware components
│   ├── model/        # Data models
│   └── repository/   # Data access layer
├── resource/view/    # Templ templates
├── translations/     # JSON translations
└── main.go          # Entry point
```

### Improved Structure
```
askfrank/
├── cmd/
│   └── server/       # Application entry points
├── internal/
│   ├── api/          # HTTP handlers (thin layer)
│   ├── service/      # Business logic layer
│   ├── repository/   # Data access layer
│   ├── config/       # Configuration management
│   ├── middleware/   # HTTP middleware
│   ├── validator/    # Input validation
│   ├── auth/         # Authentication service
│   ├── email/        # Email service
│   └── model/        # Data models
├── pkg/              # Reusable packages
├── migrations/       # Database migrations
├── tests/            # Test files
├── scripts/          # Build/deployment scripts
├── docs/             # Documentation
├── .github/          # GitHub workflows
└── deployments/      # Docker/K8s configs
```

---

## 🔒 Security Enhancements

### 1. Authentication Service Layer

**File: `internal/service/auth.go`**
```go
package service

import (
    "askfrank/internal/model"
    "askfrank/internal/repository"
    "context"
    "errors"
    "time"
    
    "golang.org/x/crypto/bcrypt"
)

type AuthService struct {
    repo         repository.Repository
    sessionStore SessionStore
    emailService EmailService
}

type LoginRequest struct {
    Email    string `validate:"required,email"`
    Password string `validate:"required,min=8"`
}

type RegisterRequest struct {
    Email           string `validate:"required,email"`
    Password        string `validate:"required,min=8,password_strength"`
    ConfirmPassword string `validate:"required,eqfield=Password"`
    Terms           bool   `validate:"required,eq=true"`
    Newsletter      bool
}

func (s *AuthService) Login(ctx context.Context, req LoginRequest) (*model.User, error) {
    // Rate limiting check
    if err := s.checkRateLimit(ctx, req.Email); err != nil {
        return nil, err
    }

    // Get user
    user, err := s.repo.GetUserByEmail(req.Email)
    if err != nil {
        s.recordFailedLogin(ctx, req.Email)
        return nil, ErrInvalidCredentials
    }

    // Verify password
    if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
        s.recordFailedLogin(ctx, req.Email)
        return nil, ErrInvalidCredentials
    }

    // Check email verification
    if !user.EmailVerified {
        return nil, ErrEmailNotVerified
    }

    // Record successful login
    s.recordSuccessfulLogin(ctx, user.ID)
    
    return &user, nil
}
```

### 2. Enhanced Input Validation

**File: `internal/validator/validator.go`**
```go
package validator

import (
    "regexp"
    "strings"
    
    "github.com/go-playground/validator/v10"
)

type Validator struct {
    validate *validator.Validate
}

func New() *Validator {
    v := validator.New()
    
    // Custom validators
    v.RegisterValidation("password_strength", validatePasswordStrength)
    v.RegisterValidation("no_disposable_email", validateNoDisposableEmail)
    
    return &Validator{validate: v}
}

func validatePasswordStrength(fl validator.FieldLevel) bool {
    password := fl.Field().String()
    
    // At least 8 characters
    if len(password) < 8 {
        return false
    }
    
    // Must contain uppercase, lowercase, digit, and special char
    hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
    hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
    hasDigit := regexp.MustCompile(`\d`).MatchString(password)
    hasSpecial := regexp.MustCompile(`[!@#$%^&*(),.?":{}|<>]`).MatchString(password)
    
    return hasUpper && hasLower && hasDigit && hasSpecial
}
```

### 3. Rate Limiting Service

**File: `internal/service/ratelimit.go`**
```go
package service

import (
    "context"
    "fmt"
    "time"
    
    "github.com/go-redis/redis/v8"
)

type RateLimiter struct {
    redis *redis.Client
}

func (r *RateLimiter) CheckLogin(ctx context.Context, email string) error {
    key := fmt.Sprintf("login_attempts:%s", email)
    
    count, err := r.redis.Incr(ctx, key).Result()
    if err != nil {
        return err
    }
    
    if count == 1 {
        r.redis.Expire(ctx, key, 15*time.Minute)
    }
    
    if count > 5 {
        return ErrTooManyAttempts
    }
    
    return nil
}
```

---

## 🧪 Testing Framework

### 1. Unit Tests Structure

**File: `tests/service/auth_test.go`**
```go
package service_test

import (
    "askfrank/internal/service"
    "askfrank/tests/mocks"
    "testing"
    
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"
)

func TestAuthService_Login(t *testing.T) {
    tests := []struct {
        name          string
        request       service.LoginRequest
        setupMocks    func(*mocks.Repository)
        expectedError error
    }{
        {
            name: "successful_login",
            request: service.LoginRequest{
                Email:    "test@example.com",
                Password: "Password123!",
            },
            setupMocks: func(repo *mocks.Repository) {
                repo.On("GetUserByEmail", "test@example.com").Return(mockUser, nil)
            },
            expectedError: nil,
        },
        // More test cases...
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            repo := &mocks.Repository{}
            authService := service.NewAuthService(repo, nil, nil)
            
            tt.setupMocks(repo)
            
            user, err := authService.Login(context.Background(), tt.request)
            
            if tt.expectedError != nil {
                assert.Error(t, err)
                assert.Equal(t, tt.expectedError, err)
            } else {
                assert.NoError(t, err)
                assert.NotNil(t, user)
            }
            
            repo.AssertExpectations(t)
        })
    }
}
```

### 2. Integration Tests

**File: `tests/integration/auth_test.go`**
```go
package integration_test

import (
    "askfrank/internal/database"
    "askfrank/tests/testutil"
    "net/http"
    "testing"
)

func TestAuthIntegration(t *testing.T) {
    // Setup test database
    db := testutil.SetupTestDB(t)
    defer testutil.CleanupTestDB(t, db)
    
    // Setup test server
    app := testutil.SetupTestApp(t, db)
    
    t.Run("login_flow", func(t *testing.T) {
        // Create test user
        user := testutil.CreateTestUser(t, db)
        
        // Attempt login
        resp := testutil.PostJSON(t, app, "/auth/login", map[string]string{
            "email":    user.Email,
            "password": "Password123!",
        })
        
        assert.Equal(t, http.StatusOK, resp.StatusCode)
    })
}
```

---

## ⚙️ Configuration Management

### Environment Configuration

**File: `internal/config/config.go`**
```go
package config

import (
    "os"
    "strconv"
    "time"
)

type Config struct {
    Server      ServerConfig      `env:",prefix=SERVER_"`
    Database    DatabaseConfig    `env:",prefix=DB_"`
    Auth        AuthConfig        `env:",prefix=AUTH_"`
    Email       EmailConfig       `env:",prefix=EMAIL_"`
    Redis       RedisConfig       `env:",prefix=REDIS_"`
    Telemetry   TelemetryConfig   `env:",prefix=OTEL_"`
}

type TelemetryConfig struct {
    ServiceName     string `env:"SERVICE_NAME" envDefault:"askfrank"`
    ServiceVersion  string `env:"SERVICE_VERSION" envDefault:"1.0.0"`
    Environment     string `env:"ENVIRONMENT" envDefault:"development"`
    TracingEnabled  bool   `env:"TRACING_ENABLED" envDefault:"true"`
    MetricsEnabled  bool   `env:"METRICS_ENABLED" envDefault:"true"`
    LoggingEnabled  bool   `env:"LOGGING_ENABLED" envDefault:"true"`
    ExporterType    string `env:"EXPORTER_TYPE" envDefault:"jaeger"`
    ExporterURL     string `env:"EXPORTER_URL" envDefault:"http://localhost:14268/api/traces"`
    SamplingRatio   float64 `env:"SAMPLING_RATIO" envDefault:"0.1"`
}

type ServerConfig struct {
    Port         string        `env:"PORT" envDefault:"8080"`
    Host         string        `env:"HOST" envDefault:"localhost"`
    ReadTimeout  time.Duration `env:"READ_TIMEOUT" envDefault:"10s"`
    WriteTimeout time.Duration `env:"WRITE_TIMEOUT" envDefault:"10s"`
    Environment  string        `env:"ENVIRONMENT" envDefault:"development"`
}

type DatabaseConfig struct {
    Host         string `env:"HOST" envDefault:"localhost"`
    Port         int    `env:"PORT" envDefault:"5432"`
    User         string `env:"USER" envDefault:"postgres"`
    Password     string `env:"PASSWORD" envDefault:"postgres"`
    Name         string `env:"NAME" envDefault:"askfrank"`
    SSLMode      string `env:"SSL_MODE" envDefault:"disable"`
    MaxOpenConns int    `env:"MAX_OPEN_CONNS" envDefault:"25"`
    MaxIdleConns int    `env:"MAX_IDLE_CONNS" envDefault:"5"`
}

func Load() (*Config, error) {
    cfg := &Config{}
    
    // Load from environment variables
    if err := env.Parse(cfg); err != nil {
        return nil, err
    }
    
    return cfg, nil
}
```

---

## 📊 Observability & Monitoring

### 1. OpenTelemetry Integration

**File: `internal/telemetry/telemetry.go`**
```go
package telemetry

import (
    "context"
    "log"
    "time"

    "go.opentelemetry.io/otel"
    "go.opentelemetry.io/otel/attribute"
    "go.opentelemetry.io/otel/exporters/jaeger"
    "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
    "go.opentelemetry.io/otel/propagation"
    "go.opentelemetry.io/otel/sdk/resource"
    "go.opentelemetry.io/otel/sdk/trace"
    semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
)

type Telemetry struct {
    tracerProvider *trace.TracerProvider
    config         TelemetryConfig
}

func New(config TelemetryConfig) (*Telemetry, error) {
    // Create resource
    res, err := resource.Merge(
        resource.Default(),
        resource.NewWithAttributes(
            semconv.SchemaURL,
            semconv.ServiceNameKey.String(config.ServiceName),
            semconv.ServiceVersionKey.String(config.ServiceVersion),
            semconv.DeploymentEnvironmentKey.String(config.Environment),
        ),
    )
    if err != nil {
        return nil, err
    }

    // Create exporter based on configuration
    var exporter trace.SpanExporter
    switch config.ExporterType {
    case "jaeger":
        exporter, err = jaeger.New(jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(config.ExporterURL)))
    case "otlp":
        exporter, err = otlptracehttp.New(context.Background(), otlptracehttp.WithEndpoint(config.ExporterURL))
    default:
        return nil, fmt.Errorf("unsupported exporter type: %s", config.ExporterType)
    }
    
    if err != nil {
        return nil, err
    }

    // Create tracer provider
    tp := trace.NewTracerProvider(
        trace.WithBatcher(exporter),
        trace.WithResource(res),
        trace.WithSampler(trace.TraceIDRatioBased(config.SamplingRatio)),
    )

    // Set global tracer provider
    otel.SetTracerProvider(tp)
    otel.SetTextMapPropagator(propagation.TraceContext{})

    return &Telemetry{
        tracerProvider: tp,
        config:         config,
    }, nil
}

func (t *Telemetry) Shutdown(ctx context.Context) error {
    return t.tracerProvider.Shutdown(ctx)
}

func (t *Telemetry) Tracer(name string) trace.Tracer {
    return otel.Tracer(name)
}
```

### 2. Enhanced Structured Logging with OpenTelemetry

**File: `internal/logger/logger.go`**
```go
package logger

import (
    "context"
    "log/slog"
    "os"

    "go.opentelemetry.io/otel/trace"
)

type Logger struct {
    *slog.Logger
}

func New(service string) *Logger {
    handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
        Level: slog.LevelInfo,
        AddSource: true,
    })
    
    logger := slog.New(handler).With(
        "service", service,
        "version", os.Getenv("VERSION"),
    )
    
    return &Logger{Logger: logger}
}

func (l *Logger) WithTrace(ctx context.Context) *Logger {
    span := trace.SpanFromContext(ctx)
    if !span.IsRecording() {
        return l
    }

    spanCtx := span.SpanContext()
    return &Logger{
        Logger: l.Logger.With(
            "trace_id", spanCtx.TraceID().String(),
            "span_id", spanCtx.SpanID().String(),
        ),
    }
}

func (l *Logger) WithRequest(ctx context.Context, requestID string) *Logger {
    logger := l.WithTrace(ctx)
    return &Logger{
        Logger: logger.Logger.With(
            "request_id", requestID,
        ),
    }
}
```

### 3. OpenTelemetry Middleware

**File: `internal/middleware/telemetry.go`**
```go
package middleware

import (
    "fmt"
    "time"

    "github.com/gofiber/fiber/v2"
    "go.opentelemetry.io/otel"
    "go.opentelemetry.io/otel/attribute"
    "go.opentelemetry.io/otel/codes"
    "go.opentelemetry.io/otel/propagation"
    "go.opentelemetry.io/otel/trace"
    semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
)

func OpenTelemetryMiddleware(serviceName string) fiber.Handler {
    tracer := otel.Tracer(serviceName)
    propagator := otel.GetTextMapPropagator()

    return func(c *fiber.Ctx) error {
        // Extract trace context from headers
        ctx := propagator.Extract(c.Context(), &fiberCarrier{c: c})
        
        // Start new span
        spanName := fmt.Sprintf("%s %s", c.Method(), c.Route().Path)
        ctx, span := tracer.Start(ctx, spanName,
            trace.WithAttributes(
                semconv.HTTPMethodKey.String(c.Method()),
                semconv.HTTPURLKey.String(c.OriginalURL()),
                semconv.HTTPRouteKey.String(c.Route().Path),
                semconv.HTTPUserAgentKey.String(c.Get("User-Agent")),
                semconv.NetPeerIPKey.String(c.IP()),
            ),
        )
        defer span.End()

        // Store context in fiber context
        c.SetUserContext(ctx)

        // Record start time
        start := time.Now()

        // Continue with request
        err := c.Next()

        // Record response attributes
        duration := time.Since(start)
        statusCode := c.Response().StatusCode()
        
        span.SetAttributes(
            semconv.HTTPStatusCodeKey.Int(statusCode),
            semconv.HTTPResponseSizeKey.Int(len(c.Response().Body())),
            attribute.Int64("http.duration_ms", duration.Milliseconds()),
        )

        // Set span status based on response
        if statusCode >= 400 {
            span.SetStatus(codes.Error, fmt.Sprintf("HTTP %d", statusCode))
            if err != nil {
                span.RecordError(err)
            }
        } else {
            span.SetStatus(codes.Ok, "")
        }

        return err
    }
}

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
    fc.c.Request().Header.VisitAll(func(key, _ []byte) {
        keys = append(keys, string(key))
    })
    return keys
}
```

### 4. Enhanced Metrics with OpenTelemetry

**File: `internal/metrics/metrics.go`**
```go
package metrics

import (
    "context"
    "time"

    "go.opentelemetry.io/otel"
    "go.opentelemetry.io/otel/exporters/prometheus"
    "go.opentelemetry.io/otel/metric"
    "go.opentelemetry.io/otel/sdk/metric"
)

type Metrics struct {
    LoginAttempts     metric.Int64Counter
    RequestDuration   metric.Float64Histogram
    ActiveConnections metric.Int64UpDownCounter
    DatabaseQueries   metric.Int64Counter
}

func New(serviceName string) (*Metrics, error) {
    // Create Prometheus exporter
    exporter, err := prometheus.New()
    if err != nil {
        return nil, err
    }

    // Create meter provider
    provider := metric.NewMeterProvider(metric.WithReader(exporter))
    otel.SetMeterProvider(provider)

    // Get meter
    meter := otel.Meter(serviceName)

    // Create metrics
    loginAttempts, err := meter.Int64Counter(
        "askfrank_login_attempts_total",
        metric.WithDescription("Total number of login attempts"),
    )
    if err != nil {
        return nil, err
    }

    requestDuration, err := meter.Float64Histogram(
        "askfrank_request_duration_seconds",
        metric.WithDescription("Request duration in seconds"),
        metric.WithUnit("s"),
    )
    if err != nil {
        return nil, err
    }

    activeConnections, err := meter.Int64UpDownCounter(
        "askfrank_active_connections",
        metric.WithDescription("Number of active connections"),
    )
    if err != nil {
        return nil, err
    }

    databaseQueries, err := meter.Int64Counter(
        "askfrank_database_queries_total",
        metric.WithDescription("Total number of database queries"),
    )
    if err != nil {
        return nil, err
    }

    return &Metrics{
        LoginAttempts:     loginAttempts,
        RequestDuration:   requestDuration,
        ActiveConnections: activeConnections,
        DatabaseQueries:   databaseQueries,
    }, nil
}

func (m *Metrics) RecordLoginAttempt(ctx context.Context, status, method string) {
    m.LoginAttempts.Add(ctx, 1, metric.WithAttributes(
        attribute.String("status", status),
        attribute.String("method", method),
    ))
}

func (m *Metrics) RecordRequestDuration(ctx context.Context, duration time.Duration, method, endpoint, status string) {
    m.RequestDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(
        attribute.String("method", method),
        attribute.String("endpoint", endpoint),
        attribute.String("status", status),
    ))
}
```

### 3. Health Checks with OpenTelemetry

**File: `internal/health/health.go`**
```go
package health

import (
    "context"
    "database/sql"
    "encoding/json"
    "net/http"
    "time"

    "go.opentelemetry.io/otel"
    "go.opentelemetry.io/otel/attribute"
    "go.opentelemetry.io/otel/trace"
)

type HealthChecker struct {
    db     *sql.DB
    redis  RedisClient
    tracer trace.Tracer
}

func NewHealthChecker(db *sql.DB, redis RedisClient) *HealthChecker {
    return &HealthChecker{
        db:     db,
        redis:  redis,
        tracer: otel.Tracer("health-checker"),
    }
}

type HealthResponse struct {
    Status    string            `json:"status"`
    Timestamp time.Time         `json:"timestamp"`
    Services  map[string]string `json:"services"`
    Version   string            `json:"version,omitempty"`
    Uptime    string            `json:"uptime,omitempty"`
}

func (h *HealthChecker) Handler(w http.ResponseWriter, r *http.Request) {
    ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
    defer cancel()

    ctx, span := h.tracer.Start(ctx, "health_check")
    defer span.End()
    
    response := HealthResponse{
        Timestamp: time.Now(),
        Services:  make(map[string]string),
        Version:   os.Getenv("VERSION"),
    }
    
    // Check database with tracing
    ctx, dbSpan := h.tracer.Start(ctx, "health_check_database")
    if err := h.db.PingContext(ctx); err != nil {
        response.Services["database"] = "unhealthy"
        response.Status = "unhealthy"
        dbSpan.SetAttributes(attribute.String("error", err.Error()))
        dbSpan.RecordError(err)
    } else {
        response.Services["database"] = "healthy"
        dbSpan.SetAttributes(attribute.String("status", "healthy"))
    }
    dbSpan.End()
    
    // Check Redis with tracing
    ctx, redisSpan := h.tracer.Start(ctx, "health_check_redis")
    if err := h.redis.Ping(ctx).Err(); err != nil {
        response.Services["redis"] = "unhealthy"
        response.Status = "unhealthy"
        redisSpan.SetAttributes(attribute.String("error", err.Error()))
        redisSpan.RecordError(err)
    } else {
        response.Services["redis"] = "healthy"
        redisSpan.SetAttributes(attribute.String("status", "healthy"))
    }
    redisSpan.End()
    
    if response.Status == "" {
        response.Status = "healthy"
    }
    
    statusCode := http.StatusOK
    if response.Status == "unhealthy" {
        statusCode = http.StatusServiceUnavailable
    }

    span.SetAttributes(
        attribute.String("health.status", response.Status),
        attribute.Int("http.status_code", statusCode),
    )
    
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(statusCode)
    json.NewEncoder(w).Encode(response)
}
```

---

## � Technology Updates

### Updated Dependencies

**File: `go.mod`**
```go
module askfrank

go 1.24 // Latest stable version

require (
    github.com/gofiber/fiber/v2 v2.52.4
    github.com/golang-migrate/migrate/v4 v4.17.1
    github.com/lib/pq v1.10.9
    github.com/redis/go-redis/v9 v9.5.4
    github.com/a-h/templ v0.2.747
    github.com/nicksnyder/go-i18n/v2 v2.4.0
    golang.org/x/text v0.16.0
    
    // OpenTelemetry dependencies
    go.opentelemetry.io/otel v1.28.0
    go.opentelemetry.io/otel/trace v1.28.0
    go.opentelemetry.io/otel/metric v1.28.0
    go.opentelemetry.io/otel/exporters/jaeger v1.17.0
    go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.28.0
    go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp v1.28.0
    go.opentelemetry.io/otel/sdk v1.28.0
    go.opentelemetry.io/contrib/instrumentation/github.com/gofiber/fiber/otelfiber/v2 v0.53.0
    
    // Security and validation
    golang.org/x/crypto v0.24.0
    github.com/go-playground/validator/v10 v10.22.0
    
    // Configuration and environment
    github.com/joho/godotenv v1.5.1
    github.com/spf13/viper v1.19.0
    
    // Structured logging
    github.com/rs/zerolog v1.33.0
    
    // Testing and development
    github.com/stretchr/testify v1.9.0
    github.com/golang/mock v1.6.0
)
```

### Database Migration to PostgreSQL 17

**Updated Docker Compose:**
```yaml
version: '3.8'
services:
  postgres:
    image: postgres:17-alpine  # Updated from 15
    environment:
      POSTGRES_DB: askfrank
      POSTGRES_USER: ${DB_USER}
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./migrations:/docker-entrypoint-initdb.d
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${DB_USER} -d askfrank"]
      interval: 30s
      timeout: 10s
      retries: 5

  redis:
    image: redis:7.2-alpine  # Latest stable
    ports:
      - "6379:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 30s
      timeout: 10s
      retries: 5

  jaeger:
    image: jaegertracing/all-in-one:1.58
    ports:
      - "16686:16686"
      - "14268:14268"
    environment:
      - COLLECTOR_OTLP_ENABLED=true

volumes:
  postgres_data:
```

---

## �🐳 DevOps & CI/CD

### 1. Updated Dockerfile with Latest Go

**File: `Dockerfile`**
```dockerfile
# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

# Install templ
RUN go install github.com/a-h/templ/cmd/templ@latest

COPY . .
RUN make generate
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o askfrank .

# Runtime stage
FROM alpine:3.20

RUN apk --no-cache add ca-certificates tzdata
WORKDIR /root/

COPY --from=builder /app/askfrank .
COPY --from=builder /app/translations ./translations/

# Create non-root user
RUN adduser -D -s /bin/sh askfrank
USER askfrank

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

CMD ["./askfrank"]
```

### 2. GitHub Actions with Latest Versions

**File: `.github/workflows/ci.yml`**
```yaml
name: CI/CD Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

env:
  GO_VERSION: '1.24'
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:17-alpine
        env:
          POSTGRES_PASSWORD: testpassword
          POSTGRES_USER: testuser
          POSTGRES_DB: testdb
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432
      
      redis:
        image: redis:7.2-alpine
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 6379:6379

    steps:
    - uses: actions/checkout@v4
    
    - name: Set up Go
      uses: actions/setup-go@v5
      with:
        go-version: ${{ env.GO_VERSION }}
    
    - name: Install templ
      run: go install github.com/a-h/templ/cmd/templ@latest
    
    - name: Generate templates
      run: templ generate
    
    - name: Download dependencies
      run: go mod download
    
    - name: Run tests
      run: make test
      env:
        DB_HOST: localhost
        DB_PORT: 5432
        DB_USER: testuser
        DB_PASSWORD: testpassword
        DB_NAME: testdb
        REDIS_URL: redis://localhost:6379
    
    - name: Run security scan
      run: make security-scan
    
    - name: Upload coverage reports
      uses: codecov/codecov-action@v4
      with:
        file: ./coverage.out

  build:
    needs: test
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Log in to Container Registry
      uses: docker/login-action@v3
      with:
        registry: ${{ env.REGISTRY }}
        username: ${{ github.actor }}
        password: ${{ secrets.GITHUB_TOKEN }}
    
    - name: Extract metadata
      id: meta
      uses: docker/metadata-action@v5
      with:
        images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
        tags: |
          type=ref,event=branch
          type=ref,event=pr
          type=sha,prefix={{branch}}-
    
    - name: Build and push Docker image
      uses: docker/build-push-action@v5
      with:
        context: .
        push: true
        tags: ${{ steps.meta.outputs.tags }}
        labels: ${{ steps.meta.outputs.labels }}
```

### 3. Health Check Endpoint Integration

**Updated main.go with health checks:**
```go
func setupRoutes(app *fiber.App, handlers *api.Handlers, healthChecker *health.HealthChecker) {
    // Health check endpoint
    app.Get("/health", adaptor.HTTPHandler(http.HandlerFunc(healthChecker.Handler)))
    app.Get("/health/ready", adaptor.HTTPHandler(http.HandlerFunc(healthChecker.ReadinessHandler)))
    app.Get("/health/live", adaptor.HTTPHandler(http.HandlerFunc(healthChecker.LivenessHandler)))
    
    // Existing routes...
}
```
```

### 2. GitHub Actions

**File: `.github/workflows/ci.yml`**
```yaml
name: CI/CD Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: postgres
          POSTGRES_DB: askfrank_test
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Set up Go
      uses: actions/setup-go@v4
      with:
        go-version: 1.21
    
    - name: Cache dependencies
      uses: actions/cache@v3
      with:
        path: ~/go/pkg/mod
        key: ${{ runner.os }}-go-${{ hashFiles('**/go.sum') }}
        restore-keys: |
          ${{ runner.os }}-go-
    
    - name: Install dependencies
      run: make deps
    
    - name: Generate code
      run: make generate
    
    - name: Run linters
      run: make lint
    
    - name: Run tests
      run: make test
      env:
        DB_HOST: localhost
        DB_PORT: 5432
        DB_USER: postgres
        DB_PASSWORD: postgres
        DB_NAME: askfrank_test
    
    - name: Run security checks
      run: make security
    
    - name: Upload coverage
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.out

  build:
    needs: test
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Set up Docker Buildx
      uses: docker/setup-buildx-action@v3
    
    - name: Build Docker image
      run: make docker-build
    
    - name: Test Docker image
      run: |
        docker run -d -p 8080:8080 --name test-container askfrank:latest
        sleep 10
        make health
        docker stop test-container
```

---

## 📈 Performance Optimizations

### 1. Database Connection Pooling

**File: `internal/database/pool.go`**
```go
package database

import (
    "database/sql"
    "time"
    
    _ "github.com/lib/pq"
)

func NewConnectionPool(config DatabaseConfig) (*sql.DB, error) {
    db, err := sql.Open("postgres", config.DSN())
    if err != nil {
        return nil, err
    }
    
    // Configure connection pool
    db.SetMaxOpenConns(config.MaxOpenConns)
    db.SetMaxIdleConns(config.MaxIdleConns)
    db.SetConnMaxLifetime(5 * time.Minute)
    db.SetConnMaxIdleTime(30 * time.Second)
    
    return db, nil
}
```

### 2. Caching Layer

**File: `internal/cache/redis.go`**
```go
package cache

import (
    "context"
    "encoding/json"
    "time"
    
    "github.com/go-redis/redis/v8"
)

type Cache struct {
    client *redis.Client
}

func (c *Cache) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
    data, err := json.Marshal(value)
    if err != nil {
        return err
    }
    
    return c.client.Set(ctx, key, data, ttl).Err()
}

func (c *Cache) Get(ctx context.Context, key string, dest interface{}) error {
    data, err := c.client.Get(ctx, key).Result()
    if err != nil {
        return err
    }
    
    return json.Unmarshal([]byte(data), dest)
}
```

---

## 🚀 Development Workflow

### Quick Start Commands

```bash
# Initial setup
make setup

# Development with hot reload
make dev

# Run tests
make test

# Build for production
make build-prod

# Security audit
make security

# Deploy with Docker
make docker-build
make docker-run
```

### Pre-commit Hooks

**File: `.pre-commit-config.yaml`**
```yaml
repos:
  - repo: local
    hooks:
      - id: go-fmt
        name: go-fmt
        entry: make format
        language: system
        pass_filenames: false
        
      - id: go-lint
        name: go-lint
        entry: make lint
        language: system
        pass_filenames: false
        
      - id: go-test
        name: go-test
        entry: make test
        language: system
        pass_filenames: false
        
      - id: security-check
        name: security-check
        entry: make security
        language: system
        pass_filenames: false
```

---

## 📋 Implementation Checklist

### Phase 1: Core Improvements ✅
- [x] ✅ Makefile with comprehensive commands
- [x] ✅ Service layer extraction
- [x] ✅ Enhanced input validation
- [x] ✅ Improved project structure
- [x] ✅ Configuration management

### Phase 2: Security & Testing 🔄
- [ ] 🔄 Rate limiting implementation
- [ ] 🔄 Unit test suite
- [ ] 🔄 Integration tests
- [ ] 🔄 Security audit tools
- [ ] 🔄 CSRF protection enhancement

### Phase 3: Observability 📋
- [ ] 📋 Structured logging
- [ ] 📋 Metrics collection
- [ ] 📋 Health check endpoints
- [ ] 📋 Performance monitoring
- [ ] 📋 Alert system

### Phase 4: DevOps 📋
- [ ] 📋 Docker optimization
- [ ] 📋 CI/CD pipeline
- [ ] 📋 Deployment automation
- [ ] 📋 Environment management
- [ ] 📋 Backup strategies

---

This comprehensive improvement plan transforms AskFrank into a production-ready, enterprise-grade healthcare IT platform with modern development practices, robust security, and excellent maintainability.