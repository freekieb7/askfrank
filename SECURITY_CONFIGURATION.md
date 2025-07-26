# Security Configuration Implementation

This document describes the comprehensive security configuration that has been implemented for the AskFrank Healthcare IT Platform.

## Overview

The security configuration provides a centralized way to manage all security-related settings including authentication, authorization, rate limiting, CSRF protection, reCAPTCHA integration, and other security features.

## Configuration Structure

### SecurityConfig in `internal/config/config.go`

```go
type SecurityConfig struct {
    ReCaptchaSecretKey string        // reCAPTCHA v2 secret key
    ReCaptchaSiteKey   string        // reCAPTCHA v2 site key  
    CSRFSecret         string        // CSRF token secret
    RateLimitEnabled   bool          // Enable/disable rate limiting
    MaxLoginAttempts   int           // Maximum login attempts before blocking
    MaxSignupAttempts  int           // Maximum signup attempts before blocking
    BlockDuration      time.Duration // Duration to block after max attempts
}
```

### TelemetryConfig in `internal/config/config.go`

```go
type TelemetryConfig struct {
    ServiceName    string  // Service name for telemetry
    ServiceVersion string  // Service version
    Environment    string  // Environment (dev, staging, prod)
    ExporterURL    string  // OTLP exporter endpoint
    InstanceID     string  // Grafana Cloud instance ID
    APIKey         string  // Grafana Cloud API key
    Enabled        bool    // Enable/disable telemetry
    SamplingRatio  float64 // Trace sampling ratio (0.0-1.0)
}
```

## Environment Variables

### Security Configuration

```bash
# reCAPTCHA Configuration (optional)
RECAPTCHA_SITE_KEY=your_site_key_here
RECAPTCHA_SECRET_KEY=your_secret_key_here

# Authentication & Security
JWT_SECRET=your-very-secure-jwt-secret-key-here
CSRF_SECRET=your-very-secure-csrf-secret-key-here
RATE_LIMIT_ENABLED=true
MAX_LOGIN_ATTEMPTS=5
MAX_SIGNUP_ATTEMPTS=3
BLOCK_DURATION=15m
PASSWORD_MIN_LENGTH=8
REQUIRE_EMAIL_VERIFICATION=true
```

### OpenTelemetry Configuration

```bash
# OpenTelemetry Configuration
OTEL_ENABLED=true
OTEL_SERVICE_NAME=askfrank
OTEL_SERVICE_VERSION=1.0.0
OTEL_SAMPLING_RATIO=0.1
OTEL_EXPORTER_OTLP_ENDPOINT=https://otlp-gateway-prod-eu-west-3.grafana.net/otlp
GRAFANA_CLOUD_INSTANCE_ID=your_instance_id
GRAFANA_CLOUD_API_KEY=your_api_key
```

## Security Features Implemented

### 1. Rate Limiting
- **Login Protection**: Maximum 5 attempts per IP before 15-minute block
- **Signup Protection**: Maximum 3 attempts per IP before 15-minute block
- **Configurable**: Can be enabled/disabled via `RATE_LIMIT_ENABLED`

### 2. CSRF Protection
- **Token-based**: Secure CSRF tokens for all forms
- **Configurable Secret**: Uses `CSRF_SECRET` environment variable
- **SameSite Cookies**: Enhanced cookie security

### 3. Password Security
- **Minimum Length**: Configurable via `PASSWORD_MIN_LENGTH` (default: 8)
- **Complexity Requirements**: Uppercase, lowercase, digits, special characters
- **Strength Validation**: Server-side password strength checking

### 4. reCAPTCHA Integration
- **Optional**: Can be enabled by setting reCAPTCHA keys
- **v2 Support**: Works with Google reCAPTCHA v2
- **Form Protection**: Protects signup and sensitive forms

### 5. Session Security
- **Secure Cookies**: HTTPOnly, Secure (in production), SameSite
- **Database Storage**: Sessions stored in PostgreSQL
- **Configurable Expiration**: Via `SESSION_EXPIRATION`

### 6. Input Sanitization
- **XSS Prevention**: Automatic HTML sanitization
- **SQL Injection Prevention**: Parameterized queries
- **Data Validation**: Comprehensive input validation

## OpenTelemetry Integration

### Features Implemented

#### 1. Distributed Tracing
- **OTLP HTTP Exporter**: Sends traces to Grafana Cloud
- **Automatic Instrumentation**: HTTP requests automatically traced
- **Custom Spans**: Easy creation of custom spans for business logic
- **Context Propagation**: Trace context propagated across service boundaries

#### 2. Telemetry Middleware
- **HTTP Tracing**: All HTTP requests automatically traced
- **Request Attributes**: Method, URL, route, user agent, IP address
- **Response Attributes**: Status code, response size
- **Error Tracking**: Automatic error recording and status setting

#### 3. Grafana Cloud Integration
- **OTLP Endpoint**: Configurable endpoint for Grafana Cloud
- **Authentication**: API key-based authentication
- **Instance ID**: Proper tenant isolation

### Usage Examples

#### Getting Trace Context in Handlers
```go
func (h *Handler) SomeHandler(c *fiber.Ctx) error {
    // Get the trace context
    ctx := telemetry.GetContextFromFiber(c)
    span := telemetry.GetSpanFromFiber(c)
    
    // Add custom attributes
    span.SetAttributes(
        attribute.String("user.id", userID),
        attribute.String("operation", "some_operation"),
    )
    
    // Create child span for business logic
    tracer := otel.Tracer("askfrank")
    _, childSpan := tracer.Start(ctx, "business_operation")
    defer childSpan.End()
    
    // Your business logic here...
    
    return c.JSON(response)
}
```

## Security Best Practices Implemented

### 1. Defense in Depth
- Multiple layers of security controls
- Rate limiting + CSRF + input validation + authentication

### 2. Principle of Least Privilege
- Minimal required permissions
- Secure defaults for all settings

### 3. Security Headers
- Content Security Policy ready (commented out until script issues resolved)
- Secure cookie settings
- XSS protection headers

### 4. Audit Trail
- Comprehensive logging with structured format
- OpenTelemetry tracing for request tracking
- Security event logging

### 5. Configuration Security
- Secrets via environment variables
- No hardcoded credentials
- Configurable security levels

## Monitoring and Observability

### 1. Application Metrics
- HTTP request metrics (duration, status codes, errors)
- Authentication metrics (login attempts, failures)
- Security metrics (rate limit hits, CSRF failures)

### 2. Distributed Tracing
- End-to-end request tracing
- Database query tracing
- External service call tracing

### 3. Structured Logging
- JSON formatted logs
- Trace correlation IDs
- Security event logging

### 4. Health Checks
- Application health endpoints
- Database connectivity checks
- External service dependency checks

## Production Deployment

### Environment-Specific Configuration

#### Development
```bash
ENVIRONMENT=development
OTEL_SAMPLING_RATIO=1.0  # 100% sampling for dev
RATE_LIMIT_ENABLED=false
```

#### Production
```bash
ENVIRONMENT=production
OTEL_SAMPLING_RATIO=0.01  # 1% sampling for prod
RATE_LIMIT_ENABLED=true
CSRF_SECRET=very-secure-production-secret
```

### Security Checklist

- [ ] All secrets stored in environment variables
- [ ] HTTPS enabled in production
- [ ] Database connections encrypted
- [ ] Rate limiting enabled
- [ ] CSRF protection enabled
- [ ] Password complexity enforced
- [ ] Session security configured
- [ ] OpenTelemetry configured for monitoring
- [ ] Security headers enabled
- [ ] Input validation in place

## Testing Security Configuration

The security configuration is tested through:

1. **Unit Tests**: Individual security functions tested
2. **Integration Tests**: End-to-end security flow testing
3. **Security Tests**: Rate limiting, CSRF, password validation tests

Run security tests:
```bash
make test
make test-integration
```

## Troubleshooting

### Common Issues

1. **Telemetry Not Working**
   - Check `OTEL_EXPORTER_OTLP_ENDPOINT` is set
   - Verify Grafana Cloud API key is valid
   - Ensure `OTEL_ENABLED=true`

2. **Rate Limiting Too Aggressive**
   - Adjust `MAX_LOGIN_ATTEMPTS` and `MAX_SIGNUP_ATTEMPTS`
   - Modify `BLOCK_DURATION` for shorter blocks

3. **CSRF Failures**
   - Ensure `CSRF_SECRET` is set and consistent
   - Check SameSite cookie settings

This comprehensive security configuration provides enterprise-grade security features while maintaining flexibility for different deployment environments.
