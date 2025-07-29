# OpenTelemetry Metrics Implementation for AskFrank

## Overview

This implementation adds OpenTelemetry metrics support to AskFrank, specifically tracking user registrations. The metrics are sent to Grafana Alloy for collection and can be exported to Prometheus for monitoring.

## Components Added

### 1. Enhanced Telemetry Service (`internal/telemetry/telemetry.go`)
- Added OpenTelemetry metrics support alongside existing tracing and logging
- Added `userRegistrations` counter metric
- Added OTLP metric exporter for sending metrics to Alloy
- Added `RecordUserRegistration()` method to track registration events

### 2. Updated API Handler (`internal/api/app.go`)
- Added telemetry interface to Handler struct
- Modified `CreateUser()` method to record registration metrics
- Records both successful and failed registration attempts

### 3. Configuration
- Uses existing telemetry configuration
- Metrics are enabled when `OTEL_ENABLED=true`
- Exports metrics every 10 seconds to configured endpoint

## Metric Details

### `askfrank_user_registrations_total`
- **Type**: Counter
- **Description**: Total number of user registrations
- **Labels**:
  - `domain`: Email domain of the registered user
  - `success`: Whether the registration was successful (true/false)
  - `service`: Always "askfrank"

## Testing the Implementation

### Prerequisites
1. **Grafana Alloy** running on port 4317 (OTLP endpoint)
2. **PostgreSQL** database configured
3. **AskFrank** application built

### Setup Instructions

1. **Start Grafana Alloy** with the provided configuration:
   ```bash
   alloy run alloy-config.alloy
   ```

2. **Start AskFrank** with telemetry enabled:
   ```bash
   ./run-with-metrics.sh
   ```

3. **Generate test registrations** by visiting:
   ```
   http://localhost:8080/auth/sign-up/create-user
   ```

### Verifying Metrics

1. **Check Alloy Prometheus endpoint**:
   ```bash
   curl http://127.0.0.1:9464/metrics | grep askfrank_user_registrations
   ```

2. **Expected output**:
   ```
   # HELP askfrank_user_registrations_total Total number of user registrations
   # TYPE askfrank_user_registrations_total counter
   askfrank_user_registrations_total{domain="example.com",service="askfrank",success="true"} 1
   ```

## Environment Variables

```bash
# Enable telemetry
OTEL_ENABLED=true

# Alloy endpoint (default for local testing)
OTEL_EXPORTER_OTLP_ENDPOINT=127.0.0.1:4317

# Service identification
OTEL_SERVICE_NAME=askfrank
OTEL_SERVICE_VERSION=1.0.0
ENVIRONMENT=development

# Sampling (set to 1.0 for testing to capture all events)
OTEL_SAMPLING_RATIO=1.0
```

## Architecture

```
AskFrank App
    ↓ (OTLP/gRPC)
Grafana Alloy
    ↓ (Prometheus format)
Prometheus/Grafana
```

## Next Steps

To extend this implementation:

1. **Add more metrics**:
   - HTTP request metrics
   - Authentication attempt metrics
   - Database connection metrics

2. **Add metric middleware**:
   - HTTP request duration
   - Request count by endpoint
   - Response status codes

3. **Enhanced monitoring**:
   - Set up Grafana dashboards
   - Configure alerting rules
   - Add metric retention policies

## Security Considerations

- Email addresses are not stored in metrics (only domains)
- Metrics include success/failure status for monitoring security events
- No sensitive data is exposed in metric labels
