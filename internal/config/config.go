package config

import (
	"os"
	"strconv"
	"time"

	"askfrank/internal/storage"
)

type Config struct {
	Server    ServerConfig
	Database  DatabaseConfig
	Auth      AuthConfig
	Email     EmailConfig
	Security  SecurityConfig
	Storage   storage.StorageConfig
	Stripe    StripeConfig
	Telemetry TelemetryConfig
	OpenFGA   OpenFGAConfig
}

type ServerConfig struct {
	Port         string
	Host         string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	Environment  string
}

type DatabaseConfig struct {
	Host         string
	Port         int
	User         string
	Password     string
	Name         string
	SSLMode      string
	MaxOpenConns int
	MaxIdleConns int
}

type AuthConfig struct {
	JWTSecret           string
	JWTExpiration       time.Duration
	RefreshExpiration   time.Duration
	SessionExpiration   time.Duration
	PasswordMinLength   int
	RequireVerification bool
}

type EmailConfig struct {
	SMTPHost     string
	SMTPPort     int
	SMTPUser     string
	SMTPPassword string
	FromAddress  string
	FromName     string
}

type SecurityConfig struct {
	ReCaptchaSecretKey string
	ReCaptchaSiteKey   string
	CSRFSecret         string
	RateLimitEnabled   bool
	MaxLoginAttempts   int
	MaxSignupAttempts  int
	BlockDuration      time.Duration
}

type StripeConfig struct {
	SecretKey      string
	PublishableKey string
	WebhookSecret  string
	Environment    string
}

type TelemetryConfig struct {
	ServiceName    string
	ServiceVersion string
	Environment    string
	ExporterURL    string
	InstanceID     string
	APIKey         string
	Enabled        bool
	SamplingRatio  float64
}

type OpenFGAConfig struct {
	APIHost     string
	StoreID     string
	ModelID     string
	APIToken    string
	Enabled     bool
	Environment string
}

func Load() (*Config, error) {
	cfg := &Config{
		Server: ServerConfig{
			Port:         getEnv("PORT", "8080"),
			Host:         getEnv("HOST", "localhost"),
			ReadTimeout:  parseDurationEnv("READ_TIMEOUT", "10s"),
			WriteTimeout: parseDurationEnv("WRITE_TIMEOUT", "10s"),
			Environment:  getEnv("ENVIRONMENT", "development"),
		},
		Database: DatabaseConfig{
			Host:         getEnv("DB_HOST", "localhost"),
			Port:         parseIntEnv("DB_PORT", 5432),
			User:         getEnv("DB_USER", "postgres"),
			Password:     getEnv("DB_PASSWORD", "postgres"),
			Name:         getEnv("DB_NAME", "postgres"),
			SSLMode:      getEnv("DB_SSL_MODE", "disable"),
			MaxOpenConns: parseIntEnv("DB_MAX_OPEN_CONNS", 25),
			MaxIdleConns: parseIntEnv("DB_MAX_IDLE_CONNS", 5),
		},
		Auth: AuthConfig{
			JWTSecret:           getEnv("JWT_SECRET", "your-jwt-secret-key"),
			JWTExpiration:       parseDurationEnv("JWT_EXPIRATION", "24h"),
			RefreshExpiration:   parseDurationEnv("REFRESH_EXPIRATION", "168h"), // 7 days
			SessionExpiration:   parseDurationEnv("SESSION_EXPIRATION", "24h"),
			PasswordMinLength:   parseIntEnv("PASSWORD_MIN_LENGTH", 8),
			RequireVerification: parseBoolEnv("REQUIRE_EMAIL_VERIFICATION", true),
		},
		Email: EmailConfig{
			SMTPHost:     getEnv("SMTP_HOST", ""),
			SMTPPort:     parseIntEnv("SMTP_PORT", 587),
			SMTPUser:     getEnv("SMTP_USER", ""),
			SMTPPassword: getEnv("SMTP_PASSWORD", ""),
			FromAddress:  getEnv("FROM_ADDRESS", "noreply@askfrank.com"),
			FromName:     getEnv("FROM_NAME", "AskFrank"),
		},
		Security: SecurityConfig{
			ReCaptchaSecretKey: getEnv("RECAPTCHA_SECRET_KEY", ""),
			ReCaptchaSiteKey:   getEnv("RECAPTCHA_SITE_KEY", ""),
			CSRFSecret:         getEnv("CSRF_SECRET", "your-csrf-secret-key"),
			RateLimitEnabled:   parseBoolEnv("RATE_LIMIT_ENABLED", true),
			MaxLoginAttempts:   parseIntEnv("MAX_LOGIN_ATTEMPTS", 5),
			MaxSignupAttempts:  parseIntEnv("MAX_SIGNUP_ATTEMPTS", 3),
			BlockDuration:      parseDurationEnv("BLOCK_DURATION", "15m"),
		},
		Storage: loadStorageConfig(),
		Stripe: StripeConfig{
			SecretKey:      getEnv("STRIPE_SECRET_KEY", ""),
			PublishableKey: getEnv("STRIPE_PUBLISHABLE_KEY", ""),
			WebhookSecret:  getEnv("STRIPE_WEBHOOK_SECRET", ""),
			Environment:    getEnv("STRIPE_ENVIRONMENT", "test"),
		},
		Telemetry: TelemetryConfig{
			ServiceName:    getEnv("OTEL_SERVICE_NAME", "askfrank"),
			ServiceVersion: getEnv("OTEL_SERVICE_VERSION", "1.0.0"),
			Environment:    getEnv("ENVIRONMENT", "development"),
			ExporterURL:    getEnv("OTEL_EXPORTER_OTLP_ENDPOINT", ""),
			InstanceID:     getEnv("GRAFANA_CLOUD_INSTANCE_ID", ""),
			APIKey:         getEnv("GRAFANA_CLOUD_API_KEY", ""),
			Enabled:        parseBoolEnv("OTEL_ENABLED", true),
			SamplingRatio:  parseFloatEnv("OTEL_SAMPLING_RATIO", 0.1),
		},
		OpenFGA: OpenFGAConfig{
			APIHost:     getEnv("OPENFGA_API_HOST", "localhost:8080"),
			StoreID:     getEnv("OPENFGA_STORE_ID", ""),
			ModelID:     getEnv("OPENFGA_MODEL_ID", ""),
			APIToken:    getEnv("OPENFGA_API_TOKEN", ""),
			Enabled:     parseBoolEnv("OPENFGA_ENABLED", false),
			Environment: getEnv("OPENFGA_ENVIRONMENT", "development"),
		},
	}

	return cfg, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func parseIntEnv(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

func parseBoolEnv(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

func parseDurationEnv(key string, defaultValue string) time.Duration {
	if value := os.Getenv(key); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil {
			return parsed
		}
	}
	if parsed, err := time.ParseDuration(defaultValue); err == nil {
		return parsed
	}
	return time.Minute
}

func parseFloatEnv(key string, defaultValue float64) float64 {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseFloat(value, 64); err == nil {
			return parsed
		}
	}
	return defaultValue
}

func loadStorageConfig() storage.StorageConfig {
	storageType := getEnv("STORAGE_TYPE", "local")

	config := storage.StorageConfig{
		Type:      storage.StorageType(storageType),
		LocalPath: getEnv("STORAGE_LOCAL_PATH", "./uploads"),
	}

	if storageType == "s3" {
		config.S3 = &storage.S3Config{
			Bucket: getEnv("STORAGE_S3_BUCKET", ""),
			Region: getEnv("STORAGE_S3_REGION", ""),
		}
	}

	return config
}
