package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	Stripe   StripeConfig
}

type Environment string

const (
	EnvironmentDevelopment Environment = "development"
	EnvironmentProduction  Environment = "production"
)

type ServerConfig struct {
	Host         string
	Port         string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	Environment  Environment
}

type ContextKey string

const (
	SessionContextKey   ContextKey = "session_id"
	LanguageContextKey  ContextKey = "lang"
	UserIDContextKey    ContextKey = "user_id"
	CSRFTokenContextKey ContextKey = "csrf_token"
)

type DatabaseConfig struct {
	URL string
}

type StripeConfig struct {
	APIKey        string
	WebhookSecret string
}

func NewConfig() Config {
	return Config{
		Server: ServerConfig{
			Host:         getEnv("SERVER_HOST", "localhost"),
			Port:         getEnv("SERVER_PORT", "3001"),
			ReadTimeout:  getEnvDuration("SERVER_READ_TIMEOUT", 10*time.Second),
			WriteTimeout: getEnvDuration("SERVER_WRITE_TIMEOUT", 10*time.Second),
			Environment:  getEnvEnvironment("SERVER_ENVIRONMENT", EnvironmentDevelopment),
		},
		Database: DatabaseConfig{
			URL: getEnv("DATABASE_URL", ""),
		},
		Stripe: StripeConfig{
			APIKey:        getEnv("STRIPE_API_KEY", ""),
			WebhookSecret: getEnv("STRIPE_WEBHOOK_SECRET", ""),
		},
	}
}

func getEnv(key string, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}

	if defaultValue == "" {
		panic("Missing required environment variable: " + key)
	}

	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value, exists := os.LookupEnv(key); exists {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value, exists := os.LookupEnv(key); exists {
		if durationValue, err := time.ParseDuration(value); err == nil {
			return durationValue
		}
	}
	return defaultValue
}

func getEnvEnvironment(key string, defaultValue Environment) Environment {
	if value, exists := os.LookupEnv(key); exists {
		return Environment(value)
	}
	return defaultValue
}
