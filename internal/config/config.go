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
	Host         string
	Port         int
	User         string
	Password     string
	Name         string
	SSLMode      string
	MaxOpenConns int
	MaxIdleConns int
}

type StripeConfig struct {
	APIKey string
	// WebhookSecret string
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
			Host:         getEnv("DB_HOST", "localhost"),
			Port:         getEnvInt("DB_PORT", 5432),
			User:         getEnv("DB_USER", "postgres"),
			Password:     getEnv("DB_PASSWORD", "password"),
			Name:         getEnv("DB_NAME", "postgres"),
			SSLMode:      getEnv("DB_SSL_MODE", "disable"),
			MaxOpenConns: getEnvInt("DB_MAX_OPEN_CONNS", 10),
			MaxIdleConns: getEnvInt("DB_MAX_IDLE_CONNS", 5),
		},
		Stripe: StripeConfig{
			APIKey: getEnv("STRIPE_API_KEY", "sk_test_51S7Lsl00bAgI7KzUm7hXRKN0PJ3IRI6CIqEg2SXNaLpUW7p8wW1FGU0rz7I3RtnL0ntbEc27i3gTzHTolOyH2ahG00EaiIRpir"),
			// WebhookSecret: getEnv("STRIPE_WEBHOOK_SECRET", ""),
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
