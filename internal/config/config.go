package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	OpenFGA  OpenFGAConfig
}

type ServerConfig struct {
	Host         string
	Port         string
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

type OpenFGAConfig struct {
	APIURL               string
	APIToken             string
	StoreID              string
	AuthorizationModelID string
}

func NewConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Host:         getEnv("SERVER_HOST", "localhost"),
			Port:         getEnv("SERVER_PORT", "3001"),
			ReadTimeout:  getEnvDuration("SERVER_READ_TIMEOUT", 10*time.Second),
			WriteTimeout: getEnvDuration("SERVER_WRITE_TIMEOUT", 10*time.Second),
			Environment:  getEnv("SERVER_ENVIRONMENT", "development"),
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
		OpenFGA: OpenFGAConfig{
			APIURL:               getEnv("OPENFGA_API_URL", "http://localhost:8080"),
			APIToken:             getEnv("OPENFGA_API_TOKEN", ""),
			StoreID:              getEnv("OPENFGA_STORE_ID", "01K332MA3TGDVDAPSSSKJKCKGB"),
			AuthorizationModelID: getEnv("OPENFGA_AUTHORIZATION_MODEL_ID", "01K38HA7G4M0JVJB5PZ6VDH589"),
		},
	}
}

func getEnv(key string, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
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
