package database

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"
)

type Database struct {
	*sql.DB
}

func NewPostgresDatabase(dataSourceName string) (Database, error) {
	db, err := sql.Open("postgres", dataSourceName)
	if err != nil {
		return Database{}, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Configure connection pool for better stability
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(time.Hour)
	db.SetConnMaxIdleTime(time.Minute * 10)

	// Test the connection with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		if err := db.Close(); err != nil {
			return Database{}, fmt.Errorf("failed to close database: %w", err)
		}
		return Database{}, fmt.Errorf("failed to ping database: %w", err)
	}

	slog.Info("Connected to database successfully")
	return Database{DB: db}, nil
}
