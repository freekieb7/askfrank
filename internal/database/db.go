package database

import (
	"database/sql"
	"fmt"
	"log/slog"
)

type Database struct {
	*sql.DB
}

func NewDatabase(dataSourceName string) (Database, error) {
	db, err := sql.Open("postgres", dataSourceName)
	if err != nil {
		return Database{}, fmt.Errorf("failed to connect to database: %w", err)
	}
	if err := db.Ping(); err != nil {
		return Database{}, fmt.Errorf("failed to ping database: %w", err)
	}
	slog.Info("Connected to database successfully")
	return Database{DB: db}, nil
}
