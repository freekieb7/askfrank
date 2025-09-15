package database

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Postgres struct {
	*pgxpool.Pool
}

func NewPostgres() Postgres {
	return Postgres{
		Pool: nil,
	}
}

func (db *Postgres) Connect(dsn string) error {
	// Construct the connection string
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		// Handle error
		return fmt.Errorf("unable to parse database configuration: %w", err)
	}

	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		// Handle error
		return fmt.Errorf("unable to connect to database: %w", err)
	}
	// Set the connection pool to be used by the Postgres
	if err := pool.Ping(context.Background()); err != nil {
		// Handle error
		return fmt.Errorf("unable to ping database: %w", err)
	}

	db.Pool = pool
	return nil
}

func (db *Postgres) Close() {
	if db.Pool != nil {
		db.Pool.Close()
	}
}
