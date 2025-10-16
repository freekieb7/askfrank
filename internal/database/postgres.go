package database

import (
	"context"
	"fmt"
	"hp/internal/util"
	"time"

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

type Options struct {
	PoolMaxConns              util.Optional[int32]
	PoolMinConns              util.Optional[int32]
	PoolMaxConnLifetime       util.Optional[time.Duration]
	PoolMaxConnIdleTime       util.Optional[time.Duration]
	PoolHealthCheckPeriod     util.Optional[time.Duration]
	PoolMaxConnLifetimeJitter util.Optional[time.Duration]
}

func (db *Postgres) Connect(url string, options Options) error {
	// Construct the connection string
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		// Handle error
		return fmt.Errorf("unable to parse database configuration: %w", err)
	}

	if options.PoolMaxConns.Some {
		config.MaxConns = options.PoolMaxConns.Data
	}
	if options.PoolMinConns.Some {
		config.MinConns = options.PoolMinConns.Data
	}
	if options.PoolMaxConnLifetime.Some {
		config.MaxConnLifetime = options.PoolMaxConnLifetime.Data
	}
	if options.PoolMaxConnIdleTime.Some {
		config.MaxConnIdleTime = options.PoolMaxConnIdleTime.Data
	}
	if options.PoolHealthCheckPeriod.Some {
		config.HealthCheckPeriod = options.PoolHealthCheckPeriod.Data
	}
	if options.PoolMaxConnLifetimeJitter.Some {
		config.MaxConnLifetimeJitter = options.PoolMaxConnLifetimeJitter.Data
	}

	// Create the connection pool
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
