package database

import (
	"database/sql"
	"hp/internal/config"
	"strconv"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver
)

type PostgresDatabase struct {
	*sql.DB
}

func NewDatabase(cfg config.DatabaseConfig) *PostgresDatabase {
	// Construct the connection string
	connectionString := "host=" + cfg.Host +
		" port=" + strconv.Itoa(cfg.Port) +
		" user=" + cfg.User +
		" password=" + cfg.Password +
		" dbname=" + cfg.Name +
		" sslmode=" + cfg.SSLMode
	db, err := sql.Open("postgres", connectionString)
	if err != nil {
		panic(err)
	}

	// Set connection pool settings
	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(time.Hour)
	db.SetConnMaxIdleTime(time.Minute * 10)

	return &PostgresDatabase{
		DB: db,
	}
}
