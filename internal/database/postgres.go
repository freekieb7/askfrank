package database

import (
	"context"
	"errors"
	"hp/internal/config"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresDatabase struct {
	*pgxpool.Pool
}

func NewDatabase(cfg config.DatabaseConfig) *PostgresDatabase {
	// Construct the connection string
	dsn := "host=" + cfg.Host +
		" port=" + strconv.Itoa(cfg.Port) +
		" user=" + cfg.User +
		" password=" + cfg.Password +
		" dbname=" + cfg.Name +
		" sslmode=" + cfg.SSLMode

	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		// Handle error
		panic("Unable to parse database configuration: " + err.Error())
	}

	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		// Handle error
		panic("Unable to connect to database: " + err.Error())
	}

	// Set the connection pool to be used by the PostgresDatabase
	if err := pool.Ping(context.Background()); err != nil {
		// Handle error
		panic("Unable to ping database: " + err.Error())
	}

	return &PostgresDatabase{
		pool,
	}
}

func (db *PostgresDatabase) Close() {
	if db.Pool != nil {
		db.Pool.Close()
	}
}

var (
	ErrUserNotFound = errors.New("User not found")
)

type User struct {
	ID              uuid.UUID
	Name            string
	Email           string
	PasswordHash    []byte
	IsEmailVerified bool
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

func (db *PostgresDatabase) CreateUser(ctx context.Context, user User) error {
	if _, err := db.Exec(ctx, `INSERT INTO tbl_user (id, name, email, password_hash, is_email_verified, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		user.ID, user.Name, user.Email, user.PasswordHash, user.IsEmailVerified, user.CreatedAt, user.UpdatedAt); err != nil {
		// Handle error
		return err
	}
	return nil
}

func (db *PostgresDatabase) GetUserByID(ctx context.Context, id uuid.UUID) (User, error) {
	var user User
	err := db.QueryRow(ctx, `SELECT id, name, email, password_hash, is_email_verified, created_at, updated_at FROM tbl_user WHERE id = $1`, id).Scan(
		&user.ID, &user.Name, &user.Email, &user.PasswordHash, &user.IsEmailVerified, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return user, ErrUserNotFound
		}
		return user, err
	}
	return user, nil
}

func (db *PostgresDatabase) GetUserByEmail(ctx context.Context, email string) (User, error) {
	var user User
	err := db.QueryRow(ctx, `SELECT id, name, email, password_hash, is_email_verified, created_at, updated_at FROM tbl_user WHERE email = $1`, email).Scan(
		&user.ID, &user.Name, &user.Email, &user.PasswordHash, &user.IsEmailVerified, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return user, ErrUserNotFound
		}
		return user, err
	}
	return user, nil
}
