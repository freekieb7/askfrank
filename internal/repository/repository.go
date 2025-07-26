package repository

import (
	"askfrank/internal/database"
	"askfrank/internal/model"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
)

var (
	ErrUserNotFound             = errors.New("user not found")
	ErrUserRegistrationNotFound = errors.New("user registration not found")
)

type Repository struct {
	db database.Database
}

func NewRepository(db database.Database) *Repository {
	return &Repository{db: db}
}

func (r *Repository) Migrate() error {
	_, err := r.db.Exec(`
	CREATE TABLE IF NOT EXISTS tbl_user (
		id UUID PRIMARY KEY,
		name VARCHAR(100) NOT NULL,
		email VARCHAR(100) NOT NULL UNIQUE,
		password_hash VARCHAR(255) NOT NULL,
		email_verified BOOLEAN NOT NULL,
		created_at TIMESTAMP NOT NULL
	);`)
	if err != nil {
		return fmt.Errorf("failed to migrate database: %w", err)
	}

	_, err = r.db.Exec(`
	CREATE TABLE IF NOT EXISTS tbl_user_registration (
		id UUID PRIMARY KEY,
		user_id UUID NOT NULL REFERENCES tbl_user(id),
		activation_code VARCHAR(255) NOT NULL
	);`)
	if err != nil {
		return fmt.Errorf("failed to migrate database: %w", err)
	}

	// Create sessions table for storing session data
	_, err = r.db.Exec(`
	CREATE TABLE IF NOT EXISTS sessions (
		k VARCHAR(255) PRIMARY KEY,
		v BYTEA,
		e BIGINT
	);`)
	if err != nil {
		return fmt.Errorf("failed to create sessions table: %w", err)
	}

	slog.Info("Database migration completed")
	return nil
}

func (r *Repository) CreateUser(user model.User) error {
	_, err := r.db.Exec("INSERT INTO tbl_user (id, name, email, password_hash, email_verified, created_at) VALUES ($1, $2, $3, $4, $5, $6)",
		user.ID, user.Name, user.Email, user.PasswordHash, user.EmailVerified, user.CreatedAt)
	if err != nil {
		return err
	}
	return nil
}

func (r *Repository) GetUserByID(id uuid.UUID) (model.User, error) {
	var user model.User
	err := r.db.QueryRow("SELECT id, name, email, password_hash, email_verified, created_at FROM tbl_user WHERE id = $1", id).Scan(&user.ID, &user.Name, &user.Email, &user.PasswordHash, &user.EmailVerified, &user.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.User{}, ErrUserNotFound
		}
		return model.User{}, err
	}
	return user, nil
}

func (r *Repository) GetUserByEmail(email string) (model.User, error) {
	var user model.User
	err := r.db.QueryRow("SELECT id, name, email, password_hash, email_verified, created_at FROM tbl_user WHERE email = $1", email).Scan(&user.ID, &user.Name, &user.Email, &user.PasswordHash, &user.EmailVerified, &user.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.User{}, ErrUserNotFound
		}
		return model.User{}, err
	}
	return user, nil
}

func (r *Repository) UpdateUser(user model.User) error {
	_, err := r.db.Exec("UPDATE tbl_user SET name = $1, email = $2, password_hash = $3, email_verified = $4 WHERE id = $5",
		user.Name, user.Email, user.PasswordHash, user.EmailVerified, user.ID)
	if err != nil {
		return err
	}
	return nil
}

func (r *Repository) CreateUserRegistration(userRegistration model.UserRegistration) error {
	_, err := r.db.Exec("INSERT INTO tbl_user_registration (id, user_id, activation_code) VALUES ($1, $2, $3)",
		userRegistration.ID, userRegistration.UserID, userRegistration.ActivationCode)
	if err != nil {
		return err
	}
	return nil
}

func (r *Repository) GetUserRegistrationByUserID(userID uuid.UUID) (model.UserRegistration, error) {
	var userRegistration model.UserRegistration
	err := r.db.QueryRow("SELECT id, user_id, activation_code FROM tbl_user_registration WHERE user_id = $1", userID).Scan(&userRegistration.ID, &userRegistration.UserID, &userRegistration.ActivationCode)
	if err != nil {
		return model.UserRegistration{}, err
	}
	return userRegistration, nil
}

func (r *Repository) GetUserRegistrationByEmail(email string) (model.UserRegistration, error) {
	var userRegistration model.UserRegistration
	err := r.db.QueryRow("SELECT id, user_id, activation_code FROM tbl_user_registration WHERE email = $1", email).Scan(&userRegistration.ID, &userRegistration.UserID, &userRegistration.ActivationCode)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.UserRegistration{}, ErrUserRegistrationNotFound
		}
		return model.UserRegistration{}, err
	}
	return userRegistration, nil
}

func (r *Repository) DeleteUserRegistration(id uuid.UUID) error {
	_, err := r.db.Exec("DELETE FROM tbl_user_registration WHERE id = $1", id)
	if err != nil {
		return err
	}
	return nil
}
