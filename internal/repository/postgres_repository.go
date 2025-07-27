package repository

import (
	"askfrank/internal/database"
	"askfrank/internal/model"
	"context"
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

type DatabaseRepository struct {
	db database.Database
}

func NewDatabaseRepository(db database.Database) *DatabaseRepository {
	return &DatabaseRepository{db: db}
}

func (r *DatabaseRepository) Migrate() error {
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
		activation_code VARCHAR(255) NOT NULL,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	);`)
	if err != nil {
		return fmt.Errorf("failed to migrate database: %w", err)
	}

	// Add created_at column to existing user_registration tables
	_, err = r.db.Exec(`
	ALTER TABLE tbl_user_registration 
	ADD COLUMN IF NOT EXISTS created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP;`)
	if err != nil {
		return fmt.Errorf("failed to add created_at column to user_registration: %w", err)
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

func (r *DatabaseRepository) CreateUser(user model.User) error {
	_, err := r.db.Exec("INSERT INTO tbl_user (id, name, email, password_hash, email_verified, created_at) VALUES ($1, $2, $3, $4, $5, $6)",
		user.ID, user.Name, user.Email, user.PasswordHash, user.EmailVerified, user.CreatedAt)
	if err != nil {
		return err
	}
	return nil
}

func (r *DatabaseRepository) GetUserByID(id uuid.UUID) (model.User, error) {
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

func (r *DatabaseRepository) GetUserByEmail(email string) (model.User, error) {
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

func (r *DatabaseRepository) UpdateUser(user model.User) error {
	_, err := r.db.Exec("UPDATE tbl_user SET name = $1, email = $2, password_hash = $3, email_verified = $4 WHERE id = $5",
		user.Name, user.Email, user.PasswordHash, user.EmailVerified, user.ID)
	if err != nil {
		return err
	}
	return nil
}

func (r *DatabaseRepository) CreateUserRegistration(userRegistration model.UserRegistration) error {
	_, err := r.db.Exec("INSERT INTO tbl_user_registration (id, user_id, activation_code, created_at) VALUES ($1, $2, $3, $4)",
		userRegistration.ID, userRegistration.UserID, userRegistration.ActivationCode, userRegistration.CreatedAt)
	if err != nil {
		return err
	}
	return nil
}

func (r *DatabaseRepository) GetUserRegistrationByUserID(userID uuid.UUID) (model.UserRegistration, error) {
	var userRegistration model.UserRegistration
	err := r.db.QueryRow("SELECT id, user_id, activation_code, created_at FROM tbl_user_registration WHERE user_id = $1", userID).Scan(&userRegistration.ID, &userRegistration.UserID, &userRegistration.ActivationCode, &userRegistration.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.UserRegistration{}, ErrUserRegistrationNotFound
		}
		return model.UserRegistration{}, err
	}
	return userRegistration, nil
}

func (r *DatabaseRepository) GetUserRegistrationByEmail(email string) (model.UserRegistration, error) {
	var userRegistration model.UserRegistration
	query := `
		SELECT ur.id, ur.user_id, ur.activation_code, ur.created_at 
		FROM tbl_user_registration ur 
		JOIN tbl_user u ON ur.user_id = u.id 
		WHERE u.email = $1
	`
	err := r.db.QueryRow(query, email).Scan(&userRegistration.ID, &userRegistration.UserID, &userRegistration.ActivationCode, &userRegistration.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.UserRegistration{}, ErrUserRegistrationNotFound
		}
		return model.UserRegistration{}, err
	}
	return userRegistration, nil
}

func (r *DatabaseRepository) DeleteUserRegistration(id uuid.UUID) error {
	_, err := r.db.Exec("DELETE FROM tbl_user_registration WHERE id = $1", id)
	if err != nil {
		return err
	}
	return nil
}

func (r *DatabaseRepository) GetUserStats() (model.AdminStats, error) {
	var stats model.AdminStats

	// Get total users count
	err := r.db.QueryRow("SELECT COUNT(*) FROM tbl_user").Scan(&stats.TotalUsers)
	if err != nil {
		return model.AdminStats{}, err
	}

	// Get active users count (users who have been verified)
	err = r.db.QueryRow("SELECT COUNT(*) FROM tbl_user WHERE email_verified = true").Scan(&stats.ActiveUsers)
	if err != nil {
		return model.AdminStats{}, err
	}

	// Get pending registrations count
	err = r.db.QueryRow("SELECT COUNT(*) FROM tbl_user_registration").Scan(&stats.PendingRegistrations)
	if err != nil {
		return model.AdminStats{}, err
	}

	// Get users registered today
	err = r.db.QueryRow("SELECT COUNT(*) FROM tbl_user WHERE DATE(created_at) = CURRENT_DATE").Scan(&stats.TodayRegistrations)
	if err != nil {
		return model.AdminStats{}, err
	}

	return stats, nil
}

func (r *DatabaseRepository) GetAllUsers(limit, offset int) ([]model.UserWithRegistration, int, error) {
	var users []model.UserWithRegistration
	var totalCount int

	// Get total count first
	err := r.db.QueryRow("SELECT COUNT(*) FROM tbl_user").Scan(&totalCount)
	if err != nil {
		return nil, 0, err
	}

	// Get users with optional registration info
	query := `
		SELECT 
			u.id, u.name, u.email, u.email_verified, u.created_at,
			ur.id, ur.activation_code, ur.created_at
		FROM tbl_user u
		LEFT JOIN tbl_user_registration ur ON u.id = ur.user_id
		ORDER BY u.created_at DESC
		LIMIT $1 OFFSET $2`

	rows, err := r.db.Query(query, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer func() {
		if err := rows.Close(); err != nil {
			slog.Error("failed to close rows", "error", err)
		}
	}()

	for rows.Next() {
		var user model.UserWithRegistration
		var regID, regActivationCode sql.NullString
		var regCreatedAt sql.NullTime

		err := rows.Scan(
			&user.User.ID, &user.User.Name, &user.User.Email,
			&user.User.EmailVerified, &user.User.CreatedAt,
			&regID, &regActivationCode, &regCreatedAt,
		)
		if err != nil {
			return nil, 0, err
		}

		// Set consistent fields
		user.User.IsEmailVerified = user.User.EmailVerified
		user.User.Role = "user"                   // Default role since we don't have role column
		user.User.UpdatedAt = user.User.CreatedAt // Use created_at as fallback

		// Set registration info if exists
		if regID.Valid {
			regUUID, err := uuid.Parse(regID.String)
			if err != nil {
				return nil, 0, err
			}
			user.Registration = &model.UserRegistration{
				ID:             regUUID,
				UserID:         user.User.ID,
				ActivationCode: regActivationCode.String,
				CreatedAt:      regCreatedAt.Time,
			}
		}

		users = append(users, user)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, err
	}

	return users, totalCount, nil
}

// ActivateUser activates a user by setting email_verified to true and removing any pending registration
func (r *DatabaseRepository) ActivateUser(userID uuid.UUID) error {
	tx, err := r.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil {
			slog.Error("failed to rollback transaction", "error", err)
		}
	}()

	// Update user to set email_verified = true
	_, err = tx.Exec("UPDATE tbl_user SET email_verified = true WHERE id = $1", userID)
	if err != nil {
		return fmt.Errorf("failed to activate user: %w", err)
	}

	// Delete any pending registration for this user
	_, err = tx.Exec("DELETE FROM tbl_user_registration WHERE user_id = $1", userID)
	if err != nil {
		return fmt.Errorf("failed to delete user registration: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// DeleteUser deletes a user and all associated data
func (r *DatabaseRepository) DeleteUser(userID uuid.UUID) error {
	tx, err := r.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil {
			slog.Error("failed to rollback transaction", "error", err)
		}
	}()

	// Delete any user registrations first (foreign key constraint)
	_, err = tx.Exec("DELETE FROM tbl_user_registration WHERE user_id = $1", userID)
	if err != nil {
		return fmt.Errorf("failed to delete user registrations: %w", err)
	}

	// Delete the user
	result, err := tx.Exec("DELETE FROM tbl_user WHERE id = $1", userID)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return ErrUserNotFound
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// GetUserByIDForAdmin gets a user by ID for admin operations (includes all fields)
func (r *DatabaseRepository) GetUserByIDForAdmin(userID uuid.UUID) (model.User, error) {
	var user model.User
	query := `
		SELECT id, name, email, password_hash, email_verified, created_at
		FROM tbl_user 
		WHERE id = $1
	`
	err := r.db.QueryRow(query, userID).Scan(
		&user.ID, &user.Name, &user.Email, &user.PasswordHash,
		&user.EmailVerified, &user.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.User{}, ErrUserNotFound
		}
		return model.User{}, err
	}

	// Set consistent fields
	user.IsEmailVerified = user.EmailVerified
	user.Role = "user"              // Default role since we don't have role column
	user.UpdatedAt = user.CreatedAt // Use created_at as fallback

	return user, nil
}

// HealthCheck performs a simple health check on the database connection
func (r *DatabaseRepository) HealthCheck(ctx context.Context) error {
	return r.db.PingContext(ctx)
}
