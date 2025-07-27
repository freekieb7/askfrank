package repository

import (
	"askfrank/internal/model"
	"context"

	"github.com/google/uuid"
)

// RepositoryInterface defines the contract for repository implementations
type Repository interface {
	// User operations
	CreateUser(user model.User) error
	GetUserByID(id uuid.UUID) (model.User, error)
	GetUserByEmail(email string) (model.User, error)
	UpdateUser(user model.User) error

	// User registration operations
	CreateUserRegistration(userRegistration model.UserRegistration) error
	GetUserRegistrationByUserID(userID uuid.UUID) (model.UserRegistration, error)
	GetUserRegistrationByEmail(email string) (model.UserRegistration, error)
	DeleteUserRegistration(id uuid.UUID) error

	// Admin operations
	GetUserStats() (model.AdminStats, error)
	GetAllUsers(limit, offset int) ([]model.UserWithRegistration, int, error)
	ActivateUser(userID uuid.UUID) error
	DeleteUser(userID uuid.UUID) error
	GetUserByIDForAdmin(userID uuid.UUID) (model.User, error)

	// Database operations
	Migrate() error
	HealthCheck(ctx context.Context) error
}
