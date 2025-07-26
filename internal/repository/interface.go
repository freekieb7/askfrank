package repository

import (
	"askfrank/internal/model"

	"github.com/google/uuid"
)

// RepositoryInterface defines the contract for repository implementations
type RepositoryInterface interface {
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

	// Database operations
	Migrate() error
}
