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
	Migrate(ctx context.Context) error
	HealthCheck(ctx context.Context) error

	// Folder operations
	CreateFolder(folder model.Folder) error
	GetFolderByID(id uuid.UUID) (model.Folder, error)
	UpdateFolder(folder model.Folder) error
	DeleteFolder(id uuid.UUID) error
	GetFoldersByOwnerID(ownerID uuid.UUID) ([]model.Folder, error)

	// Document operations
	CreateDocument(document model.Document) error
	GetDocumentByID(id uuid.UUID) (model.Document, error)
	UpdateDocument(document model.Document) error
	DeleteDocument(id uuid.UUID) error
	GetDocumentsByFolderID(folderID uuid.UUID) ([]model.Document, error)
	GetDocumentsByOwnerID(ownerID uuid.UUID) ([]model.Document, error)

	// Audit operations
	LogAudit(ctx context.Context, log model.AuditLog) error
	GetAuditLogs(ctx context.Context, filters model.AuditFilters) ([]model.AuditLog, error)
	GetAuditLogsCount(ctx context.Context, filters model.AuditFilters) (int, error)
}
