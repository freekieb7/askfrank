package repository

import (
	"askfrank/internal/database"
	"askfrank/internal/model"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

var (
	ErrUserNotFound             = errors.New("user not found")
	ErrUserRegistrationNotFound = errors.New("user registration not found")
	ErrFolderNotFound           = errors.New("folder not found")
	ErrUserAlreadyExists        = errors.New("user already exists")
	ErrDocumentNotFound         = errors.New("document not found")
	ErrFolderAlreadyExists      = errors.New("folder already exists")
)

type PostgresRepository struct {
	db database.Database
}

func NewPostgresRepository(db database.Database) Repository {
	return &PostgresRepository{db: db}
}

func (r *PostgresRepository) CreateDocument(document model.Document) error {
	_, err := r.db.Exec("INSERT INTO tbl_document (id, folder_id, owner_id, name, size, last_modified) VALUES ($1, $2, $3, $4, $5, $6)",
		document.ID, document.FolderID, document.OwnerID, document.Name, document.Size, document.LastModified)
	if err != nil {
		return err
	}
	return nil
}

func (r *PostgresRepository) DeleteDocument(id uuid.UUID) error {
	_, err := r.db.Exec("DELETE FROM tbl_document WHERE id = $1", id)
	if err != nil {
		return err
	}
	return nil
}

func (r *PostgresRepository) GetDocumentByID(id uuid.UUID) (model.Document, error) {
	var document model.Document
	err := r.db.QueryRow("SELECT id, folder_id, owner_id, name, size, last_modified FROM tbl_document WHERE id = $1", id).Scan(&document.ID, &document.FolderID, &document.OwnerID, &document.Name, &document.Size, &document.LastModified)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.Document{}, ErrDocumentNotFound
		}
		return model.Document{}, err
	}
	return document, nil
}

func (r *PostgresRepository) GetDocumentsByFolderID(folderID uuid.UUID) ([]model.Document, error) {
	var documents []model.Document
	rows, err := r.db.Query("SELECT id, folder_id, owner_id, name, size, last_modified FROM tbl_document WHERE folder_id = $1", folderID)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := rows.Close(); err != nil {
			slog.Error("Failed to close rows", "error", err)
		}
	}()

	for rows.Next() {
		var document model.Document
		if err := rows.Scan(&document.ID, &document.FolderID, &document.OwnerID, &document.Name, &document.Size, &document.LastModified); err != nil {
			return nil, err
		}
		documents = append(documents, document)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return documents, nil
}

func (r *PostgresRepository) GetDocumentsByOwnerID(ownerID uuid.UUID) ([]model.Document, error) {
	rows, err := r.db.Query("SELECT id, owner_id, name, size, last_modified FROM tbl_document WHERE owner_id = $1 ORDER BY last_modified DESC", ownerID)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := rows.Close(); err != nil {
			slog.Error("Failed to close rows", "error", err)
		}
	}()

	var documents []model.Document
	for rows.Next() {
		var document model.Document
		err := rows.Scan(&document.ID, &document.OwnerID, &document.Name, &document.Size, &document.LastModified)
		if err != nil {
			return nil, err
		}
		documents = append(documents, document)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return documents, nil
}

func (r *PostgresRepository) UpdateDocument(document model.Document) error {
	_, err := r.db.Exec("UPDATE tbl_document SET name = $1, size = $2 WHERE id = $3",
		document.Name, document.Size, document.ID)
	if err != nil {
		return err
	}
	return nil
}

func (r *PostgresRepository) CreateFolder(folder model.Folder) error {
	_, err := r.db.Exec("INSERT INTO tbl_folder (id, owner_id, name, last_modified) VALUES ($1, $2, $3, $4)",
		folder.ID, folder.OwnerID, folder.Name, folder.LastModified)
	if err != nil {
		return err
	}
	return nil
}

func (r *PostgresRepository) DeleteFolder(id uuid.UUID) error {
	_, err := r.db.Exec("DELETE FROM tbl_folder WHERE id = $1", id)
	if err != nil {
		return err
	}
	return nil
}

func (r *PostgresRepository) GetFolderByID(id uuid.UUID) (model.Folder, error) {
	var folder model.Folder
	err := r.db.QueryRow("SELECT id, owner_id, name, last_modified FROM tbl_folder WHERE id = $1", id).Scan(&folder.ID, &folder.OwnerID, &folder.Name, &folder.LastModified)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.Folder{}, ErrFolderNotFound
		}
		return model.Folder{}, err
	}
	return folder, nil
}
func (r *PostgresRepository) GetFoldersByOwnerID(ownerID uuid.UUID) ([]model.Folder, error) {
	var folders []model.Folder
	rows, err := r.db.Query("SELECT id, owner_id, name, last_modified FROM tbl_folder WHERE owner_id = $1", ownerID)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := rows.Close(); err != nil {
			slog.Error("Failed to close rows", "error", err)
		}
	}()

	for rows.Next() {
		var folder model.Folder
		if err := rows.Scan(&folder.ID, &folder.OwnerID, &folder.Name, &folder.LastModified); err != nil {
			return nil, err
		}
		folders = append(folders, folder)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return folders, nil
}

// UpdateFolder implements Repository.
func (r *PostgresRepository) UpdateFolder(folder model.Folder) error {
	_, err := r.db.Exec("UPDATE tbl_folder SET name = $1 WHERE id = $2",
		folder.Name, folder.ID)
	if err != nil {
		return err
	}
	return nil
}

// LogAudit implements Repository.
func (r *PostgresRepository) LogAudit(ctx context.Context, log model.AuditLog) error {
	oldValuesJSON, _ := json.Marshal(log.OldValues)
	newValuesJSON, _ := json.Marshal(log.NewValues)

	_, err := r.db.ExecContext(ctx,
		`INSERT INTO tbl_audit_log (id, user_id, entity_type, entity_id, action, 
         old_values, new_values, ip_address, user_agent, session_id, created_at) 
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		log.ID, log.UserID, log.EntityType, log.EntityID, log.Action,
		oldValuesJSON, newValuesJSON, log.IPAddress, log.UserAgent,
		log.SessionID, log.CreatedAt,
	)
	return err
}

// GetAuditLogs implements Repository.
func (r *PostgresRepository) GetAuditLogs(ctx context.Context, filters model.AuditFilters) ([]model.AuditLog, error) {
	query := `SELECT id, user_id, entity_type, entity_id, action, old_values, new_values, 
              ip_address, user_agent, session_id, created_at 
              FROM tbl_audit_log WHERE 1=1`
	args := []interface{}{}
	argIndex := 1

	if filters.UserID != nil {
		query += fmt.Sprintf(" AND user_id = $%d", argIndex)
		args = append(args, *filters.UserID)
		argIndex++
	}

	if filters.EntityType != "" {
		query += fmt.Sprintf(" AND entity_type = $%d", argIndex)
		args = append(args, filters.EntityType)
		argIndex++
	}

	if filters.Action != "" {
		query += fmt.Sprintf(" AND action = $%d", argIndex)
		args = append(args, filters.Action)
		argIndex++
	}

	if filters.StartDate != nil {
		query += fmt.Sprintf(" AND created_at >= $%d", argIndex)
		args = append(args, *filters.StartDate)
		argIndex++
	}

	if filters.EndDate != nil {
		query += fmt.Sprintf(" AND created_at <= $%d", argIndex)
		args = append(args, *filters.EndDate)
		argIndex++
	}

	query += " ORDER BY created_at DESC"

	if filters.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIndex)
		args = append(args, filters.Limit)
		argIndex++
	}

	if filters.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argIndex)
		args = append(args, filters.Offset)
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := rows.Close(); err != nil {
			slog.Error("Failed to close rows", "error", err)
		}
	}()

	var auditLogs []model.AuditLog
	for rows.Next() {
		var log model.AuditLog
		var oldValuesJSON, newValuesJSON sql.NullString

		err := rows.Scan(&log.ID, &log.UserID, &log.EntityType, &log.EntityID, &log.Action,
			&oldValuesJSON, &newValuesJSON, &log.IPAddress, &log.UserAgent,
			&log.SessionID, &log.CreatedAt)
		if err != nil {
			return nil, err
		}

		if oldValuesJSON.Valid {
			if err := json.Unmarshal([]byte(oldValuesJSON.String), &log.OldValues); err != nil {
				return nil, err
			}
		}
		if newValuesJSON.Valid {
			if err := json.Unmarshal([]byte(newValuesJSON.String), &log.NewValues); err != nil {
				return nil, err
			}
		}

		auditLogs = append(auditLogs, log)
	}

	return auditLogs, nil
}

// GetAuditLogsCount implements Repository.
func (r *PostgresRepository) GetAuditLogsCount(ctx context.Context, filters model.AuditFilters) (int, error) {
	query := `SELECT COUNT(*) FROM tbl_audit_log WHERE 1=1`
	args := []any{}
	argIndex := 1

	if filters.UserID != nil {
		query += fmt.Sprintf(" AND user_id = $%d", argIndex)
		args = append(args, *filters.UserID)
		argIndex++
	}

	if filters.EntityType != "" {
		query += fmt.Sprintf(" AND entity_type = $%d", argIndex)
		args = append(args, filters.EntityType)
		argIndex++
	}

	if filters.Action != "" {
		query += fmt.Sprintf(" AND action = $%d", argIndex)
		args = append(args, filters.Action)
		argIndex++
	}

	if filters.StartDate != nil {
		query += fmt.Sprintf(" AND created_at >= $%d", argIndex)
		args = append(args, *filters.StartDate)
		argIndex++
	}

	if filters.EndDate != nil {
		query += fmt.Sprintf(" AND created_at <= $%d", argIndex)
		args = append(args, *filters.EndDate)
	}

	var count int
	err := r.db.QueryRowContext(ctx, query, args...).Scan(&count)
	return count, err
}

func (r *PostgresRepository) Migrate(ctx context.Context) error {
	driver, err := postgres.WithInstance(r.db.DB, &postgres.Config{})
	if err != nil {
		return fmt.Errorf("failed to create postgres driver: %w", err)
	}

	m, err := migrate.NewWithDatabaseInstance(
		"file://../../migrations",
		"postgres", driver)
	if err != nil {
		return fmt.Errorf("failed to create new migration instance: %w", err)
	}

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("failed to apply migrations: %w", err)
	}

	slog.Info("Database migrations applied successfully")
	return nil
}

func (r *PostgresRepository) CreateUser(user model.User) error {
	_, err := r.db.Exec("INSERT INTO tbl_user (id, name, email, password_hash, role, is_email_verified, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
		user.ID, user.Name, user.Email, user.PasswordHash, user.Role, user.IsEmailVerified, user.CreatedAt)
	if err != nil {
		return err
	}
	return nil
}

func (r *PostgresRepository) GetUserByID(id uuid.UUID) (model.User, error) {
	var user model.User
	err := r.db.QueryRow("SELECT id, name, email, password_hash, role, is_email_verified, created_at FROM tbl_user WHERE id = $1", id).Scan(&user.ID, &user.Name, &user.Email, &user.PasswordHash, &user.Role, &user.IsEmailVerified, &user.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.User{}, ErrUserNotFound
		}
		return model.User{}, err
	}
	return user, nil
}

func (r *PostgresRepository) GetUserByEmail(email string) (model.User, error) {
	var user model.User
	err := r.db.QueryRow("SELECT id, name, email, password_hash, role, is_email_verified, created_at FROM tbl_user WHERE email = $1", email).Scan(&user.ID, &user.Name, &user.Email, &user.PasswordHash, &user.Role, &user.IsEmailVerified, &user.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.User{}, ErrUserNotFound
		}
		return model.User{}, err
	}
	return user, nil
}

func (r *PostgresRepository) UpdateUser(user model.User) error {
	_, err := r.db.Exec("UPDATE tbl_user SET name = $1, email = $2, password_hash = $3, role = $4, is_email_verified = $5 WHERE id = $6",
		user.Name, user.Email, user.PasswordHash, user.Role, user.IsEmailVerified, user.ID)
	if err != nil {
		return err
	}
	return nil
}

func (r *PostgresRepository) CreateUserRegistration(userRegistration model.UserRegistration) error {
	_, err := r.db.Exec("INSERT INTO tbl_user_registration (id, user_id, activation_code, created_at) VALUES ($1, $2, $3, $4)",
		userRegistration.ID, userRegistration.UserID, userRegistration.ActivationCode, userRegistration.CreatedAt)
	if err != nil {
		return err
	}
	return nil
}

func (r *PostgresRepository) GetUserRegistrationByUserID(userID uuid.UUID) (model.UserRegistration, error) {
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

func (r *PostgresRepository) GetUserRegistrationByEmail(email string) (model.UserRegistration, error) {
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

func (r *PostgresRepository) DeleteUserRegistration(id uuid.UUID) error {
	_, err := r.db.Exec("DELETE FROM tbl_user_registration WHERE id = $1", id)
	if err != nil {
		return err
	}
	return nil
}

func (r *PostgresRepository) GetUserStats() (model.AdminStats, error) {
	var stats model.AdminStats

	// Get total users count
	err := r.db.QueryRow("SELECT COUNT(*) FROM tbl_user").Scan(&stats.TotalUsers)
	if err != nil {
		return model.AdminStats{}, err
	}

	// Get active users count (users who have been verified)
	err = r.db.QueryRow("SELECT COUNT(*) FROM tbl_user WHERE is_email_verified = true").Scan(&stats.ActiveUsers)
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

func (r *PostgresRepository) GetAllUsers(limit, offset int) ([]model.UserWithRegistration, int, error) {
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
			u.id, u.name, u.email, u.role, u.is_email_verified, u.created_at,
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
			&user.User.Role, &user.User.IsEmailVerified, &user.User.CreatedAt,
			&regID, &regActivationCode, &regCreatedAt,
		)
		if err != nil {
			return nil, 0, err
		}

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
func (r *PostgresRepository) ActivateUser(userID uuid.UUID) error {
	tx, err := r.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil {
			slog.Error("failed to rollback transaction", "error", err)
		}
	}()

	_, err = tx.Exec("UPDATE tbl_user SET is_email_verified = true WHERE id = $1", userID)
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
func (r *PostgresRepository) DeleteUser(userID uuid.UUID) error {
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
func (r *PostgresRepository) GetUserByIDForAdmin(userID uuid.UUID) (model.User, error) {
	var user model.User
	query := `
		SELECT id, name, email, password_hash, role, is_email_verified, created_at
		FROM tbl_user 
		WHERE id = $1
	`
	err := r.db.QueryRow(query, userID).Scan(
		&user.ID, &user.Name, &user.Email, &user.PasswordHash,
		&user.Role, &user.IsEmailVerified, &user.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.User{}, ErrUserNotFound
		}
		return model.User{}, err
	}

	return user, nil
}

// HealthCheck performs a simple health check on the database connection
func (r *PostgresRepository) HealthCheck(ctx context.Context) error {
	return r.db.PingContext(ctx)
}
