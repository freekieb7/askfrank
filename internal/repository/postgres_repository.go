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
	"strings"
	"time"

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
	_, err := r.db.Exec(`INSERT INTO tbl_document 
		(id, folder_id, owner_id, name, size, content_type, storage_key, last_modified) 
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		document.ID, document.FolderID, document.OwnerID, document.Name, document.Size,
		document.ContentType, document.StorageKey, document.LastModified)
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
	err := r.db.QueryRow(`SELECT id, folder_id, owner_id, name, size, content_type, storage_key, last_modified 
		FROM tbl_document WHERE id = $1`, id).Scan(
		&document.ID, &document.FolderID, &document.OwnerID, &document.Name,
		&document.Size, &document.ContentType, &document.StorageKey, &document.LastModified)
	if err != nil {
		return model.Document{}, err
	}
	return document, nil
}

func (r *PostgresRepository) GetDocumentsByFolderID(folderID uuid.UUID) ([]model.Document, error) {
	var documents []model.Document
	rows, err := r.db.Query(`SELECT id, folder_id, owner_id, name, size, content_type, storage_key, last_modified 
		FROM tbl_document WHERE folder_id = $1`, folderID)
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
		if err := rows.Scan(&document.ID, &document.FolderID, &document.OwnerID, &document.Name,
			&document.Size, &document.ContentType, &document.StorageKey, &document.LastModified); err != nil {
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
	rows, err := r.db.Query(`SELECT id, folder_id, owner_id, name, size, content_type, storage_key, last_modified 
		FROM tbl_document WHERE owner_id = $1 ORDER BY last_modified DESC`, ownerID)
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
		err := rows.Scan(&document.ID, &document.FolderID, &document.OwnerID, &document.Name,
			&document.Size, &document.ContentType, &document.StorageKey, &document.LastModified)
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
	_, err := r.db.Exec(`UPDATE tbl_document SET 
		name = $1, 
		size = $2, 
		content_type = $3, 
		storage_key = $4,
		last_modified = $5
		WHERE id = $6`,
		document.Name, document.Size, document.ContentType, document.StorageKey, document.LastModified, document.ID)
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

// Subscription repository methods
func (r *PostgresRepository) GetSubscriptionPlans(ctx context.Context) ([]model.SubscriptionPlan, error) {
	query := `
		SELECT id, name, description, stripe_price_id, amount_cents, currency, 
			   interval, features, is_active, created_at, updated_at
		FROM tbl_subscription_plan 
		WHERE is_active = true 
		ORDER BY amount_cents ASC`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var plans []model.SubscriptionPlan
	for rows.Next() {
		var plan model.SubscriptionPlan
		err := rows.Scan(&plan.ID, &plan.Name, &plan.Description, &plan.StripePriceID,
			&plan.AmountCents, &plan.Currency, &plan.Interval, &plan.Features,
			&plan.IsActive, &plan.CreatedAt, &plan.UpdatedAt)
		if err != nil {
			return nil, err
		}
		plans = append(plans, plan)
	}

	return plans, nil
}

func (r *PostgresRepository) GetSubscriptionPlanByID(ctx context.Context, id uuid.UUID) (model.SubscriptionPlan, error) {
	var plan model.SubscriptionPlan
	query := `
		SELECT id, name, description, stripe_price_id, amount_cents, currency,
			   interval, features, is_active, created_at, updated_at
		FROM tbl_subscription_plan WHERE id = $1 AND is_active = true`

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&plan.ID, &plan.Name, &plan.Description, &plan.StripePriceID,
		&plan.AmountCents, &plan.Currency, &plan.Interval, &plan.Features,
		&plan.IsActive, &plan.CreatedAt, &plan.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return plan, fmt.Errorf("subscription plan not found")
		}
		return plan, err
	}

	return plan, nil
}

func (r *PostgresRepository) CreateUserSubscription(ctx context.Context, subscription model.UserSubscription) error {
	query := `
		INSERT INTO tbl_user_subscription 
		(id, user_id, plan_id, stripe_customer_id, stripe_subscription_id, status, 
		 current_period_start, current_period_end, trial_end, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`

	_, err := r.db.ExecContext(ctx, query,
		subscription.ID, subscription.UserID, subscription.PlanID,
		subscription.StripeCustomerID, subscription.StripeSubscriptionID,
		subscription.Status, subscription.CurrentPeriodStart,
		subscription.CurrentPeriodEnd, subscription.TrialEnd,
		subscription.CreatedAt, subscription.UpdatedAt)

	return err
}

func (r *PostgresRepository) GetActiveSubscriptionByUserID(ctx context.Context, userID uuid.UUID) (model.UserSubscription, error) {
	var subscription model.UserSubscription
	query := `
		SELECT us.id, us.user_id, us.plan_id, us.stripe_customer_id, us.stripe_subscription_id,
			   us.status, us.current_period_start, us.current_period_end, us.trial_end,
			   us.canceled_at, us.created_at, us.updated_at,
			   sp.name, sp.description, sp.amount_cents, sp.currency, sp.features
		FROM tbl_user_subscription us
		JOIN tbl_subscription_plan sp ON us.plan_id = sp.id
		WHERE us.user_id = $1 AND us.status IN ('active', 'trialing', 'past_due')
		ORDER BY us.created_at DESC LIMIT 1`

	var plan model.SubscriptionPlan
	err := r.db.QueryRowContext(ctx, query, userID).Scan(
		&subscription.ID, &subscription.UserID, &subscription.PlanID,
		&subscription.StripeCustomerID, &subscription.StripeSubscriptionID,
		&subscription.Status, &subscription.CurrentPeriodStart,
		&subscription.CurrentPeriodEnd, &subscription.TrialEnd,
		&subscription.CanceledAt, &subscription.CreatedAt, &subscription.UpdatedAt,
		&plan.Name, &plan.Description, &plan.AmountCents, &plan.Currency, &plan.Features)

	if err != nil {
		if err == sql.ErrNoRows {
			return subscription, fmt.Errorf("no active subscription found")
		}
		return subscription, err
	}

	subscription.Plan = &plan
	return subscription, nil
}

func (r *PostgresRepository) UpdateUserSubscription(ctx context.Context, subscription model.UserSubscription) error {
	query := `
		UPDATE tbl_user_subscription SET 
			status = $1, 
			current_period_start = $2, 
			current_period_end = $3,
			trial_end = $4,
			canceled_at = $5,
			updated_at = $6
		WHERE id = $7`

	_, err := r.db.ExecContext(ctx, query,
		subscription.Status, subscription.CurrentPeriodStart, subscription.CurrentPeriodEnd,
		subscription.TrialEnd, subscription.CanceledAt, subscription.UpdatedAt, subscription.ID)

	return err
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

// Usage tracking methods
func (r *PostgresRepository) CreateUsageRecord(ctx context.Context, record model.UsageRecord) error {
	query := `
		INSERT INTO tbl_usage_record (id, user_id, subscription_id, usage_type, quantity, unit_price, description, billing_period, is_charged, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`
	_, err := r.db.ExecContext(ctx, query,
		record.ID, record.UserID, record.SubscriptionID, record.UsageType,
		record.Quantity, record.UnitPrice, record.Description, record.BillingPeriod,
		record.IsCharged, record.CreatedAt)
	if err != nil {
		return fmt.Errorf("failed to create usage record: %w", err)
	}
	return nil
}

func (r *PostgresRepository) GetUsageByUserAndPeriod(ctx context.Context, userID uuid.UUID, period time.Time) ([]model.UsageRecord, error) {
	// Get usage for the billing period (month)
	startOfMonth := time.Date(period.Year(), period.Month(), 1, 0, 0, 0, 0, period.Location())
	endOfMonth := startOfMonth.AddDate(0, 1, 0)

	query := `
		SELECT id, user_id, subscription_id, usage_type, quantity, unit_price, description, billing_period, is_charged, created_at
		FROM tbl_usage_record
		WHERE user_id = $1 AND billing_period >= $2 AND billing_period < $3
		ORDER BY created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, userID, startOfMonth, endOfMonth)
	if err != nil {
		return nil, fmt.Errorf("failed to query usage records: %w", err)
	}
	defer rows.Close()

	var records []model.UsageRecord
	for rows.Next() {
		var record model.UsageRecord
		err := rows.Scan(&record.ID, &record.UserID, &record.SubscriptionID, &record.UsageType,
			&record.Quantity, &record.UnitPrice, &record.Description, &record.BillingPeriod,
			&record.IsCharged, &record.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan usage record: %w", err)
		}
		records = append(records, record)
	}

	return records, nil
}

func (r *PostgresRepository) GetUsageSummary(ctx context.Context, userID uuid.UUID, period time.Time) (model.UsageSummary, error) {
	// Get user's subscription and plan limits
	subscription, err := r.GetActiveSubscriptionByUserID(ctx, userID)
	if err != nil {
		return model.UsageSummary{}, fmt.Errorf("failed to get subscription: %w", err)
	}

	limits, err := r.GetPlanLimits(ctx, subscription.PlanID)
	if err != nil {
		return model.UsageSummary{}, fmt.Errorf("failed to get plan limits: %w", err)
	}

	// Get usage for the billing period
	startOfMonth := time.Date(period.Year(), period.Month(), 1, 0, 0, 0, 0, period.Location())
	endOfMonth := startOfMonth.AddDate(0, 1, 0)

	query := `
		SELECT 
			usage_type,
			SUM(quantity) as total_quantity
		FROM tbl_usage_record
		WHERE user_id = $1 AND billing_period >= $2 AND billing_period < $3
		GROUP BY usage_type
	`

	rows, err := r.db.QueryContext(ctx, query, userID, startOfMonth, endOfMonth)
	if err != nil {
		return model.UsageSummary{}, fmt.Errorf("failed to query usage summary: %w", err)
	}
	defer rows.Close()

	summary := model.UsageSummary{
		UserID:        userID,
		BillingPeriod: startOfMonth,
	}

	for rows.Next() {
		var usageType string
		var totalQuantity int
		err := rows.Scan(&usageType, &totalQuantity)
		if err != nil {
			return model.UsageSummary{}, fmt.Errorf("failed to scan usage summary: %w", err)
		}

		switch usageType {
		case model.UsageTypeReports:
			summary.ReportsUsed = totalQuantity
			if totalQuantity > limits.ReportsPerMonth {
				summary.ReportsOverage = totalQuantity - limits.ReportsPerMonth
				summary.OverageCharges += summary.ReportsOverage * model.ReportOveragePrice
			}
		case model.UsageTypeStorage:
			summary.StorageUsedGB = float64(totalQuantity) / 1000.0 // Convert MB to GB
			if summary.StorageUsedGB > float64(limits.StorageGB) {
				summary.StorageOverageGB = summary.StorageUsedGB - float64(limits.StorageGB)
				summary.OverageCharges += int(summary.StorageOverageGB * float64(model.StorageOveragePrice))
			}
		case model.UsageTypeAPICalls:
			summary.APICallsUsed = totalQuantity
			if totalQuantity > limits.APICallsPerMonth {
				summary.APICallsOverage = totalQuantity - limits.APICallsPerMonth
				summary.OverageCharges += (summary.APICallsOverage / 1000) * model.APICallOveragePrice
			}
		}
	}

	return summary, nil
}

func (r *PostgresRepository) GetPlanLimits(ctx context.Context, planID uuid.UUID) (model.PlanLimits, error) {
	query := `
		SELECT id, plan_id, reports_per_month, storage_gb, api_calls_per_month, users_included, created_at, updated_at
		FROM tbl_plan_limits
		WHERE plan_id = $1
	`

	var limits model.PlanLimits
	err := r.db.QueryRowContext(ctx, query, planID).Scan(
		&limits.ID, &limits.PlanID, &limits.ReportsPerMonth, &limits.StorageGB,
		&limits.APICallsPerMonth, &limits.UsersIncluded, &limits.CreatedAt, &limits.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.PlanLimits{}, fmt.Errorf("plan limits not found for plan %s", planID)
		}
		return model.PlanLimits{}, fmt.Errorf("failed to get plan limits: %w", err)
	}

	return limits, nil
}

func (r *PostgresRepository) MarkUsageAsCharged(ctx context.Context, usageIDs []uuid.UUID) error {
	if len(usageIDs) == 0 {
		return nil
	}

	// Create placeholders for the IN clause
	placeholders := make([]string, len(usageIDs))
	args := make([]interface{}, len(usageIDs))
	for i, id := range usageIDs {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = id
	}

	query := fmt.Sprintf(`
		UPDATE tbl_usage_record 
		SET is_charged = TRUE 
		WHERE id IN (%s)
	`, strings.Join(placeholders, ","))

	_, err := r.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to mark usage as charged: %w", err)
	}

	return nil
}

func (r *PostgresRepository) GetUnchargedUsage(ctx context.Context, userID uuid.UUID, period time.Time) ([]model.UsageRecord, error) {
	startOfMonth := time.Date(period.Year(), period.Month(), 1, 0, 0, 0, 0, period.Location())
	endOfMonth := startOfMonth.AddDate(0, 1, 0)

	query := `
		SELECT id, user_id, subscription_id, usage_type, quantity, unit_price, description, billing_period, is_charged, created_at
		FROM tbl_usage_record
		WHERE user_id = $1 AND billing_period >= $2 AND billing_period < $3 AND is_charged = FALSE
		ORDER BY created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, userID, startOfMonth, endOfMonth)
	if err != nil {
		return nil, fmt.Errorf("failed to query uncharged usage: %w", err)
	}
	defer rows.Close()

	var records []model.UsageRecord
	for rows.Next() {
		var record model.UsageRecord
		err := rows.Scan(&record.ID, &record.UserID, &record.SubscriptionID, &record.UsageType,
			&record.Quantity, &record.UnitPrice, &record.Description, &record.BillingPeriod,
			&record.IsCharged, &record.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan usage record: %w", err)
		}
		records = append(records, record)
	}

	return records, nil
}

// CreateAuditLog creates a new audit log entry
func (r *PostgresRepository) CreateAuditLog(ctx context.Context, log model.AuditLog) error {
	query := `
		INSERT INTO tbl_audit_log (id, user_id, entity_type, entity_id, action, old_values, new_values, ip_address, user_agent, session_id, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`

	var oldValuesJSON, newValuesJSON []byte
	var err error

	if log.OldValues != nil {
		oldValuesJSON, err = json.Marshal(log.OldValues)
		if err != nil {
			return fmt.Errorf("failed to marshal old values: %w", err)
		}
	}

	if log.NewValues != nil {
		newValuesJSON, err = json.Marshal(log.NewValues)
		if err != nil {
			return fmt.Errorf("failed to marshal new values: %w", err)
		}
	}

	_, err = r.db.ExecContext(ctx, query,
		log.ID, log.UserID, log.EntityType, log.EntityID, log.Action,
		oldValuesJSON, newValuesJSON, log.IPAddress, log.UserAgent, log.SessionID, log.CreatedAt)
	if err != nil {
		return fmt.Errorf("failed to create audit log: %w", err)
	}

	return nil
}

func (r *PostgresRepository) GetActiveSubscriptions(ctx context.Context) ([]model.UserSubscription, error) {
	query := `
		SELECT s.id, s.user_id, s.plan_id, s.stripe_customer_id, s.stripe_subscription_id, 
		       s.status, s.current_period_start, s.current_period_end, s.trial_end, 
		       s.canceled_at, s.created_at, s.updated_at
		FROM tbl_user_subscription s
		WHERE s.status = 'active' OR s.status = 'trialing'
		ORDER BY s.created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query active subscriptions: %w", err)
	}
	defer rows.Close()

	var subscriptions []model.UserSubscription
	for rows.Next() {
		var sub model.UserSubscription
		err := rows.Scan(&sub.ID, &sub.UserID, &sub.PlanID, &sub.StripeCustomerID,
			&sub.StripeSubscriptionID, &sub.Status, &sub.CurrentPeriodStart,
			&sub.CurrentPeriodEnd, &sub.TrialEnd, &sub.CanceledAt,
			&sub.CreatedAt, &sub.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan subscription: %w", err)
		}
		subscriptions = append(subscriptions, sub)
	}

	return subscriptions, nil
}
