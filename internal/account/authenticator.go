package account

import (
	"context"
	"fmt"
	"hp/internal/audit"
	"hp/internal/database"
	"hp/internal/notifications"
	"hp/internal/stripe"
	"hp/internal/webhook"
	"log/slog"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrUserNotFound       = fmt.Errorf("user not found")
	ErrInvalidPassword    = fmt.Errorf("invalid password")
	ErrEmailAlreadyInUse  = fmt.Errorf("email already in use")
	ErrFailedToCreateUser = fmt.Errorf("failed to create user")
)

type Authenticator struct {
	logger         *slog.Logger
	db             *database.Database
	auditor        *audit.Auditor
	webhookManager *webhook.Manager
	notifier       *notifications.Notifier
	stripeClient   *stripe.Client
}

func NewAuthenticator(logger *slog.Logger, db *database.Database, auditor *audit.Auditor, webhookManager *webhook.Manager, notifier *notifications.Notifier, stripe *stripe.Client) Authenticator {
	return Authenticator{logger: logger, db: db, auditor: auditor, webhookManager: webhookManager, notifier: notifier, stripeClient: stripe}
}

type LoginParam struct {
	Email    string
	Password string
}

func (a *Authenticator) Login(ctx context.Context, param LoginParam) (uuid.UUID, error) {
	var userID uuid.UUID

	user, err := a.db.GetUserByEmail(ctx, param.Email)
	if err != nil {
		if err == database.ErrUserNotFound {
			return userID, ErrUserNotFound
		}

		return userID, fmt.Errorf("failed to get user by email: %w", err)
	}

	// Check password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(param.Password)); err != nil {
		return userID, ErrInvalidPassword
	}

	// Successful authentication
	userID = user.ID

	// Audit log
	if err = a.auditor.LogEvent(ctx, audit.LogEventParam{
		OwnerID: user.ID,
		Type:    audit.AuditLogEventTypeUserLogin,
		Data: map[string]any{
			"email":   user.Email,
			"user_id": user.ID,
		},
	}); err != nil {
		return userID, fmt.Errorf("failed to log audit event: %w", err)
	}

	// Webhook event
	if err = a.webhookManager.RegisterEvent(ctx, webhook.RegisterEventParam{
		OwnerID: user.ID,
		Type:    webhook.EventTypeUserLogin,
		Data: map[string]any{
			"user_id":   user.ID,
			"email":     user.Email,
			"timestamp": user.CreatedAt.Format("2006-01-02T15:04:05Z"),
		},
	}); err != nil {
		return userID, fmt.Errorf("failed to create webhook event: %w", err)
	}

	// Notification
	if err = a.notifier.Notify(ctx, notifications.NotifyParam{
		OwnerID: user.ID,
		Title:   "Login Successful",
		Message: "You have successfully logged in to your account.",
		Type:    notifications.NotificationTypeInfo,
	}); err != nil {
		return userID, fmt.Errorf("failed to create notification: %w", err)
	}

	return userID, nil
}

func (a *Authenticator) Logout(ctx context.Context, userID uuid.UUID) error {
	// Audit log
	if err := a.auditor.LogEvent(ctx, audit.LogEventParam{
		OwnerID: userID,
		Type:    audit.AuditLogEventTypeUserLogout,
		Data: map[string]any{
			"user_id": userID,
		},
	}); err != nil {
		return fmt.Errorf("failed to log audit event: %w", err)
	}

	// Webhook event
	if err := a.webhookManager.RegisterEvent(ctx, webhook.RegisterEventParam{
		OwnerID: userID,
		Type:    webhook.EventTypeUserLogout,
		Data: map[string]any{
			"user_id":   userID,
			"timestamp": fmt.Sprintf("%v", userID),
		},
	}); err != nil {
		return fmt.Errorf("failed to create webhook event: %w", err)
	}

	// Notification
	if err := a.notifier.Notify(ctx, notifications.NotifyParam{
		OwnerID: userID,
		Title:   "Logout Successful",
		Message: "You have successfully logged out of your account.",
		Type:    notifications.NotificationTypeInfo,
	}); err != nil {
		return fmt.Errorf("failed to create notification: %w", err)
	}

	return nil
}
