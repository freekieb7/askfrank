package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"hp/internal/database"
	"log/slog"

	"github.com/google/uuid"
)

type AuditLogEventType string

const (
	AuditLogEventTypeUserLogin                 AuditLogEventType = "user.login"
	AuditLogEventTypeUserLogout                AuditLogEventType = "user.logout"
	AuditLogEventTypeUserRegister              AuditLogEventType = "user.register"
	AuditLogEventTypeUserCreate                AuditLogEventType = "user.create"
	AuditLogEventTypeUserUpdate                AuditLogEventType = "user.update"
	AuditLogEventTypeUserDelete                AuditLogEventType = "user.delete"
	AuditLogEventTypeUserPasswordChange        AuditLogEventType = "user.password_change"
	AuditLogEventTypeUserPasswordReset         AuditLogEventType = "user.password_reset"
	AuditLogEventTypeAPIKeyCreate              AuditLogEventType = "api_key.create"
	AuditLogEventTypeAPIKeyRevoke              AuditLogEventType = "api_key.revoke"
	AuditLogEventTypeWebhookSubscriptionCreate AuditLogEventType = "webhook_subscription.create"
	AuditLogEventTypeWebhookSubscriptionUpdate AuditLogEventType = "webhook_subscription.update"
	AuditLogEventTypeWebhookSubscriptionDelete AuditLogEventType = "webhook_subscription.delete"
	AuditLogEventTypeWebhookEventCreate        AuditLogEventType = "webhook_event.create"
	AuditLogEventTypeWebhookDeliveryAttempt    AuditLogEventType = "webhook_delivery.attempt"
	AuditLogEventTypeSubscriptionChanged       AuditLogEventType = "subscription.changed"
)

type Auditor struct {
	logger *slog.Logger
	db     *database.Database
}

func NewAuditor(logger *slog.Logger, db *database.Database) Auditor {
	return Auditor{logger: logger, db: db}
}

type LogEventParam struct {
	OwnerID uuid.UUID
	Type    AuditLogEventType
	Data    map[string]any
}

func (a *Auditor) LogEvent(ctx context.Context, params LogEventParam) error {
	data, err := json.Marshal(params.Data)
	if err != nil {
		return fmt.Errorf("failed to marshal audit log event data: %w", err)
	}

	if _, err = a.db.CreateAuditLogEvent(ctx, database.CreateAuditLogEventParams{
		OwnerID:   params.OwnerID,
		EventType: string(params.Type),
		EventData: data,
	}); err != nil {
		return fmt.Errorf("failed to create audit log event: %w", err)
	}
	return nil
}
