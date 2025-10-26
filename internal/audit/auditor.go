package audit

import (
	"context"
	"log/slog"
	"time"

	"github.com/freekieb7/askfrank/internal/database"
	"github.com/freekieb7/askfrank/internal/util"

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

type Event struct {
	ID        uuid.UUID
	CreatedAt time.Time
	Type      AuditLogEventType
	Data      []byte
}

type ListEventsParam struct {
	OrganisationID uuid.UUID
	StartTime      util.Optional[time.Time]
	EndTime        util.Optional[time.Time]
	Limit          uint8
}

func (a *Auditor) ListEvents(ctx context.Context, params ListEventsParam) ([]Event, error) {
	return make([]Event, 0), nil
	// dbEvents, err := a.db.ListAuditLogEvents(ctx, database.ListAuditLogEventsParams{
	// 	OwnerOrganisationID: util.Some(params.OrganisationID),
	// 	StartTimestamp:      params.StartTime,
	// 	EndTimestamp:        params.EndTime,
	// 	Limit:               util.Some(params.Limit),
	// })
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to list audit log events: %w", err)
	// }

	// events := make([]Event, len(dbEvents))
	// for i, dbEvent := range dbEvents {
	// 	events[i] = Event{
	// 		ID:        dbEvent.ID,
	// 		CreatedAt: dbEvent.CreatedAt,
	// 		Type:      AuditLogEventType(dbEvent.Type),
	// 		Data:      dbEvent.Data,
	// 	}
	// }
	// return events, nil
}

type LogEventParam struct {
	Type AuditLogEventType
	Data map[string]any
}

func (a *Auditor) LogEvent(ctx context.Context, params LogEventParam) error {
	// data, err := json.Marshal(params.Data)
	// if err != nil {
	// 	return fmt.Errorf("failed to marshal audit log event data: %w", err)
	// }

	// if _, err = a.db.CreateAuditLogEvent(ctx, database.CreateAuditLogEventParams{
	// 	OrganisationOwnerID: params.OrganisationID,
	// 	EventType:           string(params.Type),
	// 	EventData:           data,
	// }); err != nil {
	// 	return fmt.Errorf("failed to create audit log event: %w", err)
	// }
	return nil
}
