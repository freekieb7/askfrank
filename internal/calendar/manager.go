package calendar

import (
	"context"
	"hp/internal/audit"
	"hp/internal/database"
	"hp/internal/notifications"
	"hp/internal/util"
	"log/slog"
	"time"

	"github.com/google/uuid"
)

type Manager struct {
	Logger   *slog.Logger
	DB       *database.Database
	Auditor  *audit.Auditor
	Notifier *notifications.Manager
}

func NewManager(logger *slog.Logger, db *database.Database, auditor *audit.Auditor, notifier *notifications.Manager) Manager {
	return Manager{Logger: logger, DB: db, Auditor: auditor, Notifier: notifier}
}

type EventStatus string

const (
	EventStatusTentative EventStatus = "tentative"
	EventStatusConfirmed EventStatus = "confirmed"
	EventStatusCancelled EventStatus = "cancelled"
)

type Event struct {
	ID          uuid.UUID
	Title       string
	Description string
	StartTime   time.Time
	EndTime     time.Time
	AllDay      bool
	Location    string
	Status      EventStatus
}

type EventsParams struct {
	UserID    uuid.UUID
	StartTime time.Time
	EndTime   time.Time
}

func (m *Manager) Events(ctx context.Context, params EventsParams) ([]Event, error) {
	var events []Event

	// Fetch events from the database
	dbEvents, err := m.DB.ListCalendarEvents(ctx, database.ListCalendarEventsParams{
		OwnerUserID:    util.Some(params.UserID),
		StartTimestamp: util.Some(params.StartTime),
		EndTimestamp:   util.Some(params.EndTime),
	})
	if err != nil {
		return events, err
	}

	for _, e := range dbEvents {
		events = append(events, Event{
			ID:          e.ID,
			Title:       e.Title,
			Description: e.Description,
			StartTime:   e.StartTime,
			EndTime:     e.EndTime,
			Location:    e.Location,
			AllDay:      e.AllDay,
			Status:      EventStatus(e.Status),
		})
	}

	return events, nil
}
