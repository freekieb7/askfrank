package daemon

import (
	"context"
	"encoding/json"
	"hp/internal/database"
	"hp/internal/util"
	"log/slog"
	"time"
)

// TriggerTestWebhookEvent creates a test webhook event for testing purposes
// This is useful for manually testing the webhook delivery system
func TriggerTestWebhookEvent(ctx context.Context, db *database.Database, logger *slog.Logger, eventType database.WebhookEventType) error {
	// Create a test payload
	testPayload := map[string]interface{}{
		"event_type": string(eventType),
		"timestamp":  time.Now().Format(time.RFC3339),
		"test":       true,
		"data": map[string]interface{}{
			"message": "This is a test webhook event",
			"id":      "test-" + time.Now().Format("20060102-150405"),
		},
	}

	payloadBytes, err := json.Marshal(testPayload)
	if err != nil {
		logger.Error("Failed to marshal test payload", "error", err)
		return err
	}

	// Create the webhook event (this will automatically create deliveries for active subscriptions)
	_, err = db.CreateWebhookEvent(ctx, database.CreateWebhookEventParams{
		EventType: eventType,
		Payload:   payloadBytes,
	})
	if err != nil {
		logger.Error("Failed to create test webhook event", "error", err)
		return err
	}

	logger.Info("Test webhook event created successfully",
		"event_type", eventType,
		"payload_size", len(payloadBytes))

	return nil
}

// GetWebhookDeliveryStats returns statistics about webhook deliveries
func GetWebhookDeliveryStats(ctx context.Context, db *database.Database) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Get pending deliveries
	pendingDeliveries, err := db.ListWebhookDeliveries(ctx, database.ListWebhookDeliveriesParams{
		Status: util.Some(database.WebhookDeliveryStatusPending),
	})
	if err == nil {
		stats["pending_count"] = len(pendingDeliveries)
	}

	// Get sent deliveries
	sentDeliveries, err := db.ListWebhookDeliveries(ctx, database.ListWebhookDeliveriesParams{
		Status: util.Some(database.WebhookDeliveryStatusSent),
	})
	if err == nil {
		stats["sent_count"] = len(sentDeliveries)
	}

	// Get failed deliveries
	failedDeliveries, err := db.ListWebhookDeliveries(ctx, database.ListWebhookDeliveriesParams{
		Status: util.Some(database.WebhookDeliveryStatusFailed),
	})
	if err == nil {
		stats["failed_count"] = len(failedDeliveries)
	}

	return stats, nil
}
