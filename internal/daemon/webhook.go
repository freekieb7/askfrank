package daemon

import (
	"context"
	"hp/internal/database"
	"log/slog"
	"time"
)

var (
	// delivery policy
	maxRetries        = 6
	initialBackoff    = time.Second * 10
	backoffMultiplier = 2.0
	httpTimeout       = time.Second * 10
)

func SendWebhookDeliveriesTask(db *database.Database, logger *slog.Logger) DaemonFunc {
	return func(ctx context.Context, name string) error {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		logger.Info("Webhook delivery task started", "task", name)

		for {
			select {
			case <-ctx.Done():
				logger.Info("Webhook delivery task shutting down", "task", name)
				return nil
			case <-ticker.C:
				// Get pending deliveries and those ready for retry
				// deliveries, err := db.ListWebhookDeliveries(ctx, database.ListWebhookDeliveriesParams{
				// 	Status:        util.Some(database.WebhookDeliveryStatusPending),
				// 	MaxRetries:    util.Some(maxRetries),
				// 	ReadyForRetry: util.Some(true),
				// })
				// if err != nil {
				// 	logger.Error("Failed to fetch webhook deliveries", "error", err)
				// 	continue
				// }

				// if len(deliveries) == 0 {
				// 	continue
				// }

				// logger.Debug("Processing webhook deliveries", "count", len(deliveries))

				// // Process each delivery
				// for _, delivery := range deliveries {
				// 	err := processWebhookDelivery(ctx, db, logger, delivery)
				// 	if err != nil {
				// 		logger.Error("Failed to process webhook delivery",
				// 			"delivery_id", delivery.ID,
				// 			"url", delivery.URL,
				// 			"error", err)
				// 	}
				// }
			}
		}
	}
}

// // processWebhookDelivery handles the actual HTTP delivery of a webhook
// func processWebhookDelivery(ctx context.Context, db *database.Database, logger *slog.Logger, delivery database.WebhookDelivery) error {
// 	logger.Debug("Processing webhook delivery",
// 		"delivery_id", delivery.ID,
// 		"url", delivery.URL,
// 		"retry_count", delivery.RetryCount)

// 	// Create HMAC signature for webhook security
// 	mac := hmac.New(sha256.New, []byte(delivery.Secret))
// 	mac.Write(delivery.Payload)
// 	signature := "sha256=" + hex.EncodeToString(mac.Sum(nil))

// 	// Create HTTP request
// 	client := &http.Client{Timeout: httpTimeout}
// 	req, err := http.NewRequestWithContext(ctx, http.MethodPost, delivery.URL, bytes.NewReader(delivery.Payload))
// 	if err != nil {
// 		return scheduleRetry(ctx, db, logger, delivery, 0, fmt.Sprintf("Failed to create HTTP request: %v", err))
// 	}

// 	// Set headers
// 	req.Header.Set("Content-Type", "application/json")
// 	req.Header.Set("X-Webhook-Signature", signature)
// 	req.Header.Set("X-Webhook-Event-Type", string(delivery.EventType))
// 	req.Header.Set("X-Webhook-Event-ID", delivery.EventID.String())
// 	req.Header.Set("X-Webhook-Delivery-ID", delivery.ID.String())
// 	req.Header.Set("User-Agent", "AskFrank-Webhook/1.0")

// 	// Send the webhook
// 	resp, err := client.Do(req)
// 	if err != nil {
// 		// Network error - schedule retry
// 		return scheduleRetry(ctx, db, logger, delivery, 0, fmt.Sprintf("HTTP request failed: %v", err))
// 	}
// 	defer resp.Body.Close()

// 	// Read response body (limited to prevent memory issues)
// 	respBodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
// 	respBody := string(respBodyBytes)
// 	if err != nil {
// 		respBody = fmt.Sprintf("Error reading response: %v", err)
// 	}

// 	// Check response status
// 	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
// 		// Success - mark as sent
// 		return markDeliverySuccess(ctx, db, logger, delivery, resp.StatusCode, respBody)
// 	} else {
// 		// HTTP error - schedule retry
// 		return scheduleRetry(ctx, db, logger, delivery, resp.StatusCode, respBody)
// 	}
// }

// // markDeliverySuccess marks a webhook delivery as successfully sent
// func markDeliverySuccess(ctx context.Context, db *database.Database, logger *slog.Logger, delivery database.WebhookDelivery, statusCode int, respBody string) error {
// 	now := time.Now()
// 	err := db.UpdateWebhookDeliveryByID(ctx, delivery.ID, database.UpdateWebhookDeliveryParams{
// 		Status:           util.Some(database.WebhookDeliveryStatusSent),
// 		RetryCount:       util.Some(delivery.RetryCount + 1),
// 		LastAttemptAt:    util.Some(util.Some(now)),
// 		LastResponseCode: util.Some(util.Some(statusCode)),
// 		LastResponseBody: util.Some(util.Some(respBody)),
// 	})
// 	if err != nil {
// 		logger.Error("Failed to mark delivery as success", "delivery_id", delivery.ID, "error", err)
// 		return err
// 	}

// 	logger.Info("Webhook delivered successfully",
// 		"delivery_id", delivery.ID,
// 		"url", delivery.URL,
// 		"status_code", statusCode,
// 		"retry_count", delivery.RetryCount+1)

// 	return nil
// }

// // scheduleRetry schedules a webhook delivery for retry or marks it as failed if max retries exceeded
// func scheduleRetry(ctx context.Context, db *database.Database, logger *slog.Logger, delivery database.WebhookDelivery, statusCode int, respBody string) error {
// 	newRetryCount := delivery.RetryCount + 1
// 	now := time.Now()

// 	// Calculate next retry time using exponential backoff
// 	backoffDuration := time.Duration(float64(initialBackoff) * float64(newRetryCount) * backoffMultiplier)
// 	nextAttempt := now.Add(backoffDuration)

// 	var status database.WebhookDeliveryStatus
// 	var nextAttemptPtr util.Optional[time.Time]

// 	if newRetryCount >= maxRetries {
// 		// Max retries exceeded - mark as failed
// 		status = database.WebhookDeliveryStatusFailed
// 		nextAttemptPtr = util.Optional[time.Time]{} // No next attempt
// 		logger.Warn("Webhook delivery failed permanently",
// 			"delivery_id", delivery.ID,
// 			"url", delivery.URL,
// 			"retry_count", newRetryCount,
// 			"status_code", statusCode)
// 	} else {
// 		// Schedule for retry
// 		status = database.WebhookDeliveryStatusPending
// 		nextAttemptPtr = util.Some(nextAttempt)
// 		logger.Info("Scheduling webhook retry",
// 			"delivery_id", delivery.ID,
// 			"url", delivery.URL,
// 			"retry_count", newRetryCount,
// 			"next_attempt", nextAttempt.Format(time.RFC3339),
// 			"status_code", statusCode)
// 	}

// 	// Update delivery record
// 	err := db.UpdateWebhookDeliveryByID(ctx, delivery.ID, database.UpdateWebhookDeliveryParams{
// 		Status:           util.Some(status),
// 		RetryCount:       util.Some(newRetryCount),
// 		LastAttemptAt:    util.Some(util.Some(now)),
// 		LastResponseCode: util.Some(util.Some(statusCode)),
// 		LastResponseBody: util.Some(util.Some(respBody)),
// 		NextAttemptAt:    util.Some(nextAttemptPtr),
// 	})
// 	if err != nil {
// 		logger.Error("Failed to update delivery for retry", "delivery_id", delivery.ID, "error", err)
// 		return err
// 	}

// 	return nil
// }
