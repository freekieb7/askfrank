package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/freekieb7/askfrank/internal/database"
)

func CleanupTask(db *database.Database, logger *slog.Logger) DaemonFunc {
	return func(ctx context.Context, name string) error {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				fmt.Printf("%s shutting down...\n", name)
				return nil
			case <-ticker.C:
				// if err := db.DeleteExpiredOAuthData(ctx); err != nil {
				// 	logger.Error("Failed to delete expired OAuth data", "error", err)
				// 	// continue, but log for audit
				// }
			}
		}
	}
}
