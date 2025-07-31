#!/bin/bash

# Monthly usage overage processing script
# Run this script monthly (e.g., via cron) to charge users for overages

set -e

# Configuration
DATABASE_URL="${DATABASE_URL:-postgres://user:password@localhost/askfrank?sslmode=disable}"
STRIPE_SECRET_KEY="${STRIPE_SECRET_KEY}"

if [ -z "$STRIPE_SECRET_KEY" ]; then
    echo "Error: STRIPE_SECRET_KEY environment variable is required"
    exit 1
fi

echo "Starting monthly overage processing..."

# Create a temporary Go script to process overages
cat > /tmp/process_overages.go << 'EOF'
package main

import (
    "askfrank/internal/config"
    "askfrank/internal/database"
    "askfrank/internal/repository"
    "askfrank/internal/service"
    "context"
    "fmt"
    "log"
    "log/slog"
    "os"
)

func main() {
    // Load configuration
    cfg := config.Load()
    
    // Setup logger
    logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
    
    // Connect to database
    dataSourceName := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
        cfg.Database.Host, cfg.Database.Port, cfg.Database.User, cfg.Database.Password, cfg.Database.Name, cfg.Database.SSLMode)
    db, err := database.NewPostgresDatabase(dataSourceName)
    if err != nil {
        log.Fatalf("Failed to connect to database: %v", err)
    }
    
    // Initialize repository and services
    repo := repository.NewPostgresRepository(db)
    usageService := service.NewUsageService(repo, logger)
    
    // Get all active subscriptions
    ctx := context.Background()
    subscriptions, err := repo.GetActiveSubscriptions(ctx)
    if err != nil {
        log.Fatalf("Failed to get active subscriptions: %v", err)
    }
    
    logger.Info("Processing overages for active subscriptions", "count", len(subscriptions))
    
    processed := 0
    failed := 0
    
    for _, subscription := range subscriptions {
        err := usageService.ProcessMonthlyOverages(ctx, subscription.UserID)
        if err != nil {
            logger.Error("Failed to process overages", "user_id", subscription.UserID, "error", err)
            failed++
        } else {
            processed++
        }
    }
    
    logger.Info("Overage processing completed", 
        "processed", processed, 
        "failed", failed, 
        "total", len(subscriptions))
}
EOF

# Run the overage processing
cd /path/to/your/askfrank/project
go run /tmp/process_overages.go

# Clean up
rm /tmp/process_overages.go

echo "Monthly overage processing completed"
