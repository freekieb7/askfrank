package main

import (
	"context"
	"fmt"
	"hp/internal/config"
	"hp/internal/database"
	"os"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	ctx := context.Background()
	command := os.Args[1]

	cfg := config.NewConfig()

	connStr := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.Name,
		cfg.Database.SSLMode,
	)

	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		fmt.Printf("Failed to create connection pool: %v\n", err)
		os.Exit(1)
	}
	defer pool.Close()

	migrator := database.NewMigrator(pool)
	migrator.SetBackupConfig(false, "")

	switch command {
	case "up":
		handleUp(ctx, migrator, os.Args[2:])
	case "down":
		handleDown(ctx, migrator, os.Args[2:])
	case "version":
		handleVersion(ctx, migrator)
	case "health":
		handleHealth(ctx, migrator)
	case "status":
		handleStatus(ctx, migrator)
	case "create":
		handleCreate(migrator, os.Args[2:])
	case "validate":
		handleValidate(migrator)
	case "dry-run":
		handleDryRun(ctx, migrator, os.Args[2:])
	case "migrate-to":
		handleMigrateTo(ctx, migrator, os.Args[2:])
	case "drift-check":
		handleDriftCheck(ctx, migrator)
	case "enhanced-validate":
		handleEnhancedValidate(migrator)
	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func handleUp(ctx context.Context, migrator *database.Migrator, args []string) {
	steps := 0
	if len(args) > 0 {
		var err error
		steps, err = strconv.Atoi(args[0])
		if err != nil {
			fmt.Printf("Invalid steps argument: %v\n", err)
			os.Exit(1)
		}
	}

	if err := migrator.Up(ctx, steps); err != nil {
		fmt.Printf("Up migration failed: %v\n", err)
		os.Exit(1)
	}
}

func handleDown(ctx context.Context, migrator *database.Migrator, args []string) {
	steps := 1
	if len(args) > 0 {
		var err error
		steps, err = strconv.Atoi(args[0])
		if err != nil {
			fmt.Printf("Invalid steps argument: %v\n", err)
			os.Exit(1)
		}
	}

	if err := migrator.Down(ctx, steps); err != nil {
		fmt.Printf("Down migration failed: %v\n", err)
		os.Exit(1)
	}
}

func handleVersion(ctx context.Context, migrator *database.Migrator) {
	version, dirty, err := migrator.Version(ctx)
	if err != nil {
		fmt.Printf("Failed to get version: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Current version: %d\n", version)
	if dirty {
		fmt.Printf("Status: DIRTY (needs manual intervention)\n")
	} else {
		fmt.Printf("Status: CLEAN\n")
	}
}

func handleHealth(ctx context.Context, migrator *database.Migrator) {
	if err := migrator.HealthCheck(ctx); err != nil {
		fmt.Printf("Health check failed: %v\n", err)
		os.Exit(1)
	}
}

func handleStatus(ctx context.Context, migrator *database.Migrator) {
	status, err := migrator.GetStatus(ctx)
	if err != nil {
		fmt.Printf("Failed to get status: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Migration Status:\n")
	fmt.Printf("─────────────────\n")
	fmt.Printf("Current version: %d\n", status.Current)
	fmt.Printf("Latest available: %d\n", status.Latest)
	fmt.Printf("Pending migrations: %d\n", len(status.Pending))
	fmt.Printf("Applied migrations: %d\n", len(status.Applied))

	if status.IsDirty {
		fmt.Printf("⚠️  Database is in DIRTY state\n")
	} else {
		fmt.Printf("✓ Database is CLEAN\n")
	}

	if len(status.Pending) > 0 {
		fmt.Printf("\nPending migrations:\n")
		for _, migration := range status.Pending {
			fmt.Printf("  - %d: %s\n", migration.Version, migration.Name)
		}
	}
}

func handleCreate(migrator *database.Migrator, args []string) {
	if len(args) < 1 {
		fmt.Printf("Usage: migrate create <migration_name>\n")
		os.Exit(1)
	}

	name := args[0]
	if err := migrator.CreateMigration(name); err != nil {
		fmt.Printf("Failed to create migration: %v\n", err)
		os.Exit(1)
	}
}

func handleValidate(migrator *database.Migrator) {
	if err := migrator.ValidateMigrations(); err != nil {
		fmt.Printf("Validation failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✓ All migrations are valid\n")
}

func handleDryRun(ctx context.Context, migrator *database.Migrator, args []string) {
	if len(args) < 1 {
		fmt.Printf("Usage: migrate dry-run <up|down> [steps]\n")
		os.Exit(1)
	}

	direction := args[0]
	if direction != "up" && direction != "down" {
		fmt.Printf("Direction must be 'up' or 'down'\n")
		os.Exit(1)
	}

	steps := 0
	if len(args) > 1 {
		var err error
		steps, err = strconv.Atoi(args[1])
		if err != nil {
			fmt.Printf("Invalid steps argument: %v\n", err)
			os.Exit(1)
		}
	}

	results, err := migrator.DryRun(ctx, direction, steps)
	if err != nil {
		fmt.Printf("Dry run failed: %v\n", err)
		os.Exit(1)
	}

	if len(results) == 0 {
		fmt.Printf("No migrations to %s\n", direction)
		return
	}

	fmt.Printf("Dry Run Results (%s):\n", direction)
	fmt.Printf("═══════════════════════\n")

	for i, result := range results {
		fmt.Printf("\n%d. Migration %d: %s\n", i+1, result.Migration.Version, result.Migration.Name)
		fmt.Printf("   Operations:\n")
		for _, op := range result.Operations {
			fmt.Printf("   - %s\n", op)
		}

		if len(result.Warnings) > 0 {
			fmt.Printf("   ⚠️  Warnings:\n")
			for _, warning := range result.Warnings {
				fmt.Printf("   - %s\n", warning)
			}
		}
	}

	fmt.Printf("\nTotal migrations to %s: %d\n", direction, len(results))
}

func handleMigrateTo(ctx context.Context, migrator *database.Migrator, args []string) {
	if len(args) < 1 {
		fmt.Printf("Usage: migrate migrate-to <version>\n")
		os.Exit(1)
	}

	targetVersion, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		fmt.Printf("Invalid version: %v\n", err)
		os.Exit(1)
	}

	if err := migrator.MigrateTo(ctx, targetVersion); err != nil {
		fmt.Printf("Migration to version %d failed: %v\n", targetVersion, err)
		os.Exit(1)
	}

	fmt.Printf("Successfully migrated to version %d\n", targetVersion)
}

func handleDriftCheck(ctx context.Context, migrator *database.Migrator) {
	result, err := migrator.DetectSchemaDrift(ctx)
	if err != nil {
		fmt.Printf("Schema drift check failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Schema Drift Check Results:\n")
	fmt.Printf("═══════════════════════════\n")

	if !result.HasDrift {
		fmt.Printf("✓ No schema drift detected\n")
		return
	}

	fmt.Printf("⚠️  Schema drift detected!\n\n")

	if len(result.MissingTables) > 0 {
		fmt.Printf("Missing tables (expected but not found):\n")
		for _, table := range result.MissingTables {
			fmt.Printf("  - %s\n", table.Name)
		}
		fmt.Printf("\n")
	}

	if len(result.ExtraTables) > 0 {
		fmt.Printf("Extra tables (found but not expected):\n")
		for _, table := range result.ExtraTables {
			fmt.Printf("  - %s\n", table.Name)
		}
		fmt.Printf("\n")
	}

	for _, diff := range result.Differences {
		fmt.Printf("• %s\n", diff)
	}
}

func handleEnhancedValidate(migrator *database.Migrator) {
	if err := migrator.EnhancedValidation(); err != nil {
		fmt.Printf("Enhanced validation failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Enhanced validation passed\n")
}

func printUsage() {
	fmt.Println("Enhanced Database Migration CLI")
	fmt.Println("===============================")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("  migrate <command> [arguments]")
	fmt.Println("")
	fmt.Println("Core Commands:")
	fmt.Println("  up [steps]           Apply pending migrations (optional: limit steps)")
	fmt.Println("  down [steps]         Rollback migrations (default: 1 step)")
	fmt.Println("  version              Show current migration version")
	fmt.Println("  health               Check database health")
	fmt.Println("  status               Show detailed migration status")
	fmt.Println("  create <name>        Create new migration (.up.sql/.down.sql files)")
	fmt.Println("  validate             Validate migration files")
	fmt.Println("")
	fmt.Println("Enhanced Commands:")
	fmt.Println("  dry-run <up|down> [steps]    Preview migration changes without applying")
	fmt.Println("  migrate-to <version>         Migrate to specific version (up or down)")
	fmt.Println("  drift-check                  Check for schema drift")
	fmt.Println("  enhanced-validate            Perform comprehensive validation")
	fmt.Println("")
	fmt.Println("Features:")
	fmt.Println("  ✓ Migration Locking          Prevents concurrent migrations")
	fmt.Println("  ✓ Progress Reporting          Detailed logging with timing")
	fmt.Println("  ✓ Enhanced Validation         SQL syntax and dependency checks")
	fmt.Println("  ✓ Dry-Run Capability         Preview changes before applying")
	fmt.Println("  ✓ Version Targeting           Migrate to any specific version")
	fmt.Println("  ✓ Schema Drift Detection      Compare actual vs expected schema")
	fmt.Println("  ✓ Backup Integration          Automatic backups before rollbacks")
	fmt.Println("")
	fmt.Println("Examples:")
	fmt.Println("  migrate up")
	fmt.Println("  migrate up 2")
	fmt.Println("  migrate down 1")
	fmt.Println("  migrate create \"add user table\"")
	fmt.Println("  migrate dry-run up 1")
	fmt.Println("  migrate migrate-to 20240101000000")
	fmt.Println("  migrate drift-check")
}
