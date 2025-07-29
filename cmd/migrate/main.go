package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"askfrank/internal/config"
	"askfrank/internal/database"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/lib/pq"
)

func main() {
	var (
		command = flag.String("command", "", "Migration command: up, down, version, force, create")
		steps   = flag.Int("steps", 0, "Number of migration steps (for up/down)")
		version = flag.Int("version", 0, "Migration version (for force/goto)")
		name    = flag.String("name", "", "Migration name (for create)")
	)
	flag.Parse()

	if *command == "" {
		fmt.Println("Usage: go run cmd/migrate/main.go -command [up|down|version|force|create] [options]")
		fmt.Println("Commands:")
		fmt.Println("  up             - Apply all pending migrations")
		fmt.Println("  down           - Rollback migrations")
		fmt.Println("  version        - Show current migration version")
		fmt.Println("  force VERSION  - Force set migration version")
		fmt.Println("  create NAME    - Create new migration files")
		fmt.Println("")
		fmt.Println("Options:")
		fmt.Println("  -steps N       - Number of steps for up/down")
		fmt.Println("  -version N     - Version number for force")
		fmt.Println("  -name NAME     - Migration name for create")
		os.Exit(1)
	}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Create database connection string
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.Name,
		cfg.Database.SSLMode,
	)

	// Connect to database
	db, err := database.NewPostgresDatabase(dsn)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("Failed to close database connection: %v", err)
		}
	}()

	// Create migration instance
	driver, err := postgres.WithInstance(db.DB, &postgres.Config{})
	if err != nil {
		log.Fatalf("Failed to create migration driver: %v", err)
	}

	m, err := migrate.NewWithDatabaseInstance(
		"file://migrations",
		"postgres", driver)
	if err != nil {
		log.Fatalf("Failed to create migration instance: %v", err)
	}
	defer func() {
		if _, err := m.Close(); err != nil {
			log.Printf("Failed to close migration instance: %v", err)
		}
	}()

	// Execute command
	switch *command {
	case "up":
		if *steps > 0 {
			err = m.Steps(*steps)
		} else {
			err = m.Up()
		}
		if err != nil && err != migrate.ErrNoChange {
			log.Fatalf("Migration up failed: %v", err)
		}
		if err == migrate.ErrNoChange {
			fmt.Println("No migrations to apply")
		} else {
			fmt.Println("Migrations applied successfully")
		}

	case "down":
		if *steps > 0 {
			err = m.Steps(-*steps)
		} else {
			err = m.Steps(-1) // Default to 1 step down
		}
		if err != nil && err != migrate.ErrNoChange {
			log.Fatalf("Migration down failed: %v", err)
		}
		if err == migrate.ErrNoChange {
			fmt.Println("No migrations to rollback")
		} else {
			fmt.Println("Migrations rolled back successfully")
		}

	case "version":
		v, dirty, err := m.Version()
		if err != nil {
			log.Fatalf("Failed to get version: %v", err)
		}
		fmt.Printf("Current version: %d\n", v)
		if dirty {
			fmt.Println("⚠️  Database is in dirty state")
		} else {
			fmt.Println("✅ Database is clean")
		}

	case "force":
		if *version == 0 {
			log.Fatal("Version number required for force command")
		}
		err = m.Force(*version)
		if err != nil {
			log.Fatalf("Force migration failed: %v", err)
		}
		fmt.Printf("Migration version forced to %d\n", *version)

	case "create":
		if *name == "" {
			log.Fatal("Migration name required for create command")
		}

		// Create migration files using golang-migrate
		nextNum := getNextMigrationNumber()
		upFile := fmt.Sprintf("migrations/%06d_%s.up.sql", nextNum, *name)
		downFile := fmt.Sprintf("migrations/%06d_%s.down.sql", nextNum, *name)

		// Create up migration file
		err = os.WriteFile(upFile, []byte("-- Migration up\n\n"), 0644)
		if err != nil {
			log.Fatalf("Failed to create up migration file: %v", err)
		}

		// Create down migration file
		err = os.WriteFile(downFile, []byte("-- Migration down\n\n"), 0644)
		if err != nil {
			log.Fatalf("Failed to create down migration file: %v", err)
		}

		fmt.Printf("Created migration files:\n")
		fmt.Printf("  %s\n", upFile)
		fmt.Printf("  %s\n", downFile)

	default:
		log.Fatalf("Unknown command: %s", *command)
	}
}

// getNextMigrationNumber returns the next migration number based on existing files
func getNextMigrationNumber() int {
	files, err := os.ReadDir("migrations")
	if err != nil {
		return 1
	}

	maxNum := 0
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		var num int
		_, err := fmt.Sscanf(file.Name(), "%d_", &num)
		if err == nil && num > maxNum {
			maxNum = num
		}
	}

	return maxNum + 1
}
