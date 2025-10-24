package migrations

import (
	"context"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Migrator struct {
	pool           *pgxpool.Pool
	migrationsPath string
	lockTimeout    time.Duration
	logger         *log.Logger
	enableBackup   bool
	backupPath     string
}

type Migration struct {
	Version      int64
	Name         string
	UpSQL        string
	DownSQL      string
	Timestamp    time.Time
	UpFilePath   string
	DownFilePath string
}

type MigrationRecord struct {
	Version   int64
	Dirty     bool
	AppliedAt time.Time
}

type MigrationStatus struct {
	Current int64
	Latest  int64
	Pending []Migration
	Applied []MigrationRecord
	IsDirty bool
}

// DryRunResult represents the result of a dry-run migration
type DryRunResult struct {
	Migration    Migration
	Operations   []string
	EstimatedSQL string
	Warnings     []string
}

// ProgressInfo represents migration progress information
type ProgressInfo struct {
	Current     int
	Total       int
	Migration   Migration
	StartTime   time.Time
	ElapsedTime time.Duration
}

// SchemaObject represents a database schema object for drift detection
type SchemaObject struct {
	Type   string
	Name   string
	Schema string
	SQL    string
}

// DriftResult represents schema drift detection results
type DriftResult struct {
	HasDrift      bool
	MissingTables []SchemaObject
	ExtraTables   []SchemaObject
	Differences   []string
}

func NewMigrator(pool *pgxpool.Pool) *Migrator {
	return &Migrator{
		pool:           pool,
		migrationsPath: "internal/database/migrations/versions",
		lockTimeout:    time.Minute * 5,
		logger:         log.New(os.Stdout, "[MIGRATOR] ", log.LstdFlags),
		enableBackup:   true,
		backupPath:     "backups",
	}
}

// SetBackupConfig configures backup settings
func (m *Migrator) SetBackupConfig(enabled bool, path string) {
	m.enableBackup = enabled
	m.backupPath = path
}

// SetLogger sets a custom logger
func (m *Migrator) SetLogger(logger *log.Logger) {
	m.logger = logger
}

func (m *Migrator) SetMigrationsPath(path string) {
	m.migrationsPath = path
}

// Initialize creates the schema_migrations table if it doesn't exist
func (m *Migrator) Initialize(ctx context.Context) error {
	query := `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version BIGINT PRIMARY KEY,
			dirty BOOLEAN NOT NULL DEFAULT FALSE,
			applied_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		);
	`
	_, err := m.pool.Exec(ctx, query)
	return err
}

// acquireLock acquires an advisory lock to prevent concurrent migrations
func (m *Migrator) acquireLock(ctx context.Context) error {
	const lockID = 1234567890 // Unique ID for migration lock

	// Try to acquire the lock with timeout
	lockCtx, cancel := context.WithTimeout(ctx, m.lockTimeout)
	defer cancel()

	var acquired bool
	err := m.pool.QueryRow(lockCtx, "SELECT pg_try_advisory_lock($1)", lockID).Scan(&acquired)
	if err != nil {
		return fmt.Errorf("failed to acquire migration lock: %w", err)
	}

	if !acquired {
		return fmt.Errorf("migration lock is held by another process (timeout: %v)", m.lockTimeout)
	}

	m.logger.Println("Acquired migration lock")
	return nil
}

// releaseLock releases the advisory lock
func (m *Migrator) releaseLock(ctx context.Context) error {
	const lockID = 1234567890

	var released bool
	err := m.pool.QueryRow(ctx, "SELECT pg_advisory_unlock($1)", lockID).Scan(&released)
	if err != nil {
		return fmt.Errorf("failed to release migration lock: %w", err)
	}

	if !released {
		m.logger.Println("Warning: migration lock was not held when trying to release")
	} else {
		m.logger.Println("Released migration lock")
	}

	return nil
}

// createBackup creates a database backup before destructive operations
func (m *Migrator) createBackup(ctx context.Context, operation string) (string, error) {
	if !m.enableBackup {
		return "", nil
	}

	// Ensure backup directory exists
	if err := os.MkdirAll(m.backupPath, 0755); err != nil {
		return "", fmt.Errorf("failed to create backup directory: %w", err)
	}

	timestamp := time.Now().Format("20060102_150405")
	backupFile := filepath.Join(m.backupPath, fmt.Sprintf("backup_%s_%s.sql", operation, timestamp))

	// Get database connection info from the pool
	config := m.pool.Config()
	connConfig := config.ConnConfig

	cmd := exec.CommandContext(ctx, "pg_dump",
		"-h", connConfig.Host,
		"-p", fmt.Sprintf("%d", connConfig.Port),
		"-U", connConfig.User,
		"-d", connConfig.Database,
		"-f", backupFile,
		"--no-password",
		"--verbose")

	// Set PGPASSWORD environment variable
	cmd.Env = append(os.Environ(), fmt.Sprintf("PGPASSWORD=%s", connConfig.Password))

	m.logger.Printf("Creating backup: %s", backupFile)
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("backup failed: %w", err)
	}

	m.logger.Printf("Backup created successfully: %s", backupFile)
	return backupFile, nil
}

// Up runs pending migrations with locking and progress reporting
func (m *Migrator) Up(ctx context.Context, steps int) error {
	if err := m.Initialize(ctx); err != nil {
		return fmt.Errorf("failed to initialize migration table: %w", err)
	}

	// Acquire lock
	if err := m.acquireLock(ctx); err != nil {
		return err
	}
	defer func() {
		if err := m.releaseLock(ctx); err != nil {
			m.logger.Printf("Failed to release lock: %v", err)
		}
	}()

	migrations, err := m.loadMigrations()
	if err != nil {
		return fmt.Errorf("failed to load migrations: %w", err)
	}

	appliedVersions, err := m.getAppliedVersions(ctx)
	if err != nil {
		return fmt.Errorf("failed to get applied versions: %w", err)
	}

	pendingMigrations := []Migration{}
	for _, migration := range migrations {
		if !contains(appliedVersions, migration.Version) {
			pendingMigrations = append(pendingMigrations, migration)
		}
	}

	if len(pendingMigrations) == 0 {
		m.logger.Println("No pending migrations")
		return nil
	}

	// Sort by version
	sort.Slice(pendingMigrations, func(i, j int) bool {
		return pendingMigrations[i].Version < pendingMigrations[j].Version
	})

	// Limit steps if specified
	if steps > 0 && steps < len(pendingMigrations) {
		pendingMigrations = pendingMigrations[:steps]
	}

	m.logger.Printf("Applying %d migrations", len(pendingMigrations))
	startTime := time.Now()

	for i, migration := range pendingMigrations {
		progress := ProgressInfo{
			Current:   i + 1,
			Total:     len(pendingMigrations),
			Migration: migration,
			StartTime: startTime,
		}

		m.logger.Printf("Progress: %d/%d - Applying migration %d: %s",
			progress.Current, progress.Total, migration.Version, migration.Name)

		migrationStart := time.Now()
		if err := m.applyMigration(ctx, migration, true); err != nil {
			return fmt.Errorf("failed to apply migration %d: %w", migration.Version, err)
		}

		elapsed := time.Since(migrationStart)
		m.logger.Printf("✓ Applied migration %d: %s (took %v)",
			migration.Version, migration.Name, elapsed)
	}

	totalElapsed := time.Since(startTime)
	m.logger.Printf("Successfully applied %d migrations in %v", len(pendingMigrations), totalElapsed)
	return nil
}

// Down rolls back migrations with backup and locking
func (m *Migrator) Down(ctx context.Context, steps int) error {
	if err := m.Initialize(ctx); err != nil {
		return fmt.Errorf("failed to initialize migration table: %w", err)
	}

	// Acquire lock
	if err := m.acquireLock(ctx); err != nil {
		return err
	}
	defer func() {
		if err := m.releaseLock(ctx); err != nil {
			m.logger.Printf("Failed to release lock: %v", err)
		}
	}()

	// Create backup before rolling back
	backupFile, err := m.createBackup(ctx, "rollback")
	if err != nil {
		return fmt.Errorf("failed to create backup before rollback: %w", err)
	}
	if backupFile != "" {
		m.logger.Printf("Created backup before rollback: %s", backupFile)
	}

	migrations, err := m.loadMigrations()
	if err != nil {
		return fmt.Errorf("failed to load migrations: %w", err)
	}

	appliedVersions, err := m.getAppliedVersions(ctx)
	if err != nil {
		return fmt.Errorf("failed to get applied versions: %w", err)
	}

	if len(appliedVersions) == 0 {
		fmt.Println("No migrations to rollback")
		return nil
	}

	// Sort applied versions in descending order
	sort.Slice(appliedVersions, func(i, j int) bool {
		return appliedVersions[i] > appliedVersions[j]
	})

	// Limit steps
	if steps > len(appliedVersions) {
		steps = len(appliedVersions)
	}

	versionsToRollback := appliedVersions[:steps]

	for _, version := range versionsToRollback {
		migration := findMigrationByVersion(migrations, version)
		if migration == nil {
			return fmt.Errorf("migration file for version %d not found", version)
		}

		if err := m.applyMigration(ctx, *migration, false); err != nil {
			return fmt.Errorf("failed to rollback migration %d: %w", version, err)
		}
		fmt.Printf("✓ Rolled back migration %d: %s\n", migration.Version, migration.Name)
	}

	fmt.Printf("Successfully rolled back %d migration(s)\n", steps)
	return nil
}

// Version returns the current migration version and dirty state
func (m *Migrator) Version(ctx context.Context) (int64, bool, error) {
	if err := m.Initialize(ctx); err != nil {
		return 0, false, fmt.Errorf("failed to initialize migration table: %w", err)
	}

	query := `
		SELECT version, dirty 
		FROM schema_migrations 
		ORDER BY version DESC 
		LIMIT 1
	`

	var version int64
	var dirty bool
	err := m.pool.QueryRow(ctx, query).Scan(&version, &dirty)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return 0, false, nil
		}
		return 0, false, err
	}

	return version, dirty, nil
}

// HealthCheck verifies database connectivity and migration table health
func (m *Migrator) HealthCheck(ctx context.Context) error {
	// Test basic connectivity
	if err := m.pool.Ping(ctx); err != nil {
		return fmt.Errorf("database ping failed: %w", err)
	}

	// Test migration table
	if err := m.Initialize(ctx); err != nil {
		return fmt.Errorf("migration table check failed: %w", err)
	}

	// Check for dirty migrations
	status, err := m.GetStatus(ctx)
	if err != nil {
		return fmt.Errorf("status check failed: %w", err)
	}

	if status.IsDirty {
		return fmt.Errorf("database is in dirty state - manual intervention required")
	}

	fmt.Printf("Database health: OK\n")
	fmt.Printf("Current version: %d\n", status.Current)
	fmt.Printf("Latest available: %d\n", status.Latest)
	fmt.Printf("Pending migrations: %d\n", len(status.Pending))

	return nil
}

// GetStatus returns comprehensive migration status
func (m *Migrator) GetStatus(ctx context.Context) (*MigrationStatus, error) {
	if err := m.Initialize(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize migration table: %w", err)
	}

	migrations, err := m.loadMigrations()
	if err != nil {
		return nil, fmt.Errorf("failed to load migrations: %w", err)
	}

	appliedRecords, err := m.getAppliedMigrations(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get applied migrations: %w", err)
	}

	appliedVersions := make(map[int64]bool)
	var isDirty bool
	var current int64

	for _, record := range appliedRecords {
		appliedVersions[record.Version] = true
		if record.Dirty {
			isDirty = true
		}
		if record.Version > current {
			current = record.Version
		}
	}

	var pending []Migration
	var latest int64

	for _, migration := range migrations {
		if migration.Version > latest {
			latest = migration.Version
		}
		if !appliedVersions[migration.Version] {
			pending = append(pending, migration)
		}
	}

	// Sort pending migrations by version
	sort.Slice(pending, func(i, j int) bool {
		return pending[i].Version < pending[j].Version
	})

	return &MigrationStatus{
		Current: current,
		Latest:  latest,
		Pending: pending,
		Applied: appliedRecords,
		IsDirty: isDirty,
	}, nil
}

// getAppliedMigrations returns all applied migration records
func (m *Migrator) getAppliedMigrations(ctx context.Context) ([]MigrationRecord, error) {
	query := "SELECT version, dirty, applied_at FROM schema_migrations ORDER BY version"
	rows, err := m.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := []MigrationRecord{}
	for rows.Next() {
		var record MigrationRecord
		if err := rows.Scan(&record.Version, &record.Dirty, &record.AppliedAt); err != nil {
			return nil, err
		}
		records = append(records, record)
	}

	return records, rows.Err()
}

// CreateMigration creates a new migration file (defaults to separated files)
func (m *Migrator) CreateMigration(name string) error {
	// Generate timestamp
	timestamp := time.Now().Format("20060102150405")

	// Clean migration name
	cleanName := strings.ReplaceAll(name, " ", "_")
	cleanName = strings.ToLower(cleanName)

	// Create directory if it doesn't exist
	if err := os.MkdirAll(m.migrationsPath, 0755); err != nil {
		return fmt.Errorf("failed to create migrations directory: %w", err)
	}

	return m.createSeparatedMigrationFiles(timestamp, cleanName, name)
}

// createSeparatedMigrationFiles creates separate .up.sql and .down.sql files
func (m *Migrator) createSeparatedMigrationFiles(timestamp, cleanName, originalName string) error {
	baseFilename := fmt.Sprintf("%s_%s", timestamp, cleanName)
	upFilePath := filepath.Join(m.migrationsPath, baseFilename+".up.sql")
	downFilePath := filepath.Join(m.migrationsPath, baseFilename+".down.sql")

	// Create UP migration template
	upTemplate := fmt.Sprintf(`-- Migration: %s (UP)
-- Created: %s
-- Version: %s

`, originalName, time.Now().Format("2006-01-02 15:04:05"), timestamp)

	// Create DOWN migration template
	downTemplate := fmt.Sprintf(`-- Migration: %s (DOWN)
-- Created: %s
-- Version: %s

`, originalName, time.Now().Format("2006-01-02 15:04:05"), timestamp)

	// Write UP file
	if err := os.WriteFile(upFilePath, []byte(upTemplate), 0644); err != nil {
		return fmt.Errorf("failed to create up migration file: %w", err)
	}

	// Write DOWN file
	if err := os.WriteFile(downFilePath, []byte(downTemplate), 0644); err != nil {
		return fmt.Errorf("failed to create down migration file: %w", err)
	}

	fmt.Printf("✓ Created migration files:\n")
	fmt.Printf("  - %s\n", upFilePath)
	fmt.Printf("  - %s\n", downFilePath)
	return nil
}

// ValidateMigrations checks migration files for issues
func (m *Migrator) ValidateMigrations() error {
	migrations, err := m.loadMigrations()
	if err != nil {
		return fmt.Errorf("failed to load migrations: %w", err)
	}

	if len(migrations) == 0 {
		fmt.Println("✓ No migrations found")
		return nil
	}

	var issues []string
	versionMap := make(map[int64]bool)

	for _, migration := range migrations {
		// Check for duplicate versions
		if versionMap[migration.Version] {
			issues = append(issues, fmt.Sprintf("Duplicate version: %d", migration.Version))
		}
		versionMap[migration.Version] = true

		// Check for empty SQL
		if strings.TrimSpace(migration.UpSQL) == "" {
			issues = append(issues, fmt.Sprintf("Version %d: Empty UP SQL", migration.Version))
		}
		if strings.TrimSpace(migration.DownSQL) == "" {
			issues = append(issues, fmt.Sprintf("Version %d: Empty DOWN SQL", migration.Version))
		}
	}

	if len(issues) > 0 {
		fmt.Printf("❌ Found %d validation issue(s):\n", len(issues))
		for _, issue := range issues {
			fmt.Printf("  - %s\n", issue)
		}
		return fmt.Errorf("migration validation failed")
	}

	fmt.Printf("✓ Validated %d migration(s) - no issues found\n", len(migrations))
	return nil
}

// applyMigration applies or rolls back a single migration
func (m *Migrator) applyMigration(ctx context.Context, migration Migration, up bool) error {
	tx, err := m.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Mark as dirty
	if up {
		_, err = tx.Exec(ctx, "INSERT INTO schema_migrations (version, dirty) VALUES ($1, TRUE) ON CONFLICT (version) DO UPDATE SET dirty = TRUE", migration.Version)
	} else {
		_, err = tx.Exec(ctx, "UPDATE schema_migrations SET dirty = TRUE WHERE version = $1", migration.Version)
	}
	if err != nil {
		return err
	}

	// Apply the migration
	var sql string
	if up {
		sql = migration.UpSQL
	} else {
		sql = migration.DownSQL
	}

	if strings.TrimSpace(sql) != "" {
		_, err = tx.Exec(ctx, sql)
		if err != nil {
			return fmt.Errorf("migration SQL failed: %w", err)
		}
	}

	// Mark as clean or remove record
	if up {
		_, err = tx.Exec(ctx, "UPDATE schema_migrations SET dirty = FALSE, applied_at = NOW() WHERE version = $1", migration.Version)
	} else {
		_, err = tx.Exec(ctx, "DELETE FROM schema_migrations WHERE version = $1", migration.Version)
	}
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// loadMigrations loads all migration files from the migrations directory (separated files only)
func (m *Migrator) loadMigrations() ([]Migration, error) {
	migrations := []Migration{}

	if _, err := os.Stat(m.migrationsPath); os.IsNotExist(err) {
		return migrations, nil // Return empty slice if directory doesn't exist
	}

	// Track migrations by version to combine up/down files
	migrationMap := make(map[int64]*Migration)

	err := filepath.WalkDir(m.migrationsPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || !strings.HasSuffix(path, ".sql") {
			return nil
		}

		filename := d.Name()

		// Only process separated files (.up.sql or .down.sql)
		if strings.HasSuffix(filename, ".up.sql") || strings.HasSuffix(filename, ".down.sql") {
			return m.processSeparatedMigrationFile(path, filename, migrationMap)
		} else {
			// Skip any other .sql files (legacy combined format not supported)
			fmt.Printf("⚠️  Skipping unsupported file format: %s (only .up.sql/.down.sql files are supported)\n", filename)
			return nil
		}
	})

	if err != nil {
		return nil, err
	}

	// Add separated migrations to the list
	for _, migration := range migrationMap {
		migrations = append(migrations, *migration)
	}

	// Sort by version
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})

	return migrations, nil
}

// processSeparatedMigrationFile processes .up.sql and .down.sql files
func (m *Migrator) processSeparatedMigrationFile(path, filename string, migrationMap map[int64]*Migration) error {
	var isUp bool
	var baseFilename string

	if strings.HasSuffix(filename, ".up.sql") {
		isUp = true
		baseFilename = strings.TrimSuffix(filename, ".up.sql")
	} else {
		isUp = false
		baseFilename = strings.TrimSuffix(filename, ".down.sql")
	}

	// Parse version and name from base filename
	parts := strings.SplitN(baseFilename, "_", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid separated migration filename format: %s (expected: YYYYMMDDHHMMSS_migration_name.up/down.sql)", filename)
	}

	version, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid version in filename: %s", parts[0])
	}

	name := strings.ReplaceAll(parts[1], "_", " ")

	// Read file content
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	// Get or create migration entry
	migration, exists := migrationMap[version]
	if !exists {
		migration = &Migration{
			Version: version,
			Name:    name,
		}
		migrationMap[version] = migration
	}

	// Set the appropriate SQL and file path
	if isUp {
		migration.UpSQL = strings.TrimSpace(string(content))
		migration.UpFilePath = path
	} else {
		migration.DownSQL = strings.TrimSpace(string(content))
		migration.DownFilePath = path
	}

	return nil
}

// getAppliedVersions returns all applied migration versions
func (m *Migrator) getAppliedVersions(ctx context.Context) ([]int64, error) {
	query := "SELECT version FROM schema_migrations WHERE dirty = FALSE ORDER BY version"
	rows, err := m.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	versions := []int64{}
	for rows.Next() {
		var version int64
		if err := rows.Scan(&version); err != nil {
			return nil, err
		}
		versions = append(versions, version)
	}

	return versions, rows.Err()
}

// Helper functions
func contains(slice []int64, item int64) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

func findMigrationByVersion(migrations []Migration, version int64) *Migration {
	for _, migration := range migrations {
		if migration.Version == version {
			return &migration
		}
	}
	return nil
}

// DryRun simulates migration execution without actually applying changes
func (m *Migrator) DryRun(ctx context.Context, direction string, steps int) ([]DryRunResult, error) {
	if err := m.Initialize(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize migration table: %w", err)
	}

	migrations, err := m.loadMigrations()
	if err != nil {
		return nil, fmt.Errorf("failed to load migrations: %w", err)
	}

	var targetMigrations []Migration
	if direction == "up" {
		appliedVersions, err := m.getAppliedVersions(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get applied versions: %w", err)
		}

		for _, migration := range migrations {
			if !contains(appliedVersions, migration.Version) {
				targetMigrations = append(targetMigrations, migration)
			}
		}

		sort.Slice(targetMigrations, func(i, j int) bool {
			return targetMigrations[i].Version < targetMigrations[j].Version
		})
	} else {
		appliedVersions, err := m.getAppliedVersions(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get applied versions: %w", err)
		}

		for _, version := range appliedVersions {
			migration := findMigrationByVersion(migrations, version)
			if migration != nil {
				targetMigrations = append(targetMigrations, *migration)
			}
		}

		sort.Slice(targetMigrations, func(i, j int) bool {
			return targetMigrations[i].Version > targetMigrations[j].Version
		})
	}

	if steps > 0 && steps < len(targetMigrations) {
		targetMigrations = targetMigrations[:steps]
	}

	results := make([]DryRunResult, len(targetMigrations))
	for i, migration := range targetMigrations {
		sql := migration.UpSQL
		if direction == "down" {
			sql = migration.DownSQL
		}

		results[i] = DryRunResult{
			Migration:    migration,
			Operations:   m.parseOperations(sql),
			EstimatedSQL: sql,
			Warnings:     m.analyzeWarnings(sql),
		}
	}

	return results, nil
}

// parseOperations extracts SQL operations from migration content
func (m *Migrator) parseOperations(sql string) []string {
	operations := []string{}

	// Simple regex patterns for common operations
	patterns := map[string]*regexp.Regexp{
		"CREATE TABLE": regexp.MustCompile(`(?i)CREATE\s+TABLE\s+(\w+)`),
		"DROP TABLE":   regexp.MustCompile(`(?i)DROP\s+TABLE\s+(\w+)`),
		"ALTER TABLE":  regexp.MustCompile(`(?i)ALTER\s+TABLE\s+(\w+)`),
		"CREATE INDEX": regexp.MustCompile(`(?i)CREATE\s+(?:UNIQUE\s+)?INDEX\s+(\w+)`),
		"DROP INDEX":   regexp.MustCompile(`(?i)DROP\s+INDEX\s+(\w+)`),
	}

	for opType, pattern := range patterns {
		matches := pattern.FindAllStringSubmatch(sql, -1)
		for _, match := range matches {
			if len(match) > 1 {
				operations = append(operations, fmt.Sprintf("%s: %s", opType, match[1]))
			}
		}
	}

	if len(operations) == 0 {
		operations = append(operations, "Custom SQL operations")
	}

	return operations
}

// analyzeWarnings checks for potentially dangerous operations
func (m *Migrator) analyzeWarnings(sql string) []string {
	warnings := []string{}

	warningPatterns := map[string]string{
		`(?i)DROP\s+TABLE`:         "Destructive operation: DROP TABLE",
		`(?i)DROP\s+COLUMN`:        "Destructive operation: DROP COLUMN",
		`(?i)ALTER\s+COLUMN.*DROP`: "Destructive operation: DROP constraint/default",
		`(?i)TRUNCATE`:             "Destructive operation: TRUNCATE",
		`(?i)DELETE\s+FROM`:        "Potentially destructive: DELETE FROM",
	}

	for pattern, warning := range warningPatterns {
		re := regexp.MustCompile(pattern)
		if re.MatchString(sql) {
			warnings = append(warnings, warning)
		}
	}

	return warnings
}

// MigrateTo migrates to a specific version (up or down as needed)
func (m *Migrator) MigrateTo(ctx context.Context, targetVersion int64) error {
	if err := m.Initialize(ctx); err != nil {
		return fmt.Errorf("failed to initialize migration table: %w", err)
	}

	currentVersion, isDirty, err := m.Version(ctx)
	if err != nil {
		return fmt.Errorf("failed to get current version: %w", err)
	}

	if isDirty {
		return fmt.Errorf("database is in dirty state - cannot migrate")
	}

	if currentVersion == targetVersion {
		m.logger.Printf("Already at target version %d", targetVersion)
		return nil
	}

	// Acquire lock
	if err := m.acquireLock(ctx); err != nil {
		return err
	}
	defer func() {
		if err := m.releaseLock(ctx); err != nil {
			m.logger.Printf("Failed to release lock: %v", err)
		}
	}()

	if targetVersion > currentVersion {
		// Migrating up
		return m.migrateUp(ctx, currentVersion, targetVersion)
	} else {
		// Migrating down - create backup first
		backupFile, err := m.createBackup(ctx, fmt.Sprintf("migrate_to_%d", targetVersion))
		if err != nil {
			return fmt.Errorf("failed to create backup: %w", err)
		}
		if backupFile != "" {
			m.logger.Printf("Created backup: %s", backupFile)
		}
		return m.migrateDown(ctx, currentVersion, targetVersion)
	}
}

// migrateUp handles upward migration to target version
func (m *Migrator) migrateUp(ctx context.Context, currentVersion, targetVersion int64) error {
	migrations, err := m.loadMigrations()
	if err != nil {
		return fmt.Errorf("failed to load migrations: %w", err)
	}

	appliedVersions, err := m.getAppliedVersions(ctx)
	if err != nil {
		return fmt.Errorf("failed to get applied versions: %w", err)
	}

	pendingMigrations := []Migration{}
	for _, migration := range migrations {
		if migration.Version > currentVersion && migration.Version <= targetVersion {
			if !contains(appliedVersions, migration.Version) {
				pendingMigrations = append(pendingMigrations, migration)
			}
		}
	}

	sort.Slice(pendingMigrations, func(i, j int) bool {
		return pendingMigrations[i].Version < pendingMigrations[j].Version
	})

	m.logger.Printf("Migrating up from %d to %d (%d migrations)",
		currentVersion, targetVersion, len(pendingMigrations))

	for _, migration := range pendingMigrations {
		if err := m.applyMigration(ctx, migration, true); err != nil {
			return fmt.Errorf("failed to apply migration %d: %w", migration.Version, err)
		}
		m.logger.Printf("✓ Applied migration %d: %s", migration.Version, migration.Name)
	}

	return nil
}

// migrateDown handles downward migration to target version
func (m *Migrator) migrateDown(ctx context.Context, currentVersion, targetVersion int64) error {
	migrations, err := m.loadMigrations()
	if err != nil {
		return fmt.Errorf("failed to load migrations: %w", err)
	}

	appliedVersions, err := m.getAppliedVersions(ctx)
	if err != nil {
		return fmt.Errorf("failed to get applied versions: %w", err)
	}

	rollbackMigrations := []Migration{}
	for _, version := range appliedVersions {
		if version > targetVersion && version <= currentVersion {
			migration := findMigrationByVersion(migrations, version)
			if migration != nil {
				rollbackMigrations = append(rollbackMigrations, *migration)
			}
		}
	}

	sort.Slice(rollbackMigrations, func(i, j int) bool {
		return rollbackMigrations[i].Version > rollbackMigrations[j].Version
	})

	m.logger.Printf("Migrating down from %d to %d (%d migrations)",
		currentVersion, targetVersion, len(rollbackMigrations))

	for _, migration := range rollbackMigrations {
		if err := m.applyMigration(ctx, migration, false); err != nil {
			return fmt.Errorf("failed to rollback migration %d: %w", migration.Version, err)
		}
		m.logger.Printf("✓ Rolled back migration %d: %s", migration.Version, migration.Name)
	}

	return nil
}

// EnhancedValidation performs comprehensive validation of migrations
func (m *Migrator) EnhancedValidation() error {
	migrations, err := m.loadMigrations()
	if err != nil {
		return fmt.Errorf("failed to load migrations: %w", err)
	}

	errors := []string{}

	// Check for gaps in version numbers
	if err := m.validateVersionSequence(migrations); err != nil {
		errors = append(errors, err.Error())
	}

	// Check for orphaned files
	if err := m.validateOrphanedFiles(); err != nil {
		errors = append(errors, err.Error())
	}

	// Validate SQL syntax (basic check)
	for _, migration := range migrations {
		if err := m.validateSQL(migration); err != nil {
			errors = append(errors, fmt.Sprintf("Migration %d: %v", migration.Version, err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("validation failed:\n- %s", strings.Join(errors, "\n- "))
	}

	m.logger.Println("Enhanced validation passed")
	return nil
}

// validateVersionSequence checks for gaps in migration versions
func (m *Migrator) validateVersionSequence(migrations []Migration) error {
	if len(migrations) == 0 {
		return nil
	}

	versions := make([]int64, len(migrations))
	for i, migration := range migrations {
		versions[i] = migration.Version
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i] < versions[j] })

	// Check for potential issues (large gaps might indicate missing migrations)
	for i := 1; i < len(versions); i++ {
		gap := versions[i] - versions[i-1]
		if gap > 86400 { // More than 1 day in seconds (for timestamp-based versions)
			m.logger.Printf("Warning: Large gap between migrations %d and %d", versions[i-1], versions[i])
		}
	}

	return nil
}

// validateOrphanedFiles checks for migration files without pairs
func (m *Migrator) validateOrphanedFiles() error {
	files, err := os.ReadDir(m.migrationsPath)
	if err != nil {
		return fmt.Errorf("failed to read migrations directory: %w", err)
	}

	upFiles := make(map[int64]bool)
	downFiles := make(map[int64]bool)

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		filename := file.Name()
		if !strings.HasSuffix(filename, ".sql") {
			continue
		}

		parts := strings.Split(filename, "_")
		if len(parts) < 2 {
			continue
		}

		versionStr := parts[0]
		version, err := strconv.ParseInt(versionStr, 10, 64)
		if err != nil {
			continue
		}

		if strings.HasSuffix(filename, ".up.sql") {
			upFiles[version] = true
		} else if strings.HasSuffix(filename, ".down.sql") {
			downFiles[version] = true
		}
	}

	orphaned := []string{}
	for version := range upFiles {
		if !downFiles[version] {
			orphaned = append(orphaned, fmt.Sprintf("Missing down file for version %d", version))
		}
	}
	for version := range downFiles {
		if !upFiles[version] {
			orphaned = append(orphaned, fmt.Sprintf("Missing up file for version %d", version))
		}
	}

	if len(orphaned) > 0 {
		return fmt.Errorf("orphaned files found: %s", strings.Join(orphaned, ", "))
	}

	return nil
}

// validateSQL performs basic SQL validation
func (m *Migrator) validateSQL(migration Migration) error {
	// Basic checks
	if strings.TrimSpace(migration.UpSQL) == "" {
		return fmt.Errorf("up SQL is empty")
	}
	if strings.TrimSpace(migration.DownSQL) == "" {
		return fmt.Errorf("down SQL is empty")
	}

	// Check for common syntax issues
	sqlChecks := map[string]string{
		migration.UpSQL:   "up",
		migration.DownSQL: "down",
	}

	for sql, direction := range sqlChecks {
		// Check for unmatched parentheses
		openParens := strings.Count(sql, "(")
		closeParens := strings.Count(sql, ")")
		if openParens != closeParens {
			return fmt.Errorf("%s SQL has unmatched parentheses", direction)
		}

		// Check for missing semicolons at statement ends
		statements := strings.Split(sql, ";")
		for i, stmt := range statements[:len(statements)-1] { // Exclude last empty part
			stmt = strings.TrimSpace(stmt)
			if stmt != "" && !strings.HasSuffix(stmt, ";") {
				// This is already split by ';', so this check is redundant, but kept for structure
				_ = i
			}
		}
	}

	return nil
}

// DetectSchemaDrift compares current database schema with expected schema from migrations
func (m *Migrator) DetectSchemaDrift(ctx context.Context) (*DriftResult, error) {
	// Get current database schema
	currentSchema, err := m.getCurrentSchema(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get current schema: %w", err)
	}

	// Get expected schema from migrations
	expectedSchema, err := m.getExpectedSchema(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get expected schema: %w", err)
	}

	result := &DriftResult{
		HasDrift:      false,
		MissingTables: []SchemaObject{},
		ExtraTables:   []SchemaObject{},
		Differences:   []string{},
	}

	// Compare schemas
	currentTables := make(map[string]SchemaObject)
	for _, obj := range currentSchema {
		if obj.Type == "table" {
			currentTables[obj.Name] = obj
		}
	}

	expectedTables := make(map[string]SchemaObject)
	for _, obj := range expectedSchema {
		if obj.Type == "table" {
			expectedTables[obj.Name] = obj
		}
	}

	// Find missing tables
	for name, table := range expectedTables {
		if _, exists := currentTables[name]; !exists {
			result.MissingTables = append(result.MissingTables, table)
			result.HasDrift = true
		}
	}

	// Find extra tables (excluding schema_migrations)
	for name, table := range currentTables {
		if name == "schema_migrations" {
			continue
		}
		if _, exists := expectedTables[name]; !exists {
			result.ExtraTables = append(result.ExtraTables, table)
			result.HasDrift = true
		}
	}

	if result.HasDrift {
		result.Differences = append(result.Differences,
			fmt.Sprintf("Found %d missing tables and %d extra tables",
				len(result.MissingTables), len(result.ExtraTables)))
	}

	return result, nil
}

// getCurrentSchema retrieves the current database schema
func (m *Migrator) getCurrentSchema(ctx context.Context) ([]SchemaObject, error) {
	query := `
		SELECT 'table' as type, tablename as name, schemaname as schema, '' as sql
		FROM pg_tables 
		WHERE schemaname = 'public'
		ORDER BY tablename
	`

	rows, err := m.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var objects []SchemaObject
	for rows.Next() {
		var obj SchemaObject
		if err := rows.Scan(&obj.Type, &obj.Name, &obj.Schema, &obj.SQL); err != nil {
			return nil, err
		}
		objects = append(objects, obj)
	}

	return objects, rows.Err()
}

// getExpectedSchema builds expected schema from applied migrations
func (m *Migrator) getExpectedSchema(ctx context.Context) ([]SchemaObject, error) {
	// This is a simplified implementation
	// In a real scenario, you'd parse all applied migrations to build the expected schema

	migrations, err := m.loadMigrations()
	if err != nil {
		return nil, err
	}

	appliedVersions, err := m.getAppliedVersions(ctx)
	if err != nil {
		return nil, err
	}

	var objects []SchemaObject
	createTableRegex := regexp.MustCompile(`(?i)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)`)

	for _, version := range appliedVersions {
		migration := findMigrationByVersion(migrations, version)
		if migration != nil {
			matches := createTableRegex.FindAllStringSubmatch(migration.UpSQL, -1)
			for _, match := range matches {
				if len(match) > 1 {
					objects = append(objects, SchemaObject{
						Type:   "table",
						Name:   match[1],
						Schema: "public",
						SQL:    "",
					})
				}
			}
		}
	}

	return objects, nil
}
