# AskFrank

Required for developers:
- Go version > 1.24
- sudo apt install npm
- npm install tailwindcss @tailwindcss/cli

## Database Migrations

This project includes a powerful migration CLI tool built with **pgxpool** for managing database schema changes safely and efficiently.

### Migration Commands

Build the migration CLI:
```bash
make migrate-build
```

**Core Migration Operations:**
```bash
# Run all pending migrations
make migrate-up
./bin/migrate up

# Run specific number of migrations
./bin/migrate up --steps 2

# Rollback migrations
make migrate-down
./bin/migrate down --steps 3

# Check current migration version
make migrate-version
./bin/migrate version

# Check database connectivity and health
make migrate-health
./bin/migrate health

# Get detailed migration status
make migrate-status
./bin/migrate status
```

**Advanced Operations:**
```bash
# Create new migration file
./bin/migrate create add_user_profiles

# Force clean a dirty migration (use with caution)
./bin/migrate force 20250802120000

# Reset all migration records (DANGEROUS)
./bin/migrate reset --confirm
```

### Enhanced Features

**🔒 Concurrency Safety:**
- Advisory locks prevent concurrent migrations
- Transactional migration application
- Dirty state detection and recovery

**📊 Comprehensive Status:**
- Detailed migration status with `status` command
- Shows current, latest, pending, and applied migrations
- Clean/dirty state indication

**⚡ Performance:**
- Uses pgxpool for efficient connection management
- Optimized queries for large migration sets
- Minimal memory footprint

**🛡️ Safety Features:**
- Confirmation required for destructive operations
- Force command for dirty state recovery
- Comprehensive error handling and rollback

### Migration File Format

Migration files should follow this structure:

```sql
-- +migrate Up
-- Migration: add user preferences
-- Created: 2025-08-02 20:07:54

CREATE TABLE user_preferences (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    theme VARCHAR(20) DEFAULT 'light',
    language VARCHAR(5) DEFAULT 'en',
    notifications BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_user_preferences_user_id ON user_preferences(user_id);

-- +migrate Down
DROP TABLE IF EXISTS user_preferences;
```

### Migration Workflow Examples

**1. Create and Apply New Migration:**
```bash
# Create migration
./bin/migrate create add_user_sessions

# Edit the generated file with your SQL
# Apply the migration
./bin/migrate up
```

**2. Check Status Before/After:**
```bash
# Check current status
./bin/migrate status

# Apply migrations
./bin/migrate up

# Verify changes
./bin/migrate status
```

**3. Handle Dirty State:**
```bash
# If migration fails and leaves dirty state
./bin/migrate status  # Shows dirty state
./bin/migrate force 20250802120000  # Force clean
./bin/migrate up  # Retry
```

**4. Rollback and Reapply:**
```bash
# Rollback last 2 migrations
./bin/migrate down --steps 2

# Make changes to migration files
# Reapply
./bin/migrate up
```

### Makefile Integration

The migration commands are integrated into the project Makefile:

```bash
make migrate-build    # Build migration CLI
make migrate-up       # Apply migrations
make migrate-down     # Rollback migrations  
make migrate-version  # Show version
make migrate-health   # Health check
make migrate-status   # Detailed status
```

### Technical Details

- **Database Driver:** pgx/v5 with pgxpool for connection pooling
- **Concurrency:** PostgreSQL advisory locks (ID: 123456789)
- **Transactions:** Each migration runs in its own transaction
- **Versioning:** Timestamp-based (YYYYMMDDHHMMSS format)
- **State Tracking:** `schema_migrations` table with dirty state detection
- **File Format:** `-- +migrate Up/Down` sections for bidirectional migrations