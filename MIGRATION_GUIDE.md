# Database Migrations

This document describes the database migration system for AskFrank healthcare IT platform.

## Overview

AskFrank uses [golang-migrate](https://github.com/golang-migrate/migrate) for database schema management. This provides a robust, version-controlled approach to database changes with proper rollback capabilities.

## Migration Structure

Migrations are stored in the `migrations/` directory with the following naming convention:
```
migrations/
├── 000001_initial_schema.up.sql      # Initial database schema
├── 000001_initial_schema.down.sql    # Rollback for initial schema
├── 000002_add_user_profile.up.sql    # Example next migration
└── 000002_add_user_profile.down.sql  # Rollback for user profile
```

Each migration consists of two files:
- `.up.sql` - Contains the forward migration (schema changes)
- `.down.sql` - Contains the rollback migration (undo changes)

## Available Commands

### Basic Migration Commands

```bash
# Run all pending migrations
make migrate-up

# Rollback the last migration
make migrate-down

# Rollback ALL migrations (⚠️ DESTRUCTIVE)
make migrate-down-all

# Reset database (rollback all + apply all)
make migrate-reset

# Check current migration status
make migrate-status

# Create a new migration
make migrate-create

# List all available migrations
make migrate-list

# Validate migration files
make migrate-validate
```

### Advanced Migration Commands

```bash
# Go to specific migration version
make migrate-goto

# Force set migration version (⚠️ use with caution)
make migrate-force
```

### Built-in Migration Tool

```bash
# Use the custom migration tool
make migrate-tool-up
make migrate-tool-down
make migrate-tool-status
make migrate-tool-create
```

## Creating New Migrations

### Method 1: Using Makefile (Recommended)

```bash
make migrate-create
# Enter migration name when prompted (e.g., "add_patient_table")
```

### Method 2: Using golang-migrate CLI

```bash
migrate create -ext sql -dir migrations add_patient_table
```

### Method 3: Using built-in tool

```bash
make migrate-tool-create
# Enter migration name when prompted
```

## Migration Best Practices

### 1. Always Create Both Up and Down Migrations

Every `.up.sql` file must have a corresponding `.down.sql` file that reverses the changes.

**Example - 000002_add_patient_table.up.sql:**
```sql
-- Add patient table for healthcare data
CREATE TABLE patients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES tbl_user(id) ON DELETE CASCADE,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    date_of_birth DATE NOT NULL,
    medical_record_number VARCHAR(50) UNIQUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Add indexes for better performance
CREATE INDEX idx_patients_user_id ON patients(user_id);
CREATE INDEX idx_patients_mrn ON patients(medical_record_number);
```

**Example - 000002_add_patient_table.down.sql:**
```sql
-- Remove indexes
DROP INDEX IF EXISTS idx_patients_mrn;
DROP INDEX IF EXISTS idx_patients_user_id;

-- Remove patient table
DROP TABLE IF EXISTS patients;
```

### 2. Use Transactions for Complex Migrations

```sql
BEGIN;

-- Multiple related changes
ALTER TABLE tbl_user ADD COLUMN phone VARCHAR(20);
CREATE INDEX idx_user_phone ON tbl_user(phone);
UPDATE tbl_user SET phone = '' WHERE phone IS NULL;
ALTER TABLE tbl_user ALTER COLUMN phone SET NOT NULL;

COMMIT;
```

### 3. Handle Data Safely

```sql
-- Safe column addition
ALTER TABLE tbl_user ADD COLUMN middle_name VARCHAR(50);

-- Safe column removal (first make nullable, then remove in next migration)
ALTER TABLE tbl_user ALTER COLUMN old_column DROP NOT NULL;
-- In next migration: ALTER TABLE tbl_user DROP COLUMN old_column;
```

### 4. Use Descriptive Names

Good migration names:
- `add_patient_table`
- `add_email_verification_index`
- `update_user_role_enum`
- `remove_deprecated_session_fields`

### 5. Test Migrations

Always test both up and down migrations:

```bash
# Test forward migration
make migrate-up

# Test rollback
make migrate-down

# Test full cycle
make migrate-reset
```

## Migration Status and Troubleshooting

### Check Migration Status

```bash
make migrate-status
```

This shows:
- Current migration version
- Whether database is in "dirty" state
- Any migration errors

### Fix Dirty State

If migrations fail mid-way, the database may be in a "dirty" state:

```bash
# Check what went wrong
make migrate-status

# Force to a known good version (use carefully!)
make migrate-force
# Follow prompts to specify version
```

### Migration Conflicts

If multiple developers create migrations with the same number:
1. Rename one migration file to use the next available number
2. Update any references in the migration content
3. Coordinate with your team to avoid conflicts

## Environment-Specific Considerations

### Development

```bash
# Reset database frequently during development
make migrate-reset

# Create and test new migrations
make migrate-create
# Edit the generated files
make migrate-up
make migrate-down  # Test rollback
```

### Production

```bash
# Always backup before migrations
pg_dump $DATABASE_URL > backup.sql

# Apply migrations
make migrate-up

# Monitor for issues
make migrate-status
```

## Integration with Application

The application automatically checks for pending migrations on startup. However, it's recommended to run migrations manually in production environments.

### Manual Migration in Production

```bash
# 1. Backup database
pg_dump $DATABASE_URL > backup_$(date +%Y%m%d_%H%M%S).sql

# 2. Run migrations
make migrate-up

# 3. Start application
make run
```

### Automated Migration (Development Only)

The application can auto-run migrations in development:

```bash
# This is done automatically in 'make setup'
make docker-compose-up
make migrate-up
make run
```

## Healthcare Compliance Considerations

### HIPAA Compliance

- All migrations involving patient data must be logged
- Backup patient data before structural changes
- Ensure encryption settings are preserved during migrations
- Test data privacy after schema changes

### Audit Trail

- Migration logs are automatically captured
- Include business justification in migration comments
- Document any data transformations
- Keep rollback procedures documented

### Security

- Never include sensitive data in migration files
- Use environment variables for production settings
- Review migrations for SQL injection risks
- Ensure proper access controls after schema changes

## Common Migration Patterns

### Adding a New Table

```sql
-- up migration
CREATE TABLE medical_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    patient_id UUID NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
    record_type VARCHAR(50) NOT NULL,
    content TEXT NOT NULL,
    created_by UUID NOT NULL REFERENCES tbl_user(id),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_medical_records_patient ON medical_records(patient_id);
CREATE INDEX idx_medical_records_type ON medical_records(record_type);
```

### Adding a Column

```sql
-- up migration
ALTER TABLE tbl_user ADD COLUMN last_login TIMESTAMP;
CREATE INDEX idx_user_last_login ON tbl_user(last_login);

-- down migration
DROP INDEX IF EXISTS idx_user_last_login;
ALTER TABLE tbl_user DROP COLUMN IF EXISTS last_login;
```

### Changing Column Type

```sql
-- up migration
ALTER TABLE tbl_user ALTER COLUMN phone TYPE VARCHAR(20);

-- down migration  
ALTER TABLE tbl_user ALTER COLUMN phone TYPE VARCHAR(15);
```

### Data Migration

```sql
-- up migration
-- Add new column
ALTER TABLE tbl_user ADD COLUMN full_name VARCHAR(200);

-- Populate from existing data
UPDATE tbl_user SET full_name = CONCAT(first_name, ' ', last_name) 
WHERE full_name IS NULL;

-- Make it required
ALTER TABLE tbl_user ALTER COLUMN full_name SET NOT NULL;
```

## Monitoring and Alerts

### Migration Monitoring

```bash
# Check migration status in monitoring scripts
make migrate-status

# Log migration events
echo "$(date): Migration status checked" >> /var/log/askfrank/migrations.log
```

### Automated Checks

Add to CI/CD pipeline:

```bash
# Validate all migrations
make migrate-validate

# Test migration cycle
make migrate-reset
make migrate-up
```

## Troubleshooting Common Issues

### Issue: "dirty database version"

```bash
# Check what version is marked as dirty
make migrate-status

# Force to previous known good version
make migrate-force

# Then try again
make migrate-up
```

### Issue: Migration file missing

```bash
# List available migrations
make migrate-list

# Ensure both .up.sql and .down.sql exist
make migrate-validate
```

### Issue: Database connection failed

```bash
# Check database is running
make docker-compose-status

# Start database if needed
make docker-compose-up

# Verify connection settings in .env
```

## Migration Checklist

Before creating a migration:
- [ ] Business requirement is clear
- [ ] Impact on existing data is understood
- [ ] Rollback strategy is planned
- [ ] Testing approach is defined

When creating a migration:
- [ ] Migration name is descriptive
- [ ] Both up and down files are created
- [ ] Changes are backwards compatible when possible
- [ ] Indexes are added for new columns used in queries
- [ ] Foreign key constraints are properly defined

Before applying to production:
- [ ] Migration tested in development
- [ ] Migration tested with production-like data volume
- [ ] Rollback tested
- [ ] Database backup strategy confirmed
- [ ] Monitoring alerts configured
- [ ] Deployment window scheduled

After applying migration:
- [ ] Migration status verified
- [ ] Application functionality tested
- [ ] Performance impact monitored
- [ ] Rollback procedure documented

## Related Documentation

- [Database Configuration](../SECURITY_CONFIGURATION.md)
- [Development Setup](../README.md)
- [Testing Framework](../TESTING_FRAMEWORK.md)
- [Security Implementation](../SECURITY_IMPLEMENTATION.md)
