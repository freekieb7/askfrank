# Database Session Storage Configuration

## Overview
The application now uses PostgreSQL database for session storage instead of in-memory storage. This provides the following benefits:

1. **Persistence**: Sessions survive server restarts
2. **Scalability**: Multiple server instances can share the same session data
3. **Reliability**: Session data is not lost when the application crashes or restarts

## Configuration

### Dependencies Added
- `github.com/gofiber/storage/postgres/v3` - PostgreSQL storage adapter for Fiber sessions

### Database Schema
The following table is automatically created during migration:

```sql
CREATE TABLE IF NOT EXISTS sessions (
    k VARCHAR(255) PRIMARY KEY,  -- Session key (session ID)
    v BYTEA,                     -- Session value (serialized session data)
    e BIGINT                     -- Expiration timestamp
);
```

### Session Configuration
```go
// Session storage configuration
sessionStorage := postgres.New(postgres.Config{
    Host:     "localhost",
    Port:     5432,
    Database: "postgres",
    Username: "postgres",
    Password: "postgres",
    Table:    "sessions",
    Reset:    false, // Don't reset the table on startup
})

// Session middleware configuration
store := session.New(session.Config{
    Storage:        sessionStorage,
    KeyLookup:      "cookie:session_id",
    CookieDomain:   "",
    CookiePath:     "/",
    CookieSecure:   false,      // Set to true in production with HTTPS
    CookieHTTPOnly: true,       // Prevents XSS attacks
    CookieSameSite: "Lax",      // CSRF protection
    Expiration:     24 * 60 * 60, // 24 hours
})
```

## Features Supported

### 1. User Authentication Sessions
- User login state persists across server restarts
- Session-based protection for `/account` route
- Automatic redirect to signup if not authenticated

### 2. Language Preferences
- User's language selection persists in the session
- Works with the internationalization middleware
- Language switching via `/lang/:lang` endpoints

### 3. Session Security
- **HttpOnly**: Prevents JavaScript access to session cookies
- **SameSite=Lax**: Provides CSRF protection
- **Secure**: Should be enabled in production with HTTPS
- **Path**: Restricts cookie to application path

## Testing
The session storage has been tested and verified to work correctly:

1. ✅ Session cookies are set with proper security attributes
2. ✅ Language preferences persist across requests
3. ✅ User authentication state is maintained
4. ✅ Database table is created automatically
5. ✅ Sessions work with protected routes

## Production Considerations

### Security Enhancements
1. Set `CookieSecure: true` when using HTTPS
2. Consider setting `CookieDomain` for subdomain applications
3. Monitor session table size and implement cleanup for expired sessions

### Performance Optimizations
1. Add database indexes on frequently queried columns
2. Consider session data compression for large session objects
3. Implement session cleanup job for expired entries

### Database Configuration
```sql
-- Optional: Add index for better performance
CREATE INDEX IF NOT EXISTS idx_sessions_expiration ON sessions(e);

-- Optional: Add cleanup job (run periodically)
DELETE FROM sessions WHERE e < EXTRACT(EPOCH FROM NOW());
```

## Migration from In-Memory Sessions
The migration is seamless:
- Existing users will get new session cookies on their next visit
- No data loss as user data is stored separately in user tables
- Session-dependent features (like language preferences) will reset once

## Environment Variables (Recommended)
For production, consider using environment variables:

```go
sessionStorage := postgres.New(postgres.Config{
    Host:     os.Getenv("DB_HOST"),
    Port:     getEnvAsInt("DB_PORT", 5432),
    Database: os.Getenv("DB_NAME"),
    Username: os.Getenv("DB_USER"),
    Password: os.Getenv("DB_PASSWORD"),
    Table:    "sessions",
    Reset:    false,
})
```

This ensures sensitive database credentials are not hardcoded in the application.
