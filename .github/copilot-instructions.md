# 🤖 GitHub Copilot Instructions for AskFrank Project

## 📋 Project Overview

**AskFrank** is a healthcare IT platform built with Go, Fiber, and Templ. It provides flexible IT solutions for healthcare organizations with internationalization support (English/Dutch) and a comprehensive security system.

## 🏗️ Architecture & Tech Stack

### Core Technologies
- **Backend**: Go 1.24 with Fiber v2 web framework
- **Frontend**: Templ templates with Tailwind CSS
- **Database**: PostgreSQL with session storage
- **Internationalization**: Custom i18n system with JSON translations
- **Security**: Multi-layer protection (CSRF, rate limiting, input validation)

### Project Structure
```
askfrank/
├── internal/
│   ├── api/           # HTTP handlers and routing logic
│   ├── database/      # Database connection and configuration
│   ├── i18n/         # Internationalization system
│   ├── middleware/   # Security, i18n, and other middleware
│   ├── model/        # Data models and structures
│   └── repository/   # Database operations and queries
├── resources/view/    # Templ templates
│   ├── component/    # Reusable UI components
│   └── *.templ      # Page templates
├── translations/     # JSON translation files (en.json, nl.json)
├── STYLE_GUIDE.md   # UI color palette and design guidelines
└── main.go          # Application entry point
```

## 🎨 Design System & Style Guide

### Color Palette (Strictly Follow)
- **Ocean Blue (`#05668D`)**: Primary buttons, headers, brand elements
- **Deep Teal (`#028090`)**: Hover states, secondary actions  
- **Mint Green (`#00A896`)**: Success states, highlights
- **Aqua Green (`#02C39A`)**: Links, accents, focus states
- **Pale Yellow (`#EAF2EF`)**: Backgrounds, cards, muted elements

### UI Guidelines
- Use Tailwind CSS classes exclusively
- Compact spacing: prefer `py-8`, `px-3`, `gap-6` over larger values
- Responsive design: mobile-first with `sm:`, `lg:` breakpoints
- Card-based layouts with `bg-white`, `rounded-lg`, `shadow-lg`
- Consistent button styling with hover transitions

## 🌐 Internationalization

### Translation System
- Use `middleware.T(c, "key")` for all user-facing text
- Translation keys follow dot notation: `"home.hero.title"`
- Support English (`en`) and Dutch (`nl`) languages
- Session-based language preferences (no URL parameters)

### Translation File Structure
```json
{
  "nav.brand": "AskFrank",
  "home.hero.title": "Title Text",
  "account.info.email_label": "Email Address"
}
```

### Adding New Translations
1. Add key-value pairs to both `translations/en.json` and `translations/nl.json`
2. Use descriptive, hierarchical keys
3. Keep translations concise and professional

## 🔒 Security Implementation

### Authentication & Authorization
- Session-based authentication using PostgreSQL storage
- Email verification required before login
- Secure password hashing with bcrypt
- User roles and permissions system

### Security Middleware Layers
1. **CSRF Protection**: All forms must include csrf token
2. **Rate Limiting**: 5 attempts per 15 minutes for auth endpoints
3. **Input Validation**: HTML escaping and suspicious content detection
4. **Honeypot Fields**: Hidden form fields for bot detection
5. **IP Blocking**: Automatic blocking for repeated violations
6. **Disposable Email**: Blocked domains list for signup protection
7. **XSS Protection**: Content sanitization and validation
8. **CAPTCHA**: reCAPTCHA integration for forms

## 📝 Code Conventions

### Go Code Style
- Use descriptive variable names: `userEmail`, `activationCode`
- Error handling: Always check and log errors with context
- Structured logging: Use `slog` with key-value pairs
- Repository pattern: Separate data access from business logic
- Handler pattern: Keep handlers thin, delegate to services

### Templ Templates
- Component-based architecture: Reuse `@component.Layout()`
- Pass Fiber context: `func TemplateName(c *fiber.Ctx, data Type)`
- Consistent naming: PascalCase for template names
- Semantic HTML: Use proper HTML5 elements
- Accessibility: Include ARIA labels and proper form structure

### Database Operations
- Use prepared statements for all queries
- Handle `repository.ErrUserNotFound` gracefully
- Implement proper migrations in `Repository.Migrate()`
- Session storage in dedicated `sessions` table
- UUID primary keys for all entities

## 🧪 Testing Philosophy & Framework

### **Integration-First Testing Approach**

**AskFrank uses integration testing as the primary testing strategy**, ensuring real compatibility between all system components. This approach provides confidence that the entire system works together correctly in production environments.

#### Core Testing Principles
1. **Real Database Integration**: All tests use PostgreSQL with actual database transactions
2. **End-to-End Compatibility**: Services interact through real interfaces, not mocks
3. **Production-Like Environment**: Tests run against the same stack used in production
4. **Comprehensive Coverage**: Test entire user workflows and system interactions
5. **Fast Feedback**: Optimized database setup/teardown for quick test cycles

### **Testing Framework Structure**
```
tests/
├── integration/          # Full system integration tests
│   ├── auth_test.go     # Authentication workflows with real database
│   ├── user_test.go     # User management with repository layer
│   └── api_test.go      # HTTP API endpoints with real handlers
├── testutil/            # Testing utilities and helpers
│   ├── testutil.go      # Database setup, test data factories
│   └── fixtures.go      # Test data and scenarios
└── test_runner.go       # Test orchestration and database lifecycle
```

### **Integration Testing Best Practices**

#### Database Testing
- **Real PostgreSQL**: Every test uses actual PostgreSQL database
- **Transaction Isolation**: Each test runs in isolated transactions
- **Automatic Cleanup**: Database state reset between tests
- **Migration Testing**: Verify schema changes work correctly

#### Service Integration
- **Real Dependencies**: Services use actual repository implementations
- **Authentic Workflows**: Test complete user journeys (register → verify → login)
- **Error Scenarios**: Test failure cases with real error propagation
- **Concurrent Access**: Verify thread safety with actual database locks

#### Test Data Management
```go
// Use real repository for authentic data creation
func setupTestUser(t *testing.T, repo *repository.Repository) model.User {
    user := model.User{
        ID:    uuid.New(),
        Email: testutil.UniqueEmail("test"),
        // ... real user data
    }
    err := repo.CreateUser(user)
    require.NoError(t, err)
    return user
}
```

### **Building & Testing Commands**
```bash
# Run full integration test suite
make test

# Run specific integration tests
make test-integration

# Test with coverage reporting
make test-coverage

# Setup test database
make test-db-setup

# Reset test environment
make test-db-reset
```

### **Development Workflow**

#### Testing New Features
1. **Write Integration Tests First**: Create tests that verify complete workflows
2. **Use Real Database**: Always test against PostgreSQL, never mock repository
3. **Test User Journeys**: Verify entire use cases from start to finish
4. **Include Error Cases**: Test failure scenarios with real error handling
5. **Verify Compatibility**: Ensure new features work with existing system

#### Creating New Tests
```go
func TestUserRegistrationWorkflow(t *testing.T) {
    // Setup real database and services
    db := testutil.SetupTestDB(t)
    repo := repository.NewRepository(db)
    authService := service.NewAuthService(repo, sessionStore, emailService)
    
    // Test complete workflow
    user, err := authService.Register(ctx, request)
    require.NoError(t, err)
    
    // Verify database state
    stored, err := repo.GetUserByEmail(request.Email)
    require.NoError(t, err)
    assert.Equal(t, user.ID, stored.ID)
}
```

### **Common Development Patterns**

#### Creating New Pages
1. Create template in `resources/view/`
2. Add translation keys to both language files
3. Create handler in `internal/api/handlers.go`
4. Add route in `main.go`
5. Write integration tests for the complete workflow
6. Generate templates and test end-to-end

#### Adding Security Features
1. Update `internal/middleware/security.go`
2. Add validation to handlers
3. Write integration tests with real security scenarios
4. Include CSRF tokens in forms
5. Test with security validation suite

#### Adding New Services
1. Create service in `internal/service/`
2. Add repository methods in `internal/repository/`
3. Write integration tests for service workflows
4. Test database interactions with real PostgreSQL
5. Verify error handling with actual error scenarios

#### Database Changes
1. Update model in `internal/model/`
2. Add migration in `repository.Migrate()`
3. Create repository methods
4. Write integration tests for new database operations
5. Test migrations with real database schema changes
6. Update handlers to use new data structures
3. Include CSRF tokens in forms
4. Test with security validation suite

#### Database Changes
1. Update model in `internal/model/`
2. Add migration in `repository.Migrate()`
3. Create repository methods
4. Update handlers to use new data

## 🎯 Best Practices

### Security First
- Never trust user input - validate and sanitize everything
- Use parameterized queries to prevent SQL injection
- Include CSRF tokens in all state-changing operations
- Log security events for monitoring
- Implement defense in depth

### User Experience
- Provide clear error messages without exposing system details
- Use AJAX for form submissions to prevent page reloads
- Include loading states and visual feedback
- Ensure responsive design works on all devices
- Follow accessibility guidelines

### Code Quality
- Write descriptive commit messages
- Use meaningful variable and function names
- Keep functions small and focused
- Handle errors gracefully with user-friendly messages
- Document complex business logic

## 🚀 Production Considerations

### Environment Variables
- `RECAPTCHA_SITE_KEY` and `RECAPTCHA_SECRET_KEY` for CAPTCHA
- Database connection strings
- Session encryption keys
- `CookieSecure: true` for HTTPS environments

### Monitoring & Logging
- Structured logging with correlation IDs
- Security event monitoring
- Performance metrics tracking
- Error rate and response time monitoring

### Deployment
- Use Docker containers with proper health checks
- Implement graceful shutdown handling
- Set up automated backups for PostgreSQL
- Configure rate limiting at load balancer level

---

## 💡 AI Assistant Guidelines

When working on this project:

1. **Always follow the style guide** - Use the exact hex colors specified
2. **Include security measures** - Every form needs CSRF protection
3. **Support internationalization** - All text must be translatable
4. **Maintain consistency** - Follow existing patterns and conventions
5. **Test thoroughly** - Generate templates and verify functionality
6. **Document changes** - Explain security implications and design decisions

This project prioritizes security, user experience, and maintainability. When in doubt, choose the more secure option and follow established patterns.