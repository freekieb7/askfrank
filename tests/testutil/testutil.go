package testutil

import (
	"askfrank/internal/config"
	"askfrank/internal/database"
	"askfrank/internal/model"
	"askfrank/internal/repository"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

// TestConfig returns a test configuration
func TestConfig() *config.Config {
	return &config.Config{
		Server: config.ServerConfig{
			Port:        "8080",
			Host:        "localhost",
			Environment: "test",
		},
		Database: config.DatabaseConfig{
			Host:     "localhost",
			Port:     5432,
			User:     "postgres",
			Password: "postgres",
			Name:     "askfrank_test",
			SSLMode:  "disable",
		},
		Auth: config.AuthConfig{
			JWTSecret:           "test-jwt-secret",
			JWTExpiration:       24 * time.Hour,
			SessionExpiration:   24 * time.Hour,
			PasswordMinLength:   8,
			RequireVerification: false, // Disable for tests
		},
		Security: config.SecurityConfig{
			RateLimitEnabled:  false, // Disable for tests
			MaxLoginAttempts:  5,
			MaxSignupAttempts: 3,
			BlockDuration:     15 * time.Minute,
		},
	}
}

// SetupTestDB creates a test database connection
func SetupTestDB(t *testing.T) database.Database {
	cfg := TestConfig()

	// Create test database connection
	dataSourceName := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Database.Host, cfg.Database.Port, cfg.Database.User, cfg.Database.Password, cfg.Database.Name, cfg.Database.SSLMode)

	db, err := database.NewDatabase(dataSourceName)
	require.NoError(t, err, "Failed to connect to test database")

	// Run migrations
	repo := repository.NewPostgresRepository(db)
	err = repo.Migrate()
	require.NoError(t, err, "Failed to migrate test database")

	return db
}

// CleanupTestDB cleans up the test database
func CleanupTestDB(t *testing.T, db database.Database) {
	// Clean up test data
	_, err := db.Exec("TRUNCATE TABLE tbl_user_registration CASCADE")
	require.NoError(t, err)

	_, err = db.Exec("TRUNCATE TABLE tbl_user CASCADE")
	require.NoError(t, err)

	_, err = db.Exec("TRUNCATE TABLE sessions CASCADE")
	require.NoError(t, err)
}

// SetupTestApp creates a test Fiber app with the given database
func SetupTestApp(t *testing.T, db database.Database) *fiber.App {
	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
	})

	// Add basic routes for testing
	// You can expand this based on your needs
	return app
}

// CreateTestUser creates a test user in the database
func CreateTestUser(t *testing.T, db database.Database) *model.User {
	user := &model.User{
		ID:            uuid.New(),
		Name:          "Test User",
		Email:         fmt.Sprintf("test%d@example.com", time.Now().UnixNano()),
		PasswordHash:  "$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi", // password
		EmailVerified: true,
		CreatedAt:     time.Now(),
	}

	repo := repository.NewPostgresRepository(db)
	err := repo.CreateUser(*user)
	require.NoError(t, err, "Failed to create test user")

	return user
}

// CreateTestUserRegistration creates a test user registration
func CreateTestUserRegistration(t *testing.T, db database.Database, userID uuid.UUID) *model.UserRegistration {
	registration := &model.UserRegistration{
		ID:             uuid.New(),
		UserID:         userID,
		ActivationCode: "test-activation-code",
	}

	repo := repository.NewPostgresRepository(db)
	err := repo.CreateUserRegistration(*registration)
	require.NoError(t, err, "Failed to create test user registration")

	return registration
}

// PostJSON sends a POST request with JSON body
func PostJSON(t *testing.T, app *fiber.App, url string, body interface{}) *http.Response {
	jsonBody, err := json.Marshal(body)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	require.NoError(t, err)

	return resp
}

// GetJSON sends a GET request and expects JSON response
func GetJSON(t *testing.T, app *fiber.App, url string) *http.Response {
	req := httptest.NewRequest("GET", url, nil)
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	require.NoError(t, err)

	return resp
}

// ParseJSONResponse parses JSON response body
func ParseJSONResponse(t *testing.T, resp *http.Response, dest interface{}) {
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	err = json.Unmarshal(body, dest)
	require.NoError(t, err)
}

// AssertJSONResponse asserts that response contains expected JSON
func AssertJSONResponse(t *testing.T, resp *http.Response, expectedStatus int, expectedBody interface{}) {
	require.Equal(t, expectedStatus, resp.StatusCode)

	if expectedBody != nil {
		var actualBody interface{}
		ParseJSONResponse(t, resp, &actualBody)
		require.Equal(t, expectedBody, actualBody)
	}
}

// MockUser returns a mock user for testing
func MockUser() model.User {
	return model.User{
		ID:            uuid.New(),
		Name:          "Mock User",
		Email:         "mock@example.com",
		PasswordHash:  "$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi", // password
		EmailVerified: true,
		CreatedAt:     time.Now(),
	}
}

// MockUserRegistration returns a mock user registration for testing
func MockUserRegistration(userID uuid.UUID) model.UserRegistration {
	return model.UserRegistration{
		ID:             uuid.New(),
		UserID:         userID,
		ActivationCode: "mock-activation-code",
	}
}

// ValidPassword returns a password that meets strength requirements
func ValidPassword() string {
	return "TestPassword123!"
}

// InvalidPasswords returns passwords that don't meet requirements
func InvalidPasswords() []string {
	return []string{
		"short",             // too short
		"nouppercase123!",   // no uppercase
		"NOLOWERCASE123!",   // no lowercase
		"NoDigitsHere!",     // no digits
		"NoSpecialChars123", // no special characters
	}
}

// TestSessionStore provides a test session store
type TestSessionStore struct {
	data map[string]interface{}
	mu   sync.RWMutex
}

// NewTestSessionStore creates a new test session store
func NewTestSessionStore() *TestSessionStore {
	return &TestSessionStore{
		data: make(map[string]interface{}),
	}
}

// Set stores a value in the session
func (s *TestSessionStore) Set(key string, value interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key] = value
	return nil
}

// Get retrieves a value from the session
func (s *TestSessionStore) Get(key string) (interface{}, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, exists := s.data[key]
	if !exists {
		return nil, nil
	}
	return value, nil
}

// Delete removes a session entry
func (s *TestSessionStore) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, key)
	return nil
}

// TestEmailService provides a test email service
type TestEmailService struct {
	sentEmails        map[string]string // email -> verification code
	verificationCodes map[string]string // email -> code
	mu                sync.RWMutex
}

// NewTestEmailService creates a new test email service
func NewTestEmailService() *TestEmailService {
	return &TestEmailService{
		sentEmails:        make(map[string]string),
		verificationCodes: make(map[string]string),
	}
}

// SendVerificationEmail simulates sending a verification email
func (e *TestEmailService) SendVerificationEmail(email, code string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.sentEmails[email] = code
	e.verificationCodes[email] = code
	return nil
}

// SendPasswordResetEmail simulates sending a password reset email
func (e *TestEmailService) SendPasswordResetEmail(email, resetToken string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Store for testing purposes
	e.sentEmails[email+"_reset"] = resetToken
	return nil
}

// WasVerificationEmailSent checks if a verification email was sent
func (e *TestEmailService) WasVerificationEmailSent(email string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	_, sent := e.sentEmails[email]
	return sent
}

// GetVerificationCode returns the verification code for an email
func (e *TestEmailService) GetVerificationCode(email string) string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return e.verificationCodes[email]
}

// UniqueEmail generates a unique email for testing
func UniqueEmail(prefix string) string {
	return fmt.Sprintf("%s_%d@test.example.com", prefix, time.Now().UnixNano())
}
