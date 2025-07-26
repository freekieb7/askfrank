package integration_test

import (
	"askfrank/internal/repository"
	"askfrank/internal/service"
	"askfrank/tests/mocks"
	"askfrank/tests/testutil"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestAuthIntegration(t *testing.T) {
	// Skip integration tests if running in unit test mode
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}

	// Setup test database
	db := testutil.SetupTestDB(t)
	defer testutil.CleanupTestDB(t, db)

	// Setup test dependencies with mocks
	repo := repository.NewRepository(db)
	mockSessionStore := &mocks.MockSessionStore{}
	mockEmailService := &mocks.MockEmailService{}

	// Setup mock expectations
	mockEmailService.On("SendVerificationEmail", mock.AnythingOfType("string"), mock.AnythingOfType("string")).Return(nil)

	authService := service.NewAuthService(repo, mockSessionStore, mockEmailService)

	// Setup test server
	app := setupTestApp(authService)

	t.Run("registration_and_login_flow", func(t *testing.T) {
		// Test user registration
		registerPayload := map[string]interface{}{
			"email":            "register-login@example.com",
			"password":         testutil.ValidPassword(),
			"confirm_password": testutil.ValidPassword(),
			"terms":            true,
			"newsletter":       false,
		}

		registerResp := makeJSONRequest(t, app, "POST", "/auth/register", registerPayload)
		assert.Equal(t, http.StatusCreated, registerResp.StatusCode)

		// Verify user was created in database
		user, err := repo.GetUserByEmail("register-login@example.com")
		require.NoError(t, err)
		assert.Equal(t, "register-login@example.com", user.Email)
		assert.False(t, user.EmailVerified) // Should not be verified initially

		// Test login with unverified email (should fail)
		loginPayload := map[string]interface{}{
			"email":    "register-login@example.com",
			"password": testutil.ValidPassword(),
		}

		loginResp := makeJSONRequest(t, app, "POST", "/auth/login", loginPayload)
		assert.Equal(t, http.StatusForbidden, loginResp.StatusCode)

		// Manually verify the user for login test
		user.EmailVerified = true
		err = repo.UpdateUser(user)
		require.NoError(t, err)

		// Test successful login
		loginResp = makeJSONRequest(t, app, "POST", "/auth/login", loginPayload)
		assert.Equal(t, http.StatusOK, loginResp.StatusCode)
	})

	t.Run("duplicate_registration", func(t *testing.T) {
		// Create initial user
		user := testutil.CreateTestUser(t, db)

		// Try to register with same email
		registerPayload := map[string]interface{}{
			"email":            user.Email,
			"password":         testutil.ValidPassword(),
			"confirm_password": testutil.ValidPassword(),
			"terms":            true,
			"newsletter":       false,
		}

		registerResp := makeJSONRequest(t, app, "POST", "/auth/register", registerPayload)
		assert.Equal(t, http.StatusConflict, registerResp.StatusCode)
	})

	t.Run("invalid_credentials", func(t *testing.T) {
		// Create test user
		user := testutil.CreateTestUser(t, db)

		// Test with wrong password
		loginPayload := map[string]interface{}{
			"email":    user.Email,
			"password": "WrongPassword123!",
		}

		loginResp := makeJSONRequest(t, app, "POST", "/auth/login", loginPayload)
		assert.Equal(t, http.StatusUnauthorized, loginResp.StatusCode)

		// Test with non-existent user
		loginPayload["email"] = "nonexistent@example.com"
		loginResp = makeJSONRequest(t, app, "POST", "/auth/login", loginPayload)
		assert.Equal(t, http.StatusUnauthorized, loginResp.StatusCode)
	})

	t.Run("password_strength_validation", func(t *testing.T) {
		weakPasswords := testutil.InvalidPasswords()

		for _, weakPassword := range weakPasswords {
			registerPayload := map[string]interface{}{
				"email":            "test@example.com",
				"password":         weakPassword,
				"confirm_password": weakPassword,
				"terms":            true,
				"newsletter":       false,
			}

			registerResp := makeJSONRequest(t, app, "POST", "/auth/register", registerPayload)
			assert.Equal(t, http.StatusBadRequest, registerResp.StatusCode,
				"Password '%s' should be rejected", weakPassword)
		}
	})
}

func TestDatabaseTransactions(t *testing.T) {
	// Skip integration tests if running in unit test mode
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}

	// Setup test database
	db := testutil.SetupTestDB(t)
	defer testutil.CleanupTestDB(t, db)

	repo := repository.NewRepository(db)

	t.Run("user_crud_operations", func(t *testing.T) {
		// Create user
		user := testutil.MockUser()
		err := repo.CreateUser(user)
		require.NoError(t, err)

		// Read user by ID
		retrievedUser, err := repo.GetUserByID(user.ID)
		require.NoError(t, err)
		assert.Equal(t, user.Email, retrievedUser.Email)

		// Read user by email
		retrievedUser, err = repo.GetUserByEmail(user.Email)
		require.NoError(t, err)
		assert.Equal(t, user.ID, retrievedUser.ID)

		// Update user
		retrievedUser.EmailVerified = true
		err = repo.UpdateUser(retrievedUser)
		require.NoError(t, err)

		// Verify update
		updatedUser, err := repo.GetUserByID(user.ID)
		require.NoError(t, err)
		assert.True(t, updatedUser.EmailVerified)
	})

	t.Run("user_registration_operations", func(t *testing.T) {
		// Create user first
		user := testutil.CreateTestUser(t, db)

		// Create user registration
		registration := testutil.MockUserRegistration(user.ID)
		err := repo.CreateUserRegistration(registration)
		require.NoError(t, err)

		// Read registration by user ID
		retrievedRegistration, err := repo.GetUserRegistrationByUserID(user.ID)
		require.NoError(t, err)
		assert.Equal(t, registration.ActivationCode, retrievedRegistration.ActivationCode)

		// Delete registration
		err = repo.DeleteUserRegistration(registration.ID)
		require.NoError(t, err)

		// Verify deletion
		_, err = repo.GetUserRegistrationByUserID(user.ID)
		assert.Error(t, err) // Should not find the registration
	})
}

// setupTestApp creates a minimal Fiber app for testing
func setupTestApp(authService *service.AuthService) *fiber.App {
	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
	})

	// Add routes for testing
	app.Post("/auth/register", func(c *fiber.Ctx) error {
		var req service.RegisterRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
		}

		user, err := authService.Register(c.Context(), req)
		if err != nil {
			switch err {
			case service.ErrUserAlreadyExists:
				return c.Status(http.StatusConflict).JSON(fiber.Map{"error": "User already exists"})
			case service.ErrWeakPassword:
				return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Weak password"})
			default:
				return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Internal server error"})
			}
		}

		return c.Status(http.StatusCreated).JSON(fiber.Map{
			"message": "User created successfully",
			"user_id": user.ID,
		})
	})

	app.Post("/auth/login", func(c *fiber.Ctx) error {
		var req service.LoginRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
		}

		user, err := authService.Login(c.Context(), req)
		if err != nil {
			switch err {
			case service.ErrInvalidCredentials:
				return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid credentials"})
			case service.ErrEmailNotVerified:
				return c.Status(http.StatusForbidden).JSON(fiber.Map{"error": "Email not verified"})
			case service.ErrTooManyAttempts:
				return c.Status(http.StatusTooManyRequests).JSON(fiber.Map{"error": "Too many attempts"})
			default:
				return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Internal server error"})
			}
		}

		return c.Status(http.StatusOK).JSON(fiber.Map{
			"message": "Login successful",
			"user_id": user.ID,
		})
	})

	return app
}

// makeJSONRequest is a helper function to make JSON requests to the test app
func makeJSONRequest(t *testing.T, app *fiber.App, method, url string, body interface{}) *http.Response {
	jsonBody, err := json.Marshal(body)
	require.NoError(t, err)

	req := httptest.NewRequest(method, url, bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	require.NoError(t, err)

	return resp
}
