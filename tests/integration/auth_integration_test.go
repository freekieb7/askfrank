package integration_test

import (
	"askfrank/internal/repository"
	"askfrank/internal/service"
	"askfrank/tests/testutil"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthService_Integration(t *testing.T) {
	// Skip integration tests if running in unit test mode
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}

	// Setup test database
	db := testutil.SetupTestDB(t)
	defer testutil.CleanupTestDB(t, db)

	// Setup real services (no mocks)
	repo := repository.NewDatabaseRepository(db)
	sessionStore := testutil.NewTestSessionStore()
	emailService := testutil.NewTestEmailService()
	authService := service.NewAuthService(repo, sessionStore, emailService)

	t.Run("complete_registration_and_login_workflow", func(t *testing.T) {
		email := testutil.UniqueEmail("workflow")
		password := testutil.ValidPassword()

		// Step 1: Register user
		registerReq := service.RegisterRequest{
			Email:           email,
			Password:        password,
			ConfirmPassword: password,
			Terms:           true,
			Newsletter:      false,
		}

		user, err := authService.Register(context.Background(), registerReq)
		require.NoError(t, err)
		require.NotNil(t, user)
		assert.Equal(t, email, user.Email)
		assert.False(t, user.EmailVerified)

		// Step 2: Verify email service was called
		assert.True(t, emailService.WasVerificationEmailSent(email))

		// Step 3: Verify user exists in database
		storedUser, err := repo.GetUserByEmail(email)
		require.NoError(t, err)
		assert.Equal(t, user.ID, storedUser.ID)

		// Step 4: Attempt login with unverified email (should fail)
		loginReq := service.LoginRequest{
			Email:    email,
			Password: password,
		}

		_, err = authService.Login(context.Background(), loginReq)
		assert.Error(t, err)
		assert.Equal(t, service.ErrEmailNotVerified, err)

		// Step 5: Verify email manually (simulate email verification)
		storedUser.EmailVerified = true
		err = repo.UpdateUser(storedUser)
		require.NoError(t, err)

		// Step 6: Login should now succeed
		loginUser, err := authService.Login(context.Background(), loginReq)
		require.NoError(t, err)
		require.NotNil(t, loginUser)
		assert.Equal(t, email, loginUser.Email)
		assert.True(t, loginUser.EmailVerified)
	})

	t.Run("service_error_handling_with_real_database", func(t *testing.T) {
		// Test service layer error handling with real database

		// Attempt to register with existing email
		existingUser := testutil.CreateTestUser(t, db)

		registerReq := service.RegisterRequest{
			Email:           existingUser.Email,
			Password:        testutil.ValidPassword(),
			ConfirmPassword: testutil.ValidPassword(),
			Terms:           true,
			Newsletter:      false,
		}

		_, err := authService.Register(context.Background(), registerReq)
		assert.Error(t, err)
		assert.Equal(t, service.ErrUserAlreadyExists, err)

		// Test login with non-existent user
		loginReq := service.LoginRequest{
			Email:    "nonexistent@example.com",
			Password: "password",
		}

		_, err = authService.Login(context.Background(), loginReq)
		assert.Error(t, err)
		assert.Equal(t, service.ErrInvalidCredentials, err)
	})
}

func TestDatabase_Integration_CRUD(t *testing.T) {
	// Skip integration tests if running in unit test mode
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}

	// Setup test database
	db := testutil.SetupTestDB(t)
	defer testutil.CleanupTestDB(t, db)

	repo := repository.NewDatabaseRepository(db)

	t.Run("user_crud_operations", func(t *testing.T) {
		// Create user
		user := testutil.MockUser()
		user.Email = testutil.UniqueEmail("crud")

		err := repo.CreateUser(user)
		require.NoError(t, err)

		// Read user
		retrievedUser, err := repo.GetUserByEmail(user.Email)
		require.NoError(t, err)
		assert.Equal(t, user.Email, retrievedUser.Email)
		assert.Equal(t, user.Name, retrievedUser.Name)

		// Update user
		retrievedUser.Name = "Updated Name"
		err = repo.UpdateUser(retrievedUser)
		require.NoError(t, err)

		// Verify update
		updatedUser, err := repo.GetUserByEmail(user.Email)
		require.NoError(t, err)
		assert.Equal(t, "Updated Name", updatedUser.Name)
	})

	t.Run("user_registration_operations", func(t *testing.T) {
		// Create user first
		user := testutil.CreateTestUser(t, db)

		// Create user registration
		registration := testutil.CreateTestUserRegistration(t, db, user.ID)

		// Retrieve registration by user ID
		retrievedReg, err := repo.GetUserRegistrationByUserID(user.ID)
		require.NoError(t, err)
		assert.Equal(t, registration.UserID, retrievedReg.UserID)
		assert.Equal(t, registration.ActivationCode, retrievedReg.ActivationCode)

		// Retrieve registration by email
		retrievedRegByEmail, err := repo.GetUserRegistrationByEmail(user.Email)
		require.NoError(t, err)
		assert.Equal(t, registration.ID, retrievedRegByEmail.ID)

		// Delete registration
		err = repo.DeleteUserRegistration(registration.ID)
		require.NoError(t, err)

		// Verify deletion
		_, err = repo.GetUserRegistrationByUserID(user.ID)
		assert.Error(t, err, "Registration should have been deleted")
	})

	t.Run("concurrent_user_operations", func(t *testing.T) {
		// Test concurrent user creation to ensure database handles concurrency properly
		const numUsers = 10
		results := make(chan error, numUsers)

		for i := 0; i < numUsers; i++ {
			go func(index int) {
				user := testutil.MockUser()
				user.Email = testutil.UniqueEmail("concurrent")
				err := repo.CreateUser(user)
				results <- err
			}(i)
		}

		// Collect results
		for i := 0; i < numUsers; i++ {
			err := <-results
			assert.NoError(t, err, "Concurrent user creation should succeed")
		}
	})
}
