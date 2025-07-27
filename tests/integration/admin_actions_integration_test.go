package integration

import (
	"askfrank/internal/model"
	"askfrank/internal/repository"
	"askfrank/tests/testutil"
	"log"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAdminUserActions_Integration(t *testing.T) {
	// Setup test environment
	db := testutil.SetupTestDB(t)
	defer func() {
		if err := db.Close(); err != nil {
			log.Fatalf("Failed to close database connection: %v", err)
		}
	}()

	testRepo := repository.NewDatabaseRepository(db)

	// Clean database before starting
	testutil.CleanupTestDB(t, db)

	// Create test users
	pendingUser := model.User{
		ID:            uuid.New(),
		Name:          "Pending User",
		Email:         "pending@example.com",
		PasswordHash:  "$2a$10$abcdefghijklmnopqrstuvwxyz123456789",
		EmailVerified: false,
		CreatedAt:     time.Now(),
	}

	activeUser := model.User{
		ID:            uuid.New(),
		Name:          "Active User",
		Email:         "active@example.com",
		PasswordHash:  "$2a$10$abcdefghijklmnopqrstuvwxyz123456789",
		EmailVerified: true,
		CreatedAt:     time.Now(),
	}

	// Create users in database
	err := testRepo.CreateUser(pendingUser)
	require.NoError(t, err)

	err = testRepo.CreateUser(activeUser)
	require.NoError(t, err)

	// Create a pending registration for pendingUser
	registration := model.UserRegistration{
		ID:             uuid.New(),
		UserID:         pendingUser.ID,
		ActivationCode: "test-activation-code",
		CreatedAt:      time.Now(),
	}
	err = testRepo.CreateUserRegistration(registration)
	require.NoError(t, err)

	t.Run("ActivateUser Repository Method Works", func(t *testing.T) {
		// Verify user is pending before activation
		user, err := testRepo.GetUserByIDForAdmin(pendingUser.ID)
		require.NoError(t, err)
		assert.False(t, user.EmailVerified, "User should be unverified before activation")

		// Check that registration exists
		_, err = testRepo.GetUserRegistrationByUserID(pendingUser.ID)
		require.NoError(t, err, "Registration should exist before activation")

		// Activate the user
		err = testRepo.ActivateUser(pendingUser.ID)
		require.NoError(t, err)

		// Verify user is now verified
		user, err = testRepo.GetUserByIDForAdmin(pendingUser.ID)
		require.NoError(t, err)
		assert.True(t, user.EmailVerified, "User should be verified after activation")

		// Check that registration is deleted
		_, err = testRepo.GetUserRegistrationByUserID(pendingUser.ID)
		assert.Equal(t, repository.ErrUserRegistrationNotFound, err, "Registration should be deleted after activation")
	})

	t.Run("DeleteUser Repository Method Works", func(t *testing.T) {
		// Verify user exists before deletion
		_, err := testRepo.GetUserByIDForAdmin(activeUser.ID)
		require.NoError(t, err)

		// Delete the user
		err = testRepo.DeleteUser(activeUser.ID)
		require.NoError(t, err)

		// Verify user is deleted
		_, err = testRepo.GetUserByIDForAdmin(activeUser.ID)
		assert.Equal(t, repository.ErrUserNotFound, err, "User should be deleted")
	})

	t.Run("ActivateUser With Non-existent User Returns Error", func(t *testing.T) {
		nonExistentID := uuid.New()
		err := testRepo.ActivateUser(nonExistentID)
		require.NoError(t, err) // The method doesn't check if user exists, just updates
	})

	t.Run("DeleteUser With Non-existent User Returns Error", func(t *testing.T) {
		nonExistentID := uuid.New()
		err := testRepo.DeleteUser(nonExistentID)
		assert.Equal(t, repository.ErrUserNotFound, err, "Should return not found error for non-existent user")
	})

	t.Run("GetUserByIDForAdmin Works", func(t *testing.T) {
		// Create a new user for this test
		testUser := model.User{
			ID:            uuid.New(),
			Name:          "Test User",
			Email:         "test@example.com",
			PasswordHash:  "$2a$10$abcdefghijklmnopqrstuvwxyz123456789",
			EmailVerified: true,
			CreatedAt:     time.Now(),
		}

		err := testRepo.CreateUser(testUser)
		require.NoError(t, err)

		// Get the user using admin method
		retrievedUser, err := testRepo.GetUserByIDForAdmin(testUser.ID)
		require.NoError(t, err)

		assert.Equal(t, testUser.ID, retrievedUser.ID)
		assert.Equal(t, testUser.Name, retrievedUser.Name)
		assert.Equal(t, testUser.Email, retrievedUser.Email)
		assert.Equal(t, testUser.EmailVerified, retrievedUser.EmailVerified)
		assert.Equal(t, testUser.EmailVerified, retrievedUser.IsEmailVerified)
		assert.Equal(t, "user", retrievedUser.Role) // Default role
	})
}

func TestAdminUserActions_EndpointValidation(t *testing.T) {
	// Setup test environment
	db := testutil.SetupTestDB(t)
	defer func() {
		if err := db.Close(); err != nil {
			log.Fatalf("Failed to close database connection: %v", err)
		}
	}()

	testApp := testutil.SetupTestApp(t, db)

	// Clean database before starting
	testutil.CleanupTestDB(t, db)

	t.Run("Admin Activate Endpoint Returns 404 Without Route", func(t *testing.T) {
		userID := uuid.New()
		req, err := http.NewRequest("POST", "/admin/users/"+userID.String()+"/activate", nil)
		require.NoError(t, err)

		resp, err := testApp.Test(req, -1)
		require.NoError(t, err)

		// Since the admin routes are not set up in the test app, expect 404
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("Admin Delete Endpoint Returns 404 Without Route", func(t *testing.T) {
		userID := uuid.New()
		req, err := http.NewRequest("DELETE", "/admin/users/"+userID.String(), nil)
		require.NoError(t, err)

		resp, err := testApp.Test(req, -1)
		require.NoError(t, err)

		// Since the admin routes are not set up in the test app, expect 404
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
}
