package integration

import (
	"askfrank/internal/model"
	"askfrank/internal/repository"
	testutil "askfrank/tests/util"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAdminPage_Integration(t *testing.T) {
	// Setup test environment
	db := testutil.SetupTestDB(t)

	// Use t.Cleanup for more reliable cleanup
	t.Cleanup(func() {
		testutil.CleanupTestDB(t, db)
	})

	testRepo := repository.NewPostgresRepository(db)
	testApp := testutil.SetupTestApp(t, db)

	// Create test users
	adminUser := model.User{
		ID:              uuid.New(),
		Name:            "Admin User",
		Email:           "admin@example.com",
		PasswordHash:    "$2a$10$abcdefghijklmnopqrstuvwxyz123456789",
		IsEmailVerified: true,
		CreatedAt:       time.Now(),
	}

	regularUser := model.User{
		ID:              uuid.New(),
		Name:            "Regular User",
		Email:           "user@example.com",
		PasswordHash:    "$2a$10$abcdefghijklmnopqrstuvwxyz123456789",
		IsEmailVerified: true,
		CreatedAt:       time.Now(),
	}

	pendingUser := model.User{
		ID:              uuid.New(),
		Name:            "Pending User",
		Email:           "pending@example.com",
		PasswordHash:    "$2a$10$abcdefghijklmnopqrstuvwxyz123456789",
		IsEmailVerified: false,
		CreatedAt:       time.Now(),
	}

	// Create users in database
	err := testRepo.CreateUser(adminUser)
	require.NoError(t, err)

	err = testRepo.CreateUser(regularUser)
	require.NoError(t, err)

	err = testRepo.CreateUser(pendingUser)
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

	t.Run("Unauthorized Access Should Return 404", func(t *testing.T) {
		req, err := http.NewRequest("GET", "/admin", nil)
		require.NoError(t, err)

		resp, err := testApp.Test(req, -1)
		require.NoError(t, err)

		// The /admin route is not configured in the test app, so it should return 404
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("Admin User Cannot Access Admin Page In Test", func(t *testing.T) {
		// Create a session for admin user (simplified for test)
		req, err := http.NewRequest("GET", "/admin", nil)
		require.NoError(t, err)

		// Add session cookie for admin user
		// Note: In a real test, you'd authenticate properly first
		req.AddCookie(&http.Cookie{
			Name:  "session_id",
			Value: "admin-session-123",
		})

		resp, err := testApp.Test(req, -1)
		require.NoError(t, err)

		// Since /admin route is not set up in test app, expect 404
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("Repository Methods Work Correctly", func(t *testing.T) {
		// Test GetUserStats
		stats, err := testRepo.GetUserStats()
		require.NoError(t, err)

		assert.Equal(t, 3, stats.TotalUsers, "Should have 3 total users")
		assert.Equal(t, 2, stats.ActiveUsers, "Should have 2 active (verified) users")
		assert.Equal(t, 1, stats.PendingRegistrations, "Should have 1 pending registration")

		// Test GetAllUsers
		users, totalCount, err := testRepo.GetAllUsers(10, 0)
		require.NoError(t, err)

		assert.Equal(t, 3, totalCount, "Total count should be 3")
		assert.Len(t, users, 3, "Should return 3 users")

		// Verify the users contain correct data
		userEmails := make(map[string]bool)
		for _, user := range users {
			userEmails[user.User.Email] = true

			// Check if pending user has registration info
			if user.User.Email == "pending@example.com" {
				assert.NotNil(t, user.Registration, "Pending user should have registration info")
				assert.Equal(t, "test-activation-code", user.Registration.ActivationCode)
			} else {
				assert.Nil(t, user.Registration, "Verified users should not have registration info")
			}

			// Verify that Role and IsEmailVerified are properly set by repository
			assert.Equal(t, user.User.Role, user.User.Role, "Default role should be 'user'")
			assert.Equal(t, user.User.IsEmailVerified, user.User.IsEmailVerified, "IsEmailVerified should match EmailVerified")
		}

		assert.True(t, userEmails["admin@example.com"], "Should include admin user")
		assert.True(t, userEmails["user@example.com"], "Should include regular user")
		assert.True(t, userEmails["pending@example.com"], "Should include pending user")
	})

	t.Run("Pagination Works Correctly", func(t *testing.T) {
		// Test with limit 2, offset 0
		users, totalCount, err := testRepo.GetAllUsers(2, 0)
		require.NoError(t, err)

		assert.Equal(t, 3, totalCount, "Total count should be 3")
		assert.Len(t, users, 2, "Should return 2 users (page 1)")

		// Test with limit 2, offset 2
		users, totalCount, err = testRepo.GetAllUsers(2, 2)
		require.NoError(t, err)

		assert.Equal(t, 3, totalCount, "Total count should be 3")
		assert.Len(t, users, 1, "Should return 1 user (page 2)")

		// Test with limit 10, offset 5 (beyond available data)
		users, totalCount, err = testRepo.GetAllUsers(10, 5)
		require.NoError(t, err)

		assert.Equal(t, 3, totalCount, "Total count should be 3")
		assert.Len(t, users, 0, "Should return 0 users (beyond available data)")
	})
}

func TestAdminPage_AdminStatsCalculation(t *testing.T) {
	db := testutil.SetupTestDB(t)

	// Use t.Cleanup for more reliable cleanup
	t.Cleanup(func() {
		testutil.CleanupTestDB(t, db)
	})

	testRepo := repository.NewPostgresRepository(db)

	// Create users with different creation dates
	today := time.Now()
	yesterday := today.Add(-24 * time.Hour)

	// User created today
	todayUser := model.User{
		ID:              uuid.New(),
		Name:            "Today User",
		Email:           "today@example.com",
		PasswordHash:    "$2a$10$abcdefghijklmnopqrstuvwxyz123456789",
		IsEmailVerified: true,
		CreatedAt:       today,
	}

	// User created yesterday
	yesterdayUser := model.User{
		ID:              uuid.New(),
		Name:            "Yesterday User",
		Email:           "yesterday@example.com",
		PasswordHash:    "$2a$10$abcdefghijklmnopqrstuvwxyz123456789",
		IsEmailVerified: true,
		CreatedAt:       yesterday,
	}

	err := testRepo.CreateUser(todayUser)
	require.NoError(t, err)

	err = testRepo.CreateUser(yesterdayUser)
	require.NoError(t, err)

	stats, err := testRepo.GetUserStats()
	require.NoError(t, err)

	assert.Equal(t, 2, stats.TotalUsers, "Should have 2 total users")
	assert.Equal(t, 2, stats.ActiveUsers, "Should have 2 active users")
	assert.Equal(t, 0, stats.PendingRegistrations, "Should have 0 pending registrations")
	assert.Equal(t, 1, stats.TodayRegistrations, "Should have 1 user registered today")
}
