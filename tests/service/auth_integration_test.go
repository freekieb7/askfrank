package service_test

import (
	"askfrank/internal/model"
	"askfrank/internal/repository"
	"askfrank/internal/service"
	"askfrank/tests/testutil"
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestAuthService_Login_Integration(t *testing.T) {
	// Setup test database and services
	db := testutil.SetupTestDB(t)
	defer testutil.CleanupTestDB(t, db)

	repo := repository.NewPostgresRepository(db)
	sessionStore := testutil.NewTestSessionStore()
	emailService := testutil.NewTestEmailService()
	authService := service.NewAuthService(repo, sessionStore, emailService)

	// Create a real test user in the database
	password := "TestPassword123!"
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	require.NoError(t, err)

	testUser := model.User{
		ID:            uuid.New(),
		Name:          "Test User",
		Email:         "test@example.com",
		PasswordHash:  string(hashedPassword),
		EmailVerified: true,
		CreatedAt:     time.Now(),
	}

	err = repo.CreateUser(testUser)
	require.NoError(t, err)

	tests := []struct {
		name          string
		email         string
		password      string
		setupUser     func() model.User
		expectedError error
		expectUser    bool
	}{
		{
			name:     "successful_login",
			email:    "test@example.com",
			password: password,
			setupUser: func() model.User {
				return testUser // User already created above
			},
			expectedError: nil,
			expectUser:    true,
		},
		{
			name:          "user_not_found",
			email:         "nonexistent@example.com",
			password:      password,
			setupUser:     func() model.User { return model.User{} }, // No setup needed
			expectedError: service.ErrInvalidCredentials,
			expectUser:    false,
		},
		{
			name:     "invalid_password",
			email:    "test@example.com",
			password: "WrongPassword123!",
			setupUser: func() model.User {
				return testUser // User already exists
			},
			expectedError: service.ErrInvalidCredentials,
			expectUser:    false,
		},
		{
			name:     "email_not_verified",
			email:    "unverified@example.com",
			password: password,
			setupUser: func() model.User {
				unverifiedUser := model.User{
					ID:            uuid.New(),
					Name:          "Unverified User",
					Email:         "unverified@example.com",
					PasswordHash:  string(hashedPassword),
					EmailVerified: false,
					CreatedAt:     time.Now(),
				}
				err := repo.CreateUser(unverifiedUser)
				require.NoError(t, err)
				return unverifiedUser
			},
			expectedError: service.ErrEmailNotVerified,
			expectUser:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test data
			expectedUser := tt.setupUser()

			// Create login request
			request := service.LoginRequest{
				Email:    tt.email,
				Password: tt.password,
			}

			// Execute test
			user, err := authService.Login(context.Background(), request)

			// Assert results
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError, err)
				assert.Nil(t, user)
			} else {
				assert.NoError(t, err)
				if tt.expectUser {
					assert.NotNil(t, user)
					assert.Equal(t, expectedUser.Email, user.Email)
					assert.Equal(t, expectedUser.ID, user.ID)
					assert.True(t, user.EmailVerified)
				}
			}
		})
	}
}

func TestAuthService_Register_Integration(t *testing.T) {
	// Setup test database and services
	db := testutil.SetupTestDB(t)
	defer testutil.CleanupTestDB(t, db)

	repo := repository.NewPostgresRepository(db)
	sessionStore := testutil.NewTestSessionStore()
	emailService := testutil.NewTestEmailService()
	authService := service.NewAuthService(repo, sessionStore, emailService)

	tests := []struct {
		name          string
		email         string
		password      string
		confirmPass   string
		terms         bool
		newsletter    bool
		setupData     func()
		expectedError error
		expectUser    bool
	}{
		{
			name:          "successful_registration",
			email:         "newuser@example.com",
			password:      testutil.ValidPassword(),
			confirmPass:   testutil.ValidPassword(),
			terms:         true,
			newsletter:    false,
			setupData:     func() {}, // No setup needed
			expectedError: nil,
			expectUser:    true,
		},
		{
			name:        "user_already_exists",
			email:       "existing@example.com",
			password:    testutil.ValidPassword(),
			confirmPass: testutil.ValidPassword(),
			terms:       true,
			newsletter:  false,
			setupData: func() {
				// Create existing user
				existingUser := model.User{
					ID:            uuid.New(),
					Name:          "Existing User",
					Email:         "existing@example.com",
					PasswordHash:  "hashedpassword",
					EmailVerified: true,
					CreatedAt:     time.Now(),
				}
				err := repo.CreateUser(existingUser)
				require.NoError(t, err)
			},
			expectedError: service.ErrUserAlreadyExists,
			expectUser:    false,
		},
		{
			name:          "weak_password",
			email:         "weakpass@example.com",
			password:      "weak",
			confirmPass:   "weak",
			terms:         true,
			newsletter:    false,
			setupData:     func() {}, // No setup needed
			expectedError: service.ErrWeakPassword,
			expectUser:    false,
		},
		// Note: Password mismatch and terms validation are typically handled
		// at the HTTP/validation layer, not the service layer.
		// Service layer focuses on business logic validation (password strength, user existence)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test data
			tt.setupData()

			// Create registration request
			request := service.RegisterRequest{
				Email:           tt.email,
				Password:        tt.password,
				ConfirmPassword: tt.confirmPass,
				Terms:           tt.terms,
				Newsletter:      tt.newsletter,
			}

			// Execute test
			user, err := authService.Register(context.Background(), request)

			// Assert results
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError, err)
				assert.Nil(t, user)
			} else {
				assert.NoError(t, err)
				if tt.expectUser {
					assert.NotNil(t, user)
					assert.Equal(t, tt.email, user.Email)
					assert.False(t, user.EmailVerified) // Should be false initially

					// Verify user was actually created in database
					storedUser, err := repo.GetUserByEmail(tt.email)
					assert.NoError(t, err)
					assert.Equal(t, user.ID, storedUser.ID)
					assert.Equal(t, tt.email, storedUser.Email)

					// Verify email service was called
					assert.True(t, emailService.WasVerificationEmailSent(tt.email))
				}
			}
		})
	}
}

func TestAuthService_PasswordStrengthValidation_Integration(t *testing.T) {
	// Setup test database and services
	db := testutil.SetupTestDB(t)
	defer testutil.CleanupTestDB(t, db)

	repo := repository.NewPostgresRepository(db)
	sessionStore := testutil.NewTestSessionStore()
	emailService := testutil.NewTestEmailService()
	authService := service.NewAuthService(repo, sessionStore, emailService)

	tests := []struct {
		name     string
		password string
		isValid  bool
	}{
		{
			name:     "valid_password",
			password: testutil.ValidPassword(),
			isValid:  true,
		},
		{
			name:     "too_short",
			password: "Short1!",
			isValid:  false,
		},
		{
			name:     "no_uppercase",
			password: "nouppercase123!",
			isValid:  false,
		},
		{
			name:     "no_lowercase",
			password: "NOLOWERCASE123!",
			isValid:  false,
		},
		{
			name:     "no_digits",
			password: "NoDigitsHere!",
			isValid:  false,
		},
		{
			name:     "no_special_chars",
			password: "NoSpecialChars123",
			isValid:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test password validation through registration
			request := service.RegisterRequest{
				Email:           testutil.UniqueEmail("passwordtest"),
				Password:        tt.password,
				ConfirmPassword: tt.password,
				Terms:           true,
				Newsletter:      false,
			}

			user, err := authService.Register(context.Background(), request)

			if tt.isValid {
				assert.NoError(t, err)
				assert.NotNil(t, user)

				// Verify user was actually created in database
				storedUser, err := repo.GetUserByEmail(request.Email)
				assert.NoError(t, err)
				assert.Equal(t, user.ID, storedUser.ID)
			} else {
				assert.Error(t, err)
				assert.Equal(t, service.ErrWeakPassword, err)
				assert.Nil(t, user)

				// Verify user was NOT created in database
				_, err := repo.GetUserByEmail(request.Email)
				assert.Error(t, err)
			}
		})
	}
}
