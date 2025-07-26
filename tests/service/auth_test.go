package service_test

import (
	"askfrank/internal/model"
	"askfrank/internal/service"
	"askfrank/tests/mocks"
	"askfrank/tests/testutil"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
)

func TestAuthService_Login(t *testing.T) {
	// Create a mock user with a hashed password
	password := "TestPassword123!"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	mockUser := model.User{
		ID:            uuid.New(),
		Name:          "Test User",
		Email:         "test@example.com",
		PasswordHash:  string(hashedPassword),
		EmailVerified: true,
		CreatedAt:     time.Now(),
	}

	tests := []struct {
		name          string
		request       service.LoginRequest
		setupMocks    func(*mocks.MockRepository, *mocks.MockSessionStore, *mocks.MockEmailService)
		expectedError error
		expectUser    bool
	}{
		{
			name: "successful_login",
			request: service.LoginRequest{
				Email:    "test@example.com",
				Password: password,
			},
			setupMocks: func(repo *mocks.MockRepository, session *mocks.MockSessionStore, email *mocks.MockEmailService) {
				repo.On("GetUserByEmail", "test@example.com").Return(mockUser, nil)
			},
			expectedError: nil,
			expectUser:    true,
		},
		{
			name: "user_not_found",
			request: service.LoginRequest{
				Email:    "nonexistent@example.com",
				Password: password,
			},
			setupMocks: func(repo *mocks.MockRepository, session *mocks.MockSessionStore, email *mocks.MockEmailService) {
				repo.On("GetUserByEmail", "nonexistent@example.com").Return(model.User{}, errors.New("user not found"))
			},
			expectedError: service.ErrInvalidCredentials,
			expectUser:    false,
		},
		{
			name: "invalid_password",
			request: service.LoginRequest{
				Email:    "test@example.com",
				Password: "WrongPassword123!",
			},
			setupMocks: func(repo *mocks.MockRepository, session *mocks.MockSessionStore, email *mocks.MockEmailService) {
				repo.On("GetUserByEmail", "test@example.com").Return(mockUser, nil)
			},
			expectedError: service.ErrInvalidCredentials,
			expectUser:    false,
		},
		{
			name: "email_not_verified",
			request: service.LoginRequest{
				Email:    "test@example.com",
				Password: password,
			},
			setupMocks: func(repo *mocks.MockRepository, session *mocks.MockSessionStore, email *mocks.MockEmailService) {
				unverifiedUser := mockUser
				unverifiedUser.EmailVerified = false
				repo.On("GetUserByEmail", "test@example.com").Return(unverifiedUser, nil)
			},
			expectedError: service.ErrEmailNotVerified,
			expectUser:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			repo := &mocks.MockRepository{}
			sessionStore := &mocks.MockSessionStore{}
			emailService := &mocks.MockEmailService{}

			// Setup mocks
			tt.setupMocks(repo, sessionStore, emailService)

			// Create auth service
			authService := service.NewAuthService(repo, sessionStore, emailService)

			// Execute test
			user, err := authService.Login(context.Background(), tt.request)

			// Assert results
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError, err)
				assert.Nil(t, user)
			} else {
				assert.NoError(t, err)
				if tt.expectUser {
					assert.NotNil(t, user)
					assert.Equal(t, mockUser.Email, user.Email)
				}
			}

			// Assert mock expectations
			repo.AssertExpectations(t)
			sessionStore.AssertExpectations(t)
			emailService.AssertExpectations(t)
		})
	}
}

func TestAuthService_Register(t *testing.T) {
	tests := []struct {
		name          string
		request       service.RegisterRequest
		setupMocks    func(*mocks.MockRepository, *mocks.MockSessionStore, *mocks.MockEmailService)
		expectedError error
		expectUser    bool
	}{
		{
			name: "successful_registration",
			request: service.RegisterRequest{
				Email:           "newuser@example.com",
				Password:        testutil.ValidPassword(),
				ConfirmPassword: testutil.ValidPassword(),
				Terms:           true,
				Newsletter:      false,
			},
			setupMocks: func(repo *mocks.MockRepository, session *mocks.MockSessionStore, email *mocks.MockEmailService) {
				// User doesn't exist
				repo.On("GetUserByEmail", "newuser@example.com").Return(model.User{}, errors.New("user not found"))
				// User creation succeeds
				repo.On("CreateUser", mock.AnythingOfType("model.User")).Return(nil)
				// Email sending succeeds
				email.On("SendVerificationEmail", "newuser@example.com", mock.AnythingOfType("string")).Return(nil)
			},
			expectedError: nil,
			expectUser:    true,
		},
		{
			name: "user_already_exists",
			request: service.RegisterRequest{
				Email:           "existing@example.com",
				Password:        testutil.ValidPassword(),
				ConfirmPassword: testutil.ValidPassword(),
				Terms:           true,
				Newsletter:      false,
			},
			setupMocks: func(repo *mocks.MockRepository, session *mocks.MockSessionStore, email *mocks.MockEmailService) {
				// User already exists
				existingUser := testutil.MockUser()
				existingUser.Email = "existing@example.com"
				repo.On("GetUserByEmail", "existing@example.com").Return(existingUser, nil)
			},
			expectedError: service.ErrUserAlreadyExists,
			expectUser:    false,
		},
		{
			name: "weak_password",
			request: service.RegisterRequest{
				Email:           "newuser@example.com",
				Password:        "weak",
				ConfirmPassword: "weak",
				Terms:           true,
				Newsletter:      false,
			},
			setupMocks: func(repo *mocks.MockRepository, session *mocks.MockSessionStore, email *mocks.MockEmailService) {
				// User doesn't exist
				repo.On("GetUserByEmail", "newuser@example.com").Return(model.User{}, errors.New("user not found"))
			},
			expectedError: service.ErrWeakPassword,
			expectUser:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			repo := &mocks.MockRepository{}
			sessionStore := &mocks.MockSessionStore{}
			emailService := &mocks.MockEmailService{}

			// Setup mocks
			tt.setupMocks(repo, sessionStore, emailService)

			// Create auth service
			authService := service.NewAuthService(repo, sessionStore, emailService)

			// Execute test
			user, err := authService.Register(context.Background(), tt.request)

			// Assert results
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError, err)
				assert.Nil(t, user)
			} else {
				assert.NoError(t, err)
				if tt.expectUser {
					assert.NotNil(t, user)
					assert.Equal(t, tt.request.Email, user.Email)
					assert.False(t, user.EmailVerified) // Should be false initially
				}
			}

			// Assert mock expectations
			repo.AssertExpectations(t)
			sessionStore.AssertExpectations(t)
			emailService.AssertExpectations(t)
		})
	}
}

func TestAuthService_PasswordStrengthValidation(t *testing.T) {
	// Create mocks (not used in this test but required for service creation)
	repo := &mocks.MockRepository{}
	sessionStore := &mocks.MockSessionStore{}
	emailService := &mocks.MockEmailService{}

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
				Email:           "test@example.com",
				Password:        tt.password,
				ConfirmPassword: tt.password,
				Terms:           true,
				Newsletter:      false,
			}

			if tt.isValid {
				// Mock successful path
				repo.On("GetUserByEmail", "test@example.com").Return(model.User{}, errors.New("user not found"))
				repo.On("CreateUser", mock.AnythingOfType("model.User")).Return(nil)
				emailService.On("SendVerificationEmail", "test@example.com", mock.AnythingOfType("string")).Return(nil)

				user, err := authService.Register(context.Background(), request)
				assert.NoError(t, err)
				assert.NotNil(t, user)
			} else {
				// Should fail without reaching repository
				user, err := authService.Register(context.Background(), request)
				assert.Error(t, err)
				assert.Equal(t, service.ErrWeakPassword, err)
				assert.Nil(t, user)
			}
		})
	}
}
