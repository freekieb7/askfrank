package service

import (
	"askfrank/internal/model"
	"askfrank/internal/repository"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrEmailNotVerified   = errors.New("email not verified")
	ErrTooManyAttempts    = errors.New("too many attempts")
	ErrUserAlreadyExists  = errors.New("user already exists")
	ErrWeakPassword       = errors.New("password does not meet security requirements")
)

type AuthService struct {
	repo         repository.RepositoryInterface
	sessionStore SessionStore
	emailService EmailService
}

type SessionStore interface {
	Set(key string, value interface{}) error
	Get(key string) (interface{}, error)
	Delete(key string) error
}

type EmailService interface {
	SendVerificationEmail(email, token string) error
	SendPasswordResetEmail(email, token string) error
}

type LoginRequest struct {
	Email    string `validate:"required,email"`
	Password string `validate:"required,min=8"`
}

type RegisterRequest struct {
	Email           string `validate:"required,email,no_disposable_email"`
	Password        string `validate:"required,min=8,password_strength"`
	ConfirmPassword string `validate:"required,eqfield=Password"`
	Terms           bool   `validate:"required,eq=true"`
	Newsletter      bool
}

func NewAuthService(repo repository.RepositoryInterface, sessionStore SessionStore, emailService EmailService) *AuthService {
	return &AuthService{
		repo:         repo,
		sessionStore: sessionStore,
		emailService: emailService,
	}
}

func (s *AuthService) Login(ctx context.Context, req LoginRequest) (*model.User, error) {
	// TODO: Add rate limiting check here

	// Get user
	user, err := s.repo.GetUserByEmail(req.Email)
	if err != nil {
		s.recordFailedLogin(ctx, req.Email)
		return nil, ErrInvalidCredentials
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		s.recordFailedLogin(ctx, req.Email)
		return nil, ErrInvalidCredentials
	}

	// Check email verification
	if !user.EmailVerified {
		return nil, ErrEmailNotVerified
	}

	// Record successful login
	s.recordSuccessfulLogin(ctx, user.ID)

	return &user, nil
}

func (s *AuthService) Register(ctx context.Context, req RegisterRequest) (*model.User, error) {
	// TODO: Add rate limiting check here

	// Check if user already exists
	if _, err := s.repo.GetUserByEmail(req.Email); err == nil {
		return nil, ErrUserAlreadyExists
	}

	// Validate password strength
	if err := s.validatePasswordStrength(req.Password); err != nil {
		return nil, err
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	// Create user
	user := &model.User{
		ID:            uuid.New(),
		Name:          "", // TODO: Get from registration form
		Email:         req.Email,
		PasswordHash:  string(hashedPassword),
		EmailVerified: false,
		CreatedAt:     time.Now(),
	}

	if err := s.repo.CreateUser(*user); err != nil {
		return nil, err
	}

	// Send verification email
	verificationToken, err := s.generateVerificationToken(user.ID)
	if err != nil {
		return nil, err
	}

	if err := s.emailService.SendVerificationEmail(user.Email, verificationToken); err != nil {
		// Log error but don't fail registration
		// User can request another verification email
	}

	return user, nil
}

func (s *AuthService) validatePasswordStrength(password string) error {
	if len(password) < 8 {
		return ErrWeakPassword
	}

	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false

	for _, char := range password {
		switch {
		case 'A' <= char && char <= 'Z':
			hasUpper = true
		case 'a' <= char && char <= 'z':
			hasLower = true
		case '0' <= char && char <= '9':
			hasDigit = true
		case strings.ContainsRune("!@#$%^&*(),.?\":{}|<>", char):
			hasSpecial = true
		}
	}

	if !hasUpper || !hasLower || !hasDigit || !hasSpecial {
		return ErrWeakPassword
	}

	return nil
}

func (s *AuthService) recordFailedLogin(ctx context.Context, email string) {
	// Implementation to record failed login attempts
	// This could be logged or stored in database for security monitoring
}

func (s *AuthService) recordSuccessfulLogin(ctx context.Context, userID uuid.UUID) {
	// Implementation to record successful login
	// This could update last login time in database
}

func (s *AuthService) generateVerificationToken(userID uuid.UUID) (string, error) {
	// Generate a cryptographically secure random token
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
