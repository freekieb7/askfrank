package service

import (
	"askfrank/internal/model"
	"askfrank/internal/repository"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
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
	tracer := otel.Tracer("askfrank.auth")
	ctx, span := tracer.Start(ctx, "auth.login")
	defer span.End()

	// Add attributes to span
	span.SetAttributes(
		attribute.String("auth.email", req.Email),
		attribute.String("auth.action", "login"),
	)

	// Structured logging with trace context
	logger := slog.With(
		"operation", "login",
		"email", req.Email,
		"trace_id", span.SpanContext().TraceID().String(),
		"span_id", span.SpanContext().SpanID().String(),
	)

	logger.InfoContext(ctx, "Login attempt started")

	// Get user
	user, err := s.repo.GetUserByEmail(req.Email)
	if err != nil {
		s.recordFailedLogin(ctx, req.Email)
		span.SetStatus(codes.Error, "User not found")
		span.RecordError(err)

		logger.WarnContext(ctx, "Login failed - user not found",
			"error", err.Error(),
		)
		return nil, ErrInvalidCredentials
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		s.recordFailedLogin(ctx, req.Email)
		span.SetStatus(codes.Error, "Invalid password")
		span.RecordError(err)

		logger.WarnContext(ctx, "Login failed - invalid password",
			"user_id", user.ID.String(),
		)
		return nil, ErrInvalidCredentials
	}

	// Check email verification
	if !user.EmailVerified {
		span.SetStatus(codes.Error, "Email not verified")
		logger.WarnContext(ctx, "Login failed - email not verified",
			"user_id", user.ID.String(),
		)
		return nil, ErrEmailNotVerified
	}

	// Record successful login
	s.recordSuccessfulLogin(ctx, user.ID)
	span.SetStatus(codes.Ok, "Login successful")
	span.SetAttributes(
		attribute.String("auth.user_id", user.ID.String()),
		attribute.Bool("auth.success", true),
	)

	logger.InfoContext(ctx, "Login successful",
		"user_id", user.ID.String(),
		"last_login", user.CreatedAt,
	)

	return &user, nil
}

func (s *AuthService) Register(ctx context.Context, req RegisterRequest) (*model.User, error) {
	tracer := otel.Tracer("askfrank.auth")
	ctx, span := tracer.Start(ctx, "auth.register")
	defer span.End()

	span.SetAttributes(
		attribute.String("auth.email", req.Email),
		attribute.String("auth.action", "register"),
		attribute.Bool("auth.newsletter", req.Newsletter),
	)

	logger := slog.With(
		"operation", "register",
		"email", req.Email,
		"newsletter", req.Newsletter,
		"trace_id", span.SpanContext().TraceID().String(),
		"span_id", span.SpanContext().SpanID().String(),
	)

	logger.InfoContext(ctx, "Registration attempt started")

	// Check if user already exists
	if _, err := s.repo.GetUserByEmail(req.Email); err == nil {
		span.SetStatus(codes.Error, "User already exists")
		logger.WarnContext(ctx, "Registration failed - user already exists")
		return nil, ErrUserAlreadyExists
	}

	// Validate password strength
	if err := s.validatePasswordStrength(req.Password); err != nil {
		span.SetStatus(codes.Error, "Weak password")
		span.RecordError(err)
		logger.WarnContext(ctx, "Registration failed - weak password",
			"error", err.Error(),
		)
		return nil, err
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		span.SetStatus(codes.Error, "Password hashing failed")
		span.RecordError(err)
		logger.ErrorContext(ctx, "Failed to hash password",
			"error", err.Error(),
		)
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
		span.SetStatus(codes.Error, "User creation failed")
		span.RecordError(err)
		logger.ErrorContext(ctx, "Failed to create user in database",
			"error", err.Error(),
			"user_id", user.ID.String(),
		)
		return nil, err
	}

	// Send verification email
	verificationToken, err := s.generateVerificationToken(user.ID)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate verification token",
			"error", err.Error(),
			"user_id", user.ID.String(),
		)
		return nil, err
	}

	if err := s.emailService.SendVerificationEmail(user.Email, verificationToken); err != nil {
		// Log error but don't fail registration
		logger.WarnContext(ctx, "Failed to send verification email",
			"error", err.Error(),
			"user_id", user.ID.String(),
		)
	} else {
		logger.InfoContext(ctx, "Verification email sent",
			"user_id", user.ID.String(),
		)
	}

	span.SetStatus(codes.Ok, "Registration successful")
	span.SetAttributes(
		attribute.String("auth.user_id", user.ID.String()),
		attribute.Bool("auth.success", true),
	)

	logger.InfoContext(ctx, "Registration successful",
		"user_id", user.ID.String(),
		"email_verified", user.EmailVerified,
	)

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
	slog.WarnContext(ctx, "Failed login attempt recorded",
		"email", email,
		"timestamp", time.Now(),
	)
}

func (s *AuthService) recordSuccessfulLogin(ctx context.Context, userID uuid.UUID) {
	slog.InfoContext(ctx, "Successful login recorded",
		"user_id", userID.String(),
		"timestamp", time.Now(),
	)
}

func (s *AuthService) generateVerificationToken(userID uuid.UUID) (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
