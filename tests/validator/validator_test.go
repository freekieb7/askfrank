package validator_test

import (
	"askfrank/internal/service"
	"askfrank/internal/validator"
	"askfrank/tests/testutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidator_PasswordStrength(t *testing.T) {
	v := validator.New()

	tests := []struct {
		name    string
		request service.RegisterRequest
		isValid bool
	}{
		{
			name: "valid_password",
			request: service.RegisterRequest{
				Email:           "test@example.com",
				Password:        testutil.ValidPassword(),
				ConfirmPassword: testutil.ValidPassword(),
				Terms:           true,
				Newsletter:      false,
			},
			isValid: true,
		},
		{
			name: "too_short",
			request: service.RegisterRequest{
				Email:           "test@example.com",
				Password:        "Short1!",
				ConfirmPassword: "Short1!",
				Terms:           true,
				Newsletter:      false,
			},
			isValid: false,
		},
		{
			name: "no_uppercase",
			request: service.RegisterRequest{
				Email:           "test@example.com",
				Password:        "nouppercase123!",
				ConfirmPassword: "nouppercase123!",
				Terms:           true,
				Newsletter:      false,
			},
			isValid: false,
		},
		{
			name: "no_lowercase",
			request: service.RegisterRequest{
				Email:           "test@example.com",
				Password:        "NOLOWERCASE123!",
				ConfirmPassword: "NOLOWERCASE123!",
				Terms:           true,
				Newsletter:      false,
			},
			isValid: false,
		},
		{
			name: "no_digits",
			request: service.RegisterRequest{
				Email:           "test@example.com",
				Password:        "NoDigitsHere!",
				ConfirmPassword: "NoDigitsHere!",
				Terms:           true,
				Newsletter:      false,
			},
			isValid: false,
		},
		{
			name: "no_special_chars",
			request: service.RegisterRequest{
				Email:           "test@example.com",
				Password:        "NoSpecialChars123",
				ConfirmPassword: "NoSpecialChars123",
				Terms:           true,
				Newsletter:      false,
			},
			isValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.request)
			if tt.isValid {
				assert.NoError(t, err, "Password should be valid: %s", tt.request.Password)
			} else {
				assert.Error(t, err, "Password should be invalid: %s", tt.request.Password)
			}
		})
	}
}

func TestValidator_DisposableEmail(t *testing.T) {
	v := validator.New()

	tests := []struct {
		name    string
		email   string
		isValid bool
	}{
		{
			name:    "valid_email",
			email:   "user@example.com",
			isValid: true,
		},
		{
			name:    "gmail_email",
			email:   "user@gmail.com",
			isValid: true,
		},
		{
			name:    "disposable_10minutemail",
			email:   "user@10minutemail.com",
			isValid: false,
		},
		{
			name:    "disposable_guerrillamail",
			email:   "user@guerrillamail.com",
			isValid: false,
		},
		{
			name:    "disposable_mailinator",
			email:   "user@mailinator.com",
			isValid: false,
		},
		{
			name:    "disposable_tempmail",
			email:   "user@tempmail.org",
			isValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := service.RegisterRequest{
				Email:           tt.email,
				Password:        testutil.ValidPassword(),
				ConfirmPassword: testutil.ValidPassword(),
				Terms:           true,
				Newsletter:      false,
			}

			err := v.Validate(request)
			if tt.isValid {
				assert.NoError(t, err, "Email should be valid: %s", tt.email)
			} else {
				assert.Error(t, err, "Email should be invalid (disposable): %s", tt.email)
			}
		})
	}
}

func TestValidator_RequiredFields(t *testing.T) {
	v := validator.New()

	tests := []struct {
		name    string
		request service.RegisterRequest
		isValid bool
	}{
		{
			name: "missing_email",
			request: service.RegisterRequest{
				Email:           "",
				Password:        testutil.ValidPassword(),
				ConfirmPassword: testutil.ValidPassword(),
				Terms:           true,
				Newsletter:      false,
			},
			isValid: false,
		},
		{
			name: "missing_password",
			request: service.RegisterRequest{
				Email:           "test@example.com",
				Password:        "",
				ConfirmPassword: "",
				Terms:           true,
				Newsletter:      false,
			},
			isValid: false,
		},
		{
			name: "password_mismatch",
			request: service.RegisterRequest{
				Email:           "test@example.com",
				Password:        testutil.ValidPassword(),
				ConfirmPassword: "DifferentPassword123!",
				Terms:           true,
				Newsletter:      false,
			},
			isValid: false,
		},
		{
			name: "terms_not_accepted",
			request: service.RegisterRequest{
				Email:           "test@example.com",
				Password:        testutil.ValidPassword(),
				ConfirmPassword: testutil.ValidPassword(),
				Terms:           false,
				Newsletter:      false,
			},
			isValid: false,
		},
		{
			name: "invalid_email_format",
			request: service.RegisterRequest{
				Email:           "invalid-email",
				Password:        testutil.ValidPassword(),
				ConfirmPassword: testutil.ValidPassword(),
				Terms:           true,
				Newsletter:      false,
			},
			isValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.request)
			if tt.isValid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestValidator_LoginRequest(t *testing.T) {
	v := validator.New()

	tests := []struct {
		name    string
		request service.LoginRequest
		isValid bool
	}{
		{
			name: "valid_login",
			request: service.LoginRequest{
				Email:    "user@example.com",
				Password: "password123",
			},
			isValid: true,
		},
		{
			name: "missing_email",
			request: service.LoginRequest{
				Email:    "",
				Password: "password123",
			},
			isValid: false,
		},
		{
			name: "missing_password",
			request: service.LoginRequest{
				Email:    "user@example.com",
				Password: "",
			},
			isValid: false,
		},
		{
			name: "invalid_email_format",
			request: service.LoginRequest{
				Email:    "invalid-email",
				Password: "password123",
			},
			isValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.request)
			if tt.isValid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}
