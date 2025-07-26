package validator

import (
	"regexp"
	"strings"

	"github.com/go-playground/validator/v10"
)

var disposableEmailDomains = []string{
	"10minutemail.com", "guerrillamail.com", "mailinator.com", "tempmail.org",
	"yopmail.com", "maildrop.cc", "temp-mail.org", "throwaway.email",
}

type Validator struct {
	validate *validator.Validate
}

func New() *Validator {
	v := validator.New()

	// Custom validators
	v.RegisterValidation("password_strength", validatePasswordStrength)
	v.RegisterValidation("no_disposable_email", validateNoDisposableEmail)

	return &Validator{validate: v}
}

func (v *Validator) Validate(i interface{}) error {
	return v.validate.Struct(i)
}

func validatePasswordStrength(fl validator.FieldLevel) bool {
	password := fl.Field().String()

	// At least 8 characters
	if len(password) < 8 {
		return false
	}

	// Must contain uppercase, lowercase, digit, and special char
	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	hasDigit := regexp.MustCompile(`\d`).MatchString(password)
	hasSpecial := regexp.MustCompile(`[!@#$%^&*(),.?":{}|<>]`).MatchString(password)

	return hasUpper && hasLower && hasDigit && hasSpecial
}

func validateNoDisposableEmail(fl validator.FieldLevel) bool {
	email := fl.Field().String()
	emailParts := strings.Split(email, "@")
	if len(emailParts) != 2 {
		return false
	}

	domain := strings.ToLower(emailParts[1])
	for _, disposableDomain := range disposableEmailDomains {
		if domain == disposableDomain {
			return false
		}
	}

	return true
}
