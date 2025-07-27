package service_test

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// BenchmarkPasswordHashing benchmarks password hashing operations
func BenchmarkPasswordHashing(b *testing.B) {
	password := "TestPassword123!"

	b.ReportAllocs()

	for b.Loop() {
		// Simulate bcrypt hashing (without actual bcrypt dependency)
		_ = hashPassword(password)
	}
}

// BenchmarkTokenGeneration benchmarks JWT token generation
func BenchmarkTokenGeneration(b *testing.B) {
	userID := "123e4567-e89b-12d3-a456-426614174000"
	email := "test@example.com"

	b.ReportAllocs()

	for b.Loop() {
		// Simulate JWT token generation
		_ = generateToken(userID, email)
	}
}

// BenchmarkEmailValidation benchmarks email validation
func BenchmarkEmailValidation(b *testing.B) {
	emails := []string{
		"valid@example.com",
		"invalid.email",
		"test@test.co.uk",
		"user+tag@domain.com",
		"not_an_email",
	}

	b.ReportAllocs()

	for i := 0; b.Loop(); i++ {
		email := emails[i%len(emails)]
		_ = isValidEmail(email)
	}
}

// BenchmarkPasswordValidation benchmarks password validation
func BenchmarkPasswordValidation(b *testing.B) {
	passwords := []string{
		"ValidPassword123!",
		"weak",
		"NoNumbers!",
		"nonumbersorspecial",
		"AnotherValid123$",
	}

	b.ReportAllocs()

	for i := 0; b.Loop(); i++ {
		password := passwords[i%len(passwords)]
		_ = isValidPassword(password)
	}
}

// Simple helper functions for benchmarking (simulating real operations)

func hashPassword(password string) string {
	// Simulate expensive hashing operation
	time.Sleep(time.Microsecond) // Simulate bcrypt work
	return "hashed_" + password
}

func generateToken(userID, email string) string {
	// Simulate JWT token generation
	bytes := make([]byte, 16)
	_, _ = rand.Read(bytes)
	return hex.EncodeToString(bytes) + "." + userID + "." + email
}

func isValidEmail(email string) bool {
	// Simple email validation for benchmarking
	return strings.Contains(email, "@") && strings.Contains(email, ".")
}

func isValidPassword(password string) bool {
	// Simple password validation for benchmarking
	if len(password) < 8 {
		return false
	}

	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false

	for _, char := range password {
		switch {
		case char >= 'A' && char <= 'Z':
			hasUpper = true
		case char >= 'a' && char <= 'z':
			hasLower = true
		case char >= '0' && char <= '9':
			hasDigit = true
		case strings.ContainsRune("!@#$%^&*", char):
			hasSpecial = true
		}
	}

	return hasUpper && hasLower && hasDigit && hasSpecial
}
