package util

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
)

// RandomString generates a secure random string of the specified length.
func GenerateRandomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// SecureCompare performs a constant-time comparison of two strings to prevent timing attacks.
func SecureCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
