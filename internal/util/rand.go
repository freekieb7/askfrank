package util

import (
	"crypto/rand"
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
