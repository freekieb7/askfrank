package util

import (
	"crypto/rand"
	"encoding/base64"
)

type Optional[T any] struct {
	Value T
	Some  bool
}

func RandomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
