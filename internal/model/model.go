package model

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID              uuid.UUID `json:"id"`
	Name            string    `json:"name"`
	Email           string    `json:"email"`
	PasswordHash    string    `json:"-"`
	Role            string    `json:"role"`
	IsEmailVerified bool      `json:"is_email_verified"`
	EmailVerified   bool      `json:"email_verified"` // Keep for backward compatibility
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type UserRegistration struct {
	ID             uuid.UUID `json:"id"`
	UserID         uuid.UUID `json:"user_id"`
	ActivationCode string    `json:"activation_code"`
	CreatedAt      time.Time `json:"created_at"`
}

type AdminStats struct {
	TotalUsers           int `json:"total_users"`
	ActiveUsers          int `json:"active_users"`
	PendingRegistrations int `json:"pending_registrations"`
	TodayRegistrations   int `json:"today_registrations"`
}

type UserWithRegistration struct {
	User         User              `json:"user"`
	Registration *UserRegistration `json:"registration,omitempty"`
}
