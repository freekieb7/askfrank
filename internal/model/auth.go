package model

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

type Role string

const (
	RoleUser  Role = "user"
	RoleAdmin Role = "admin"
)

func (r Role) String() string {
	return string(r)
}

func (r *Role) Scan(value any) error {
	if str, ok := value.(string); ok {
		*r = Role(str)
		return nil
	}
	return fmt.Errorf("cannot scan %T into Role", value)
}

type User struct {
	ID              uuid.UUID `json:"id"`
	Name            string    `json:"name"`
	Email           string    `json:"email"`
	PasswordHash    string    `json:"-"`
	Role            Role      `json:"role"`
	IsEmailVerified bool      `json:"is_email_verified"`
	CreatedAt       time.Time `json:"created_at"`
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
