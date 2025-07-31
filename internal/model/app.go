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

type Group struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

type GroupMemberType string

const (
	GroupMemberTypeUser   GroupMemberType = "user"
	GroupMemberTypeSystem GroupMemberType = "system"
	GroupMemberTypeGroup  GroupMemberType = "group"
)

type GroupMember struct {
	GroupID  uuid.UUID       `json:"group_id"`
	Type     GroupMemberType `json:"type"` // "user", "system" or "group"
	MemberID uuid.UUID       `json:"member_id"`
}

type Folder struct {
	ID           uuid.UUID `json:"id"`
	OwnerID      uuid.UUID `json:"owner_id"`
	Name         string    `json:"name"`
	LastModified time.Time `json:"last_modified"`
}

type Document struct {
	ID           uuid.UUID  `json:"id"`
	OwnerID      uuid.UUID  `json:"owner_id"`
	Name         string     `json:"name"`
	Size         uint64     `json:"size"`
	ContentType  string     `json:"content_type"`
	StorageKey   string     `json:"storage_key"`
	FolderID     *uuid.UUID `json:"folder_id,omitempty"`
	LastModified time.Time  `json:"last_modified"`
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

type AuditAction string

const (
	AuditActionCreate AuditAction = "create"
	AuditActionRead   AuditAction = "read"
	AuditActionUpdate AuditAction = "update"
	AuditActionDelete AuditAction = "delete"
	AuditActionLogin  AuditAction = "login"
	AuditActionLogout AuditAction = "logout"
)

type AuditLog struct {
	ID         uuid.UUID              `json:"id"`
	UserID     *uuid.UUID             `json:"user_id,omitempty"`
	EntityType string                 `json:"entity_type"`
	EntityID   uuid.UUID              `json:"entity_id"`
	Action     AuditAction            `json:"action"`
	OldValues  map[string]interface{} `json:"old_values,omitempty"`
	NewValues  map[string]interface{} `json:"new_values,omitempty"`
	IPAddress  string                 `json:"ip_address,omitempty"`
	UserAgent  string                 `json:"user_agent,omitempty"`
	SessionID  string                 `json:"session_id,omitempty"`
	CreatedAt  time.Time              `json:"created_at"`
}

type AuditFilters struct {
	UserID     *uuid.UUID
	EntityType string
	Action     AuditAction
	StartDate  *time.Time
	EndDate    *time.Time
	Limit      int
	Offset     int
}
