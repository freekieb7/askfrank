package model

import (
	"time"

	"github.com/google/uuid"
)

type Person struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

type System struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
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

type Organization struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}
