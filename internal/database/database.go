package database

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hp/internal/util"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type Database struct {
	*Postgres
	logger *slog.Logger
}

func NewDatabase(postgres *Postgres, logger *slog.Logger) Database {
	return Database{
		Postgres: postgres,
		logger:   logger,
	}
}

type User struct {
	ID               uuid.UUID
	Name             string
	Email            string
	PasswordHash     string
	IsEmailVerified  bool
	IsBot            bool
	StripeCustomerID string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type Session struct {
	ID        uuid.UUID
	Token     string
	UserID    util.Optional[uuid.UUID]
	UserAgent string
	IPAddress string
	Data      map[string]any
	ExpiresAt time.Time
	RevokedAt util.Optional[time.Time]
	CreatedAt time.Time
	UpdatedAt time.Time
}

type PasswordReset struct {
	ID        uuid.UUID
	Token     string
	UserID    uuid.UUID
	ExpiresAt time.Time
	UsedAt    util.Optional[time.Time]
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Group struct {
	ID        uuid.UUID
	Name      string
	OwnerID   uuid.UUID
	CreatedAt time.Time
	UpdatedAt time.Time
}

type GroupMember struct {
	ID        uuid.UUID
	GroupID   uuid.UUID
	UserID    uuid.UUID
	Role      string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type GroupInvite struct {
	ID              uuid.UUID
	Token           string
	GroupID         uuid.UUID
	InvitedByUserID uuid.UUID
	Email           string
	Role            string
	ExpiresAt       time.Time
	UsedAt          util.Optional[time.Time]
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type File struct {
	ID        uuid.UUID
	OwnerID   uuid.UUID
	ParentID  util.Optional[uuid.UUID]
	Name      string
	MimeType  string
	Path      util.Optional[string]
	S3Key     util.Optional[string]
	SizeBytes int64
	CreatedAt time.Time
	UpdatedAt time.Time
}

type FileShare struct {
	ID               uuid.UUID
	FileID           uuid.UUID
	SharedWithUserID uuid.UUID
	Permission       string // e.g., "read", "write"
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type AuditLogEvent struct {
	ID        uuid.UUID
	OwnerID   uuid.UUID
	EventType string
	EventData json.RawMessage
	CreatedAt time.Time
}

type WebhookEventType string

const (
	WebhookEventTypeFileCreated WebhookEventType = "file.created"
	WebhookEventTypeFileDeleted WebhookEventType = "file.deleted"
	WebhookEventTypeUserLogin   WebhookEventType = "user.login"
	WebhookEventTypeUserLogout  WebhookEventType = "user.logout"
)

type WebhookSubscription struct {
	ID          uuid.UUID
	OwnerID     uuid.UUID
	Name        string
	Description string
	URL         string
	Secret      string
	EventTypes  []WebhookEventType
	IsActive    bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type WebhookEvent struct {
	ID        uuid.UUID
	EventType WebhookEventType
	Payload   json.RawMessage
	CreatedAt time.Time
	UpdatedAt time.Time
}

type WebhookDeliveryStatus string

const (
	WebhookDeliveryStatusPending WebhookDeliveryStatus = "pending"
	WebhookDeliveryStatusSent    WebhookDeliveryStatus = "sent"
	WebhookDeliveryStatusFailed  WebhookDeliveryStatus = "failed"
)

type WebhookDelivery struct {
	ID               uuid.UUID
	EventID          uuid.UUID
	SubscriptionID   uuid.UUID
	URL              string
	Secret           string
	Payload          []byte
	EventType        WebhookEventType
	Status           WebhookDeliveryStatus
	RetryCount       int
	LastAttemptAt    util.Optional[time.Time]
	NextAttemptAt    util.Optional[time.Time]
	LastResponseCode util.Optional[int]
	LastResponseBody util.Optional[string]
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type CalendarEventStatus string

const (
	CalendarEventStatusTentative CalendarEventStatus = "tentative"
	CalendarEventStatusConfirmed CalendarEventStatus = "confirmed"
	CalendarEventStatusCancelled CalendarEventStatus = "cancelled"
)

type CalendarEvent struct {
	ID          uuid.UUID
	OwnerID     uuid.UUID
	Title       string
	Description string
	StartTime   time.Time
	EndTime     time.Time
	AllDay      bool
	Status      CalendarEventStatus
	Location    util.Optional[string]
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type CalendarEventAttendeeStatus string

const (
	CalendarEventAttendeeStatusPending  CalendarEventAttendeeStatus = "pending"
	CalendarEventAttendeeStatusAccepted CalendarEventAttendeeStatus = "accepted"
	CalendarEventAttendeeStatusDeclined CalendarEventAttendeeStatus = "declined"
)

type CalendarEventAttendee struct {
	ID              uuid.UUID
	CalendarEventID uuid.UUID
	UserID          util.Optional[uuid.UUID]
	Email           util.Optional[string]
	Status          CalendarEventAttendeeStatus
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type NotificationType string

const (
	NotificationTypeInfo    NotificationType = "info"
	NotificationTypeWarning NotificationType = "warning"
	NotificationTypeError   NotificationType = "error"
)

type Notification struct {
	ID        uuid.UUID
	OwnerID   uuid.UUID
	Type      NotificationType
	Message   string
	Read      bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

type OAuthClient struct {
	ID            uuid.UUID
	OwnerID       uuid.UUID
	Name          string
	Secret        string
	RedirectURIs  []string
	IsPublic      bool
	AllowedScopes []string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type OAuthAuthorizationCode struct {
	ID                  uuid.UUID
	Token               string
	ClientID            uuid.UUID
	UserID              uuid.UUID
	Scopes              []string
	CodeChallenge       util.Optional[string]
	CodeChallengeMethod util.Optional[string]
	RedirectURI         string
	ExpiresAt           time.Time
	UsedAt              util.Optional[time.Time]
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

type OAuthAccessToken struct {
	ID        uuid.UUID
	Token     string
	ClientID  uuid.UUID
	UserID    uuid.UUID
	Data      OAuthAccessTokenData
	ExpiresAt time.Time
	RevokedAt util.Optional[time.Time]
	CreatedAt time.Time
	UpdatedAt time.Time
}

type OAuthAccessTokenData struct {
	Scopes []string `json:"scopes"`
}

type OAuthRefreshTokenChain struct {
	ID        uuid.UUID
	ClientID  uuid.UUID
	UserID    uuid.UUID
	Scopes    []string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type OAuthRefreshToken struct {
	ID        uuid.UUID
	Token     string
	ChainID   uuid.UUID
	ExpiresAt time.Time
	UsedAt    util.Optional[time.Time]
	RevokedAt util.Optional[time.Time]
	CreatedAt time.Time
	UpdatedAt time.Time
}

var (
	ErrUserNotFound                   = errors.New("user not found")
	ErrOAuthRefreshTokenNotFound      = errors.New("oAuth refresh token not found")
	ErrOAuthAccessTokenNotFound       = errors.New("oAuth access token not found")
	ErrOAuthAuthCodeNotFound          = errors.New("oAuth authorization code not found")
	ErrOAuthSigningKeyNotFound        = errors.New("oAuth signing key not found")
	ErrOAuthClientNotFound            = errors.New("oAuth client not found")
	ErrFileNotFound                   = errors.New("file not found")
	ErrCalendarNotFound               = errors.New("calendar not found")
	ErrCalendarEventNotFound          = errors.New("calendar event not found")
	ErrGroupNotFound                  = errors.New("group not found")
	ErrGroupInviteNotFound            = errors.New("group invite not found")
	ErrFileShareNotFound              = errors.New("file share not found")
	ErrPasswordResetNotFound          = errors.New("password reset not found")
	ErrWebhookNotFound                = errors.New("webhook not found")
	ErrWebhookEventNotFound           = errors.New("webhook event not found")
	ErrAuditLogNotFound               = errors.New("audit log not found")
	ErrAuditLogEventNotFound          = errors.New("audit log event not found")
	ErrNotificationNotFound           = errors.New("notification not found")
	ErrOAuthAuthorizationCodeNotFound = errors.New("oAuth authorization code not found")
	ErrOAuthRefreshTokenChainNotFound = errors.New("oAuth refresh token chain not found")
	ErrSessionNotFound                = errors.New("session not found")
)

type CreateUserParams struct {
	Name             string
	Email            string
	PasswordHash     string
	IsEmailVerified  bool
	IsBot            bool
	StripeCustomerID string
}

func (db *Database) CreateUser(ctx context.Context, params CreateUserParams) (User, error) {
	user := User{
		ID:               uuid.New(),
		Name:             params.Name,
		Email:            params.Email,
		PasswordHash:     params.PasswordHash,
		IsEmailVerified:  params.IsEmailVerified,
		IsBot:            params.IsBot,
		StripeCustomerID: params.StripeCustomerID,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	if _, err := db.Exec(ctx, `INSERT INTO tbl_user (id, name, email, password_hash, is_email_verified, is_bot, stripe_customer_id, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		user.ID, user.Name, user.Email, user.PasswordHash, user.IsEmailVerified, user.IsBot, user.StripeCustomerID, user.CreatedAt, user.UpdatedAt); err != nil {
		err = fmt.Errorf("CreateUser: failed to insert user (email=%s): %w", user.Email, err)
		db.logger.Error("CreateUser error", "error", err)
		return user, err
	}
	return user, nil
}

type ListUsersParams struct {
	Email           util.Optional[string]
	Name            util.Optional[string]
	IsBot           util.Optional[bool]
	IsEmailVerified util.Optional[bool]
}

func (db *Database) ListUsers(ctx context.Context, params ListUsersParams) ([]User, error) {
	var users []User

	var query strings.Builder
	query.WriteString(`SELECT id, name, email, password_hash, is_email_verified, is_bot, stripe_id, created_at, updated_at FROM tbl_user`)
	var args []any
	argNum := 1

	if params.Email.Some {
		query.WriteString(fmt.Sprintf(" WHERE email = $%d", argNum))
		args = append(args, params.Email.Data)
		argNum++
	}

	if params.Name.Some {
		query.WriteString(fmt.Sprintf(" AND name = $%d", argNum))
		args = append(args, params.Name.Data)
		argNum++
	}

	if params.IsBot.Some {
		query.WriteString(fmt.Sprintf(" AND is_bot = $%d", argNum))
		args = append(args, params.IsBot.Data)
		argNum++
	}

	if params.IsEmailVerified.Some {
		query.WriteString(fmt.Sprintf(" AND is_email_verified = $%d", argNum))
		args = append(args, params.IsEmailVerified.Data)
		argNum++
	}

	rows, err := db.Query(ctx, query.String(), args...)
	if err != nil {
		db.logger.Error("ListUsers error", "error", err)
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.Name, &user.Email, &user.PasswordHash, &user.IsEmailVerified, &user.IsBot, &user.StripeCustomerID, &user.CreatedAt, &user.UpdatedAt); err != nil {
			db.logger.Error("ListUsers error", "error", err)
			return nil, err
		}
		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		db.logger.Error("ListUsers error", "error", err)
		return nil, err
	}

	return users, nil
}

func (db *Database) GetUserByID(ctx context.Context, id uuid.UUID) (User, error) {
	return db.GetUser(ctx, GetUserParams{ID: util.Some(id)})
}

func (db *Database) GetUserByEmail(ctx context.Context, email string) (User, error) {
	return db.GetUser(ctx, GetUserParams{Email: util.Some(email)})
}

type GetUserParams struct {
	ID    util.Optional[uuid.UUID]
	Email util.Optional[string]
}

func (db *Database) GetUser(ctx context.Context, params GetUserParams) (User, error) {
	var user User

	var query strings.Builder
	query.WriteString(`SELECT id, name, email, password_hash, is_email_verified, is_bot, stripe_customer_id, created_at, updated_at FROM tbl_user WHERE 1=1`)
	var args []any
	argNum := 1

	if params.ID.Some {
		query.WriteString(fmt.Sprintf(" AND id = $%d", argNum))
		args = append(args, params.ID.Data)
		argNum++
	}

	if params.Email.Some {
		query.WriteString(fmt.Sprintf(" AND email = $%d", argNum))
		args = append(args, params.Email.Data)
		argNum++
	}

	err := db.QueryRow(ctx, query.String(), args...).Scan(
		&user.ID, &user.Name, &user.Email, &user.PasswordHash, &user.IsEmailVerified, &user.IsBot, &user.StripeCustomerID, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return user, ErrUserNotFound
		}
		err = fmt.Errorf("GetUser: failed to scan user (id=%s): %w", params.ID.Data, err)
		db.logger.Error("GetUser error", "error", err)
		return user, err
	}
	return user, nil
}

type UpdateUserParams struct {
	Name            util.Optional[string]
	Email           util.Optional[string]
	PasswordHash    util.Optional[[]byte]
	IsEmailVerified util.Optional[bool]
	IsBot           util.Optional[bool]
	DeletedAt       util.Optional[time.Time]
}

func (db *Database) UpdateUserByID(ctx context.Context, userID uuid.UUID, params UpdateUserParams) error {
	var query strings.Builder
	args := []any{}
	argNum := 1
	query.WriteString("UPDATE tbl_user SET ")

	if params.Name.Some {
		query.WriteString(fmt.Sprintf("name = $%d, ", argNum))
		args = append(args, params.Name)
		argNum++
	}

	if params.Email.Some {
		query.WriteString(fmt.Sprintf("email = $%d, ", argNum))
		args = append(args, params.Email)
		argNum++
	}

	if params.PasswordHash.Some {
		query.WriteString(fmt.Sprintf("password_hash = $%d, ", argNum))
		args = append(args, params.PasswordHash)
		argNum++
	}

	if params.IsEmailVerified.Some {
		query.WriteString(fmt.Sprintf("is_email_verified = $%d, ", argNum))
		args = append(args, params.IsEmailVerified)
		argNum++
	}

	if params.IsBot.Some {
		query.WriteString(fmt.Sprintf("is_bot = $%d, ", argNum))
		args = append(args, params.IsBot)
		argNum++
	}

	query.WriteString(fmt.Sprintf("updated_at = $%d WHERE id = $%d", argNum, argNum+1))
	args = append(args, time.Now(), userID)

	if _, err := db.Exec(ctx, query.String(), args...); err != nil {
		err = fmt.Errorf("UpdateUser: failed to update user (id=%s): %w", userID, err)
		db.logger.Error("UpdateUser error", "error", err)
		return err
	}
	return nil
}

func (db *Database) DeleteUserByID(ctx context.Context, userID uuid.UUID) error {
	if _, err := db.Exec(ctx, `DELETE FROM tbl_user WHERE id = $1`, userID); err != nil {
		err = fmt.Errorf("DeleteUser: failed to delete user (id=%s): %w", userID, err)
		db.logger.Error("DeleteUser error", "error", err)
		return err
	}
	return nil
}

type CreatePasswordResetParams struct {
	Token     string
	UserID    uuid.UUID
	ExpiresAt time.Time
	UsedAt    util.Optional[time.Time]
}

func (db *Database) CreatePasswordReset(ctx context.Context, params CreatePasswordResetParams) (PasswordReset, error) {
	reset := PasswordReset{
		ID:        uuid.New(),
		Token:     params.Token,
		UserID:    params.UserID,
		ExpiresAt: params.ExpiresAt,
		UsedAt:    params.UsedAt,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	if _, err := db.Exec(ctx, `INSERT INTO tbl_password_reset (id, token, user_id, expires_at, used_at, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		reset.ID, reset.Token, reset.UserID, reset.ExpiresAt, reset.UsedAt, reset.CreatedAt, reset.UpdatedAt); err != nil {
		err = fmt.Errorf("CreatePasswordReset: failed to insert password reset (user_id=%s): %w", reset.UserID, err)
		db.logger.Error("CreatePasswordReset error", "error", err)
		return reset, err
	}
	return reset, nil
}

type ListPasswordResetsParams struct {
	UserID util.Optional[uuid.UUID]
}

func (db *Database) ListPasswordResets(ctx context.Context, params ListPasswordResetsParams) ([]PasswordReset, error) {
	var resets []PasswordReset

	var query strings.Builder
	query.WriteString(`SELECT id, token, user_id, expires_at, used_at, created_at, updated_at FROM tbl_password_reset WHERE 1=1`)
	var args []any
	argNum := 1

	if params.UserID.Some {
		query.WriteString(fmt.Sprintf(" AND user_id = $%d", argNum))
		args = append(args, params.UserID)
		argNum++
	}

	rows, err := db.Query(ctx, query.String(), args...)
	if err != nil {
		db.logger.Error("ListPasswordResets error", "error", err)
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var reset PasswordReset
		if err := rows.Scan(&reset.ID, &reset.Token, &reset.UserID, &reset.ExpiresAt, &reset.UsedAt, &reset.CreatedAt, &reset.UpdatedAt); err != nil {
			db.logger.Error("ListPasswordResets error", "error", err)
			return nil, err
		}
		resets = append(resets, reset)
	}

	if err := rows.Err(); err != nil {
		db.logger.Error("ListPasswordResets error", "error", err)
		return nil, err
	}

	return resets, nil
}

type UpdatePasswordResetParams struct {
	UsedAt util.Optional[time.Time]
}

func (db *Database) UpdatePasswordResetByID(ctx context.Context, id uuid.UUID, params UpdatePasswordResetParams) error {
	var query strings.Builder
	query.WriteString(`UPDATE tbl_password_reset SET `)
	args := []any{}
	argNum := 1

	if params.UsedAt.Some {
		query.WriteString(fmt.Sprintf("used_at = $%d, ", argNum))
		args = append(args, params.UsedAt)
		argNum++
	}

	query.WriteString(fmt.Sprintf("updated_at = $%d WHERE id = $%d", argNum, argNum+1))
	args = append(args, time.Now(), id)

	if _, err := db.Exec(ctx, query.String(), args...); err != nil {
		err = fmt.Errorf("UpdatePasswordReset: failed to update password reset (id=%s): %w", id, err)
		db.logger.Error("UpdatePasswordReset error", "error", err)
		return err
	}
	return nil
}

type CreateGroupParams struct {
	Name string
}

func (db *Database) CreateGroup(ctx context.Context, params CreateGroupParams) (Group, error) {
	group := Group{
		ID:        uuid.New(),
		Name:      params.Name,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if _, err := db.Exec(ctx, `INSERT INTO tbl_group (id, name, created_at, updated_at) VALUES ($1, $2, $3, $4)`,
		group.ID, group.Name, group.CreatedAt, group.UpdatedAt); err != nil {
		err = fmt.Errorf("CreateGroup: failed to insert group (id=%s): %w", group.ID, err)
		db.logger.Error("CreateGroup error", "error", err)
		return group, err
	}
	return group, nil
}

type ListGroupsParams struct {
	OwnerID util.Optional[uuid.UUID]
}

func (db *Database) ListGroups(ctx context.Context, params ListGroupsParams) ([]Group, error) {
	var groups []Group

	var query strings.Builder
	query.WriteString(`SELECT id, name, owner_id, created_at, updated_at FROM tbl_group`)
	var args []any
	argNum := 1

	if params.OwnerID.Some {
		query.WriteString(fmt.Sprintf(" WHERE owner_id = $%d", argNum))
		args = append(args, params.OwnerID)
		argNum++
	}

	rows, err := db.Query(ctx, query.String(), args...)
	if err != nil {
		db.logger.Error("ListGroups error", "error", err)
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var group Group
		if err := rows.Scan(&group.ID, &group.Name, &group.OwnerID, &group.CreatedAt, &group.UpdatedAt); err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return groups, nil
}

func (db *Database) GetGroupByID(ctx context.Context, id uuid.UUID) (Group, error) {
	var group Group

	query := `SELECT id, name, created_at, updated_at FROM tbl_group WHERE id = $1 LIMIT 1`
	err := db.QueryRow(ctx, query, id).Scan(&group.ID, &group.Name, &group.CreatedAt, &group.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return group, ErrGroupNotFound
		}
		err = fmt.Errorf("GetGroup: failed to scan group (id=%s): %w", id, err)
		db.logger.Error("GetGroup error", "error", err)
		return group, err
	}
	return group, nil
}

type UpdateGroupParams struct {
	Name util.Optional[string]
}

func (db *Database) UpdateGroupByID(ctx context.Context, id uuid.UUID, params UpdateGroupParams) error {
	var query strings.Builder
	query.WriteString(`UPDATE tbl_group SET `)
	args := []any{}
	argNum := 1

	if params.Name.Some {
		query.WriteString(fmt.Sprintf("name = $%d, ", argNum))
		args = append(args, params.Name)
		argNum++
	}

	query.WriteString(fmt.Sprintf("updated_at = $%d WHERE id = $%d", argNum, argNum+1))
	args = append(args, time.Now(), id)

	if _, err := db.Exec(ctx, query.String(), args...); err != nil {
		err = fmt.Errorf("UpdateGroup: failed to update group (id=%s): %w", id, err)
		db.logger.Error("UpdateGroup error", "error", err)
		return err
	}
	return nil
}

func (db *Database) DeleteGroupByID(ctx context.Context, id uuid.UUID) error {
	if _, err := db.Exec(ctx, `DELETE FROM tbl_group WHERE id = $1`, id); err != nil {
		err = fmt.Errorf("DeleteGroup: failed to delete group (id=%s): %w", id, err)
		db.logger.Error("DeleteGroup error", "error", err)
		return err
	}
	return nil
}

type CreateGroupMemberParams struct {
	GroupID uuid.UUID
	UserID  uuid.UUID
	Role    string
}

func (db *Database) CreateGroupMember(ctx context.Context, params CreateGroupMemberParams) error {
	groupMember := GroupMember{
		ID:        uuid.New(),
		GroupID:   params.GroupID,
		UserID:    params.UserID,
		Role:      params.Role,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if _, err := db.Exec(ctx, `INSERT INTO tbl_group_member (id, group_id, user_id, role, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6)`,
		groupMember.ID, groupMember.GroupID, groupMember.UserID, groupMember.Role, groupMember.CreatedAt, groupMember.UpdatedAt); err != nil {
		err = fmt.Errorf("CreateGroupMember: failed to insert group member (group_id=%s, user_id=%s): %w", groupMember.GroupID, groupMember.UserID, err)
		db.logger.Error("CreateGroupMember error", "error", err)
		return err
	}
	return nil
}

type ListGroupMembersParams struct {
	GroupID util.Optional[uuid.UUID]
}

func (db *Database) ListGroupMembers(ctx context.Context, params ListGroupMembersParams) ([]GroupMember, error) {
	var members []GroupMember

	var query strings.Builder
	query.WriteString(`SELECT id, group_id, user_id, role, created_at, updated_at FROM tbl_group_member`)
	var args []any
	argNum := 1

	if params.GroupID.Some {
		query.WriteString(fmt.Sprintf(" WHERE group_id = $%d", argNum))
		args = append(args, params.GroupID)
		argNum++
	}

	rows, err := db.Query(ctx, query.String(), args...)
	if err != nil {
		db.logger.Error("ListGroupMembers error", "error", err)
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var member GroupMember
		if err := rows.Scan(&member.ID, &member.GroupID, &member.UserID, &member.Role, &member.CreatedAt, &member.UpdatedAt); err != nil {
			return nil, err
		}
		members = append(members, member)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return members, nil
}

// todo update group member

func (db *Database) DeleteGroupMemberByID(ctx context.Context, groupID, userID uuid.UUID) error {
	if _, err := db.Exec(ctx, `DELETE FROM tbl_group_member WHERE group_id = $1 AND user_id = $2`, groupID, userID); err != nil {
		err = fmt.Errorf("DeleteGroupMember: failed to delete group member (group_id=%s, user_id=%s): %w", groupID, userID, err)
		db.logger.Error("DeleteGroupMember error", "error", err)
		return err
	}
	return nil
}

type GroupInviteParams struct {
	ID              uuid.UUID
	GroupID         uuid.UUID
	InvitedByUserID uuid.UUID
	Email           string
	Token           string
	Role            string
}

func (db *Database) CreateGroupInvite(ctx context.Context, params GroupInviteParams) error {
	invite := GroupInvite{
		ID:              params.ID,
		Token:           params.Token,
		GroupID:         params.GroupID,
		InvitedByUserID: params.InvitedByUserID,
		Email:           params.Email,
		Role:            params.Role,
		ExpiresAt:       time.Now().Add(24 * time.Hour),
		UsedAt:          util.None[time.Time](),
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	if _, err := db.Exec(ctx, `INSERT INTO tbl_group_invite (id, token, group_id, invited_by_user_id, email, role, expires_at, used_at, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		invite.ID, invite.Token, invite.GroupID, invite.InvitedByUserID, invite.Email, invite.Role, invite.ExpiresAt, invite.UsedAt, invite.CreatedAt, invite.UpdatedAt); err != nil {
		err = fmt.Errorf("CreateGroupInvite: failed to insert group invite (group_id=%s, email=%s): %w", invite.GroupID, invite.Email, err)
		db.logger.Error("CreateGroupInvite error", "error", err)
		return err
	}
	return nil
}

type ListGroupInvitesParams struct {
	GroupID util.Optional[uuid.UUID]
}

func (db *Database) ListGroupInvites(ctx context.Context, params ListGroupInvitesParams) ([]GroupInvite, error) {
	var invites []GroupInvite

	var query strings.Builder
	query.WriteString(`SELECT id, token, group_id, invited_by_user_id, email, role, created_at, updated_at, expires_at, used_at FROM tbl_group_invite`)
	var args []any
	argNum := 1

	if params.GroupID.Some {
		query.WriteString(fmt.Sprintf(" WHERE group_id = $%d", argNum))
		args = append(args, params.GroupID)
		argNum++
	}

	rows, err := db.Query(ctx, query.String(), args...)
	if err != nil {
		db.logger.Error("ListGroupInvites error", "error", err)
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var invite GroupInvite
		if err := rows.Scan(&invite.ID, &invite.Token, &invite.GroupID, &invite.InvitedByUserID, &invite.Email, &invite.Role, &invite.CreatedAt, &invite.UpdatedAt, &invite.ExpiresAt, &invite.UsedAt); err != nil {
			return nil, err
		}
		invites = append(invites, invite)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return invites, nil
}

func (db *Database) GetGroupInviteByID(ctx context.Context, id uuid.UUID) (GroupInvite, error) {
	var invite GroupInvite

	query := `SELECT id, token, group_id, invited_by_user_id, email, role, created_at, updated_at, expires_at, used_at FROM tbl_group_invite WHERE id = $1`
	if err := db.QueryRow(ctx, query, id).Scan(&invite.ID, &invite.Token, &invite.GroupID, &invite.InvitedByUserID, &invite.Email, &invite.Role, &invite.CreatedAt, &invite.UpdatedAt, &invite.ExpiresAt, &invite.UsedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return GroupInvite{}, ErrGroupInviteNotFound
		}
		db.logger.Error("GetGroupInvite error", "error", err)
		return GroupInvite{}, err
	}

	return invite, nil
}

type UpdateGroupInviteParams struct {
	ExpiresAt util.Optional[time.Time]
	UsedAt    util.Optional[time.Time]
}

func (db *Database) UpdateGroupInviteByID(ctx context.Context, id uuid.UUID, params UpdateGroupInviteParams) error {
	var query strings.Builder
	query.WriteString(`UPDATE tbl_group_invite SET `)
	args := []any{}
	argNum := 1

	if params.ExpiresAt.Some {
		query.WriteString(fmt.Sprintf("expires_at = $%d, ", argNum))
		args = append(args, params.ExpiresAt)
		argNum++
	}

	if params.UsedAt.Some {
		query.WriteString(fmt.Sprintf("used_at = $%d, ", argNum))
		args = append(args, params.UsedAt)
		argNum++
	}

	query.WriteString(fmt.Sprintf("updated_at = $%d WHERE id = $%d", argNum, argNum+1))
	args = append(args, time.Now(), id)

	if _, err := db.Exec(ctx, query.String(), args...); err != nil {
		err = fmt.Errorf("UpdateGroupInvite: failed to update group invite (id=%s): %w", id, err)
		db.logger.Error("UpdateGroupInvite error", "error", err)
		return err
	}
	return nil
}

func (db *Database) DeleteGroupInvite(ctx context.Context, inviteID uuid.UUID) error {
	if _, err := db.Exec(ctx, `DELETE FROM tbl_group_invite WHERE id = $1`, inviteID); err != nil {
		err = fmt.Errorf("DeleteGroupInvite: failed to delete group invite (id=%s): %w", inviteID, err)
		db.logger.Error("DeleteGroupInvite error", "error", err)
		return err
	}
	return nil
}

type CreateFileParams struct {
	OwnerID   uuid.UUID
	ParentID  util.Optional[uuid.UUID]
	Name      string
	MimeType  string
	Path      util.Optional[string]
	S3Key     util.Optional[string]
	SizeBytes int64
}

func (db *Database) CreateFile(ctx context.Context, params CreateFileParams) (File, error) {
	file := File{
		ID:        uuid.New(),
		OwnerID:   params.OwnerID,
		ParentID:  params.ParentID,
		Name:      params.Name,
		MimeType:  params.MimeType,
		Path:      params.Path,
		S3Key:     params.S3Key,
		SizeBytes: params.SizeBytes,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if file.MimeType != "application/askfrank.folder" && (!file.S3Key.Some || !file.Path.Some) {
		err := errors.New("CreateFile: S3Key or Path is required for non-folder files")
		db.logger.Error("CreateFile error", "error", err)
		return file, err
	}

	if _, err := db.Exec(ctx, `INSERT INTO tbl_file (id, owner_id, parent_id, name, mime_type, path, s3_key, size_bytes, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		file.ID, file.OwnerID, file.ParentID, file.Name, file.MimeType, file.Path, file.S3Key, file.SizeBytes, file.CreatedAt, file.UpdatedAt); err != nil {
		err = fmt.Errorf("CreateFile: failed to insert file (owner_id=%s, name=%s): %w", file.OwnerID, file.Name, err)
		db.logger.Error("CreateFile error", "error", err)
		return file, err
	}
	return file, nil
}

type ListFilesParams struct {
	OwnerID  util.Optional[uuid.UUID]
	ParentID util.Optional[util.Optional[uuid.UUID]] // nil = root files, Some(nil) = files without parent, Some(uuid) = files with specific parent
}

func (db *Database) ListFiles(ctx context.Context, params ListFilesParams) ([]File, error) {
	var files []File

	var query strings.Builder
	query.WriteString(`SELECT id, owner_id, parent_id, name, mime_type, path, s3_key, size_bytes, created_at, updated_at FROM tbl_file WHERE 1=1`)
	var args []any
	argNum := 1

	if params.OwnerID.Some {
		query.WriteString(fmt.Sprintf(" AND owner_id = $%d", argNum))
		args = append(args, params.OwnerID.Data)
		argNum++
	}

	if params.ParentID.Some {
		if !params.ParentID.Data.Some {
			query.WriteString(" AND parent_id IS NULL")
		} else {
			query.WriteString(fmt.Sprintf(" AND parent_id = $%d", argNum))
			args = append(args, params.ParentID.Data.Data)
			argNum++
		}
	}

	rows, err := db.Query(ctx, query.String(), args...)
	if err != nil {
		db.logger.Error("ListFiles error", "error", err)
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var file File
		if err := rows.Scan(&file.ID, &file.OwnerID, &file.ParentID, &file.Name, &file.MimeType, &file.Path, &file.S3Key, &file.SizeBytes, &file.CreatedAt, &file.UpdatedAt); err != nil {
			return nil, err
		}
		files = append(files, file)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return files, nil
}

func (db *Database) GetFileByID(ctx context.Context, id uuid.UUID) (File, error) {
	var file File
	err := db.QueryRow(ctx, `SELECT id, owner_id, parent_id, name, mime_type, path, s3_key, size_bytes, created_at, updated_at FROM tbl_file WHERE id = $1`, id).Scan(
		&file.ID, &file.OwnerID, &file.ParentID, &file.Name, &file.MimeType, &file.Path, &file.S3Key, &file.SizeBytes, &file.CreatedAt, &file.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return file, ErrFileNotFound
		}
		err = fmt.Errorf("GetFile: failed to scan file (id=%s): %w", id, err)
		db.logger.Error("GetFile error", "error", err)
		return file, err
	}
	return file, nil
}

type UpdateFileParams struct {
	ParentID  util.Optional[uuid.UUID]
	Name      util.Optional[string]
	MimeType  util.Optional[string]
	Path      util.Optional[string]
	S3Key     util.Optional[string]
	SizeBytes util.Optional[int64]
}

func (db *Database) UpdateFileByID(ctx context.Context, id uuid.UUID, params UpdateFileParams) error {
	var query strings.Builder
	query.WriteString(`UPDATE tbl_file SET `)
	args := []any{}
	argNum := 1

	if params.ParentID.Some {
		query.WriteString(fmt.Sprintf("parent_id = $%d, ", argNum))
		args = append(args, params.ParentID.Data)
		argNum++
	}
	if params.Name.Some {
		query.WriteString(fmt.Sprintf("name = $%d, ", argNum))
		args = append(args, params.Name.Data)
		argNum++
	}
	if params.MimeType.Some {
		query.WriteString(fmt.Sprintf("mime_type = $%d, ", argNum))
		args = append(args, params.MimeType.Data)
		argNum++
	}
	if params.Path.Some {
		query.WriteString(fmt.Sprintf("path = $%d, ", argNum))
		args = append(args, params.Path.Data)
		argNum++
	}
	if params.S3Key.Some {
		query.WriteString(fmt.Sprintf("s3_key = $%d, ", argNum))
		args = append(args, params.S3Key.Data)
		argNum++
	}
	if params.SizeBytes.Some {
		query.WriteString(fmt.Sprintf("size_bytes = $%d, ", argNum))
		args = append(args, params.SizeBytes.Data)
		argNum++
	}
	query.WriteString(fmt.Sprintf("updated_at = $%d WHERE id = $%d", argNum, argNum+1))
	args = append(args, time.Now(), id)

	if _, err := db.Exec(ctx, query.String(), args...); err != nil {
		err = fmt.Errorf("UpdateFile: failed to update file (id=%s): %w", id, err)
		db.logger.Error("UpdateFile error", "error", err)
		return err
	}
	return nil
}

func (db *Database) DeleteFileByID(ctx context.Context, id uuid.UUID) error {
	if _, err := db.Exec(ctx, `DELETE FROM tbl_file WHERE id = $1`, id); err != nil {
		err = fmt.Errorf("DeleteFile: failed to delete file (id=%s): %w", id, err)
		db.logger.Error("DeleteFile error", "error", err)
		return err
	}
	return nil
}

type CreateFileShareParams struct {
	FileID           uuid.UUID
	SharedWithUserID uuid.UUID
	Permission       string // e.g., "read", "write"
}

func (db *Database) CreateFileShare(ctx context.Context, params CreateFileShareParams) (FileShare, error) {
	share := FileShare{
		ID:               uuid.New(),
		FileID:           params.FileID,
		SharedWithUserID: params.SharedWithUserID,
		Permission:       params.Permission,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	if _, err := db.Exec(ctx, `INSERT INTO tbl_file_share (id, file_id, shared_with_user_id, permission, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6)`,
		share.ID, share.FileID, share.SharedWithUserID, share.Permission, share.CreatedAt, share.UpdatedAt); err != nil {
		err = fmt.Errorf("CreateFileShare: failed to insert file share (file_id=%s, shared_with_user_id=%s): %w", share.FileID, share.SharedWithUserID, err)
		db.logger.Error("CreateFileShare error", "error", err)
		return share, err
	}
	return share, nil
}

type ListFileSharesParams struct {
	FileID util.Optional[uuid.UUID]
}

func (db *Database) ListFileShares(ctx context.Context, params ListFileSharesParams) ([]FileShare, error) {
	var shares []FileShare

	var query strings.Builder
	query.WriteString(`SELECT id, file_id, shared_with_user_id, permission, created_at, updated_at FROM tbl_file_share`)
	var args []any
	argNum := 1

	if params.FileID.Some {
		query.WriteString(fmt.Sprintf(" WHERE file_id = $%d", argNum))
		args = append(args, params.FileID.Data)
		argNum++
	}

	rows, err := db.Query(ctx, query.String(), args...)
	if err != nil {
		db.logger.Error("ListFileShares error", "error", err)
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var share FileShare
		if err := rows.Scan(&share.ID, &share.FileID, &share.SharedWithUserID, &share.Permission, &share.CreatedAt, &share.UpdatedAt); err != nil {
			return nil, err
		}
		shares = append(shares, share)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return shares, nil
}

// todo update file share

func (db *Database) DeleteFileShareByID(ctx context.Context, id uuid.UUID) error {
	if _, err := db.Exec(ctx, `DELETE FROM tbl_file_share WHERE id = $1`, id); err != nil {
		err = fmt.Errorf("DeleteFileShare: failed to delete file share (id=%s): %w", id, err)
		db.logger.Error("DeleteFileShare error", "error", err)
		return err
	}
	return nil
}

type ListSharedFilesParams struct {
	UserID util.Optional[uuid.UUID]
}

func (db *Database) ListSharedFiles(ctx context.Context, params ListSharedFilesParams) ([]File, error) {
	var files []File

	var query strings.Builder
	query.WriteString(`SELECT f.id, f.owner_id, f.parent_id, f.name, f.mime_type, f.path, f.s3_key, f.size_bytes, f.created_at, f.updated_at
			  FROM tbl_file f
			  JOIN tbl_file_share fs ON f.id = fs.file_id
			  WHERE 1=1`)
	var args []any
	argNum := 1

	if params.UserID.Some {
		query.WriteString(fmt.Sprintf(" AND fs.shared_with_user_id = $%d", argNum))
		args = append(args, params.UserID.Data)
		argNum++
	}

	rows, err := db.Query(ctx, query.String(), args...)
	if err != nil {
		db.logger.Error("ListSharedFiles error", "error", err)
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var file File
		if err := rows.Scan(&file.ID, &file.OwnerID, &file.ParentID, &file.Name, &file.MimeType, &file.Path, &file.S3Key, &file.SizeBytes, &file.CreatedAt, &file.UpdatedAt); err != nil {
			return nil, err
		}
		files = append(files, file)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return files, nil
}

type CreateAuditLogEventParams struct {
	OwnerID   uuid.UUID
	EventType string
	EventData AuditLogEventChange
	CreatedAt time.Time
}

type AuditLogEventChange struct {
	Key      string                `json:"key"`
	OldValue util.Optional[[]byte] `json:"old_value"`
	NewValue util.Optional[[]byte] `json:"new_value"`
}

func (db *Database) CreateAuditLogEvent(ctx context.Context, params CreateAuditLogEventParams) (AuditLogEvent, error) {
	eventData, err := json.Marshal(params.EventData)
	if err != nil {
		err = fmt.Errorf("CreateAuditLogEvent: failed to marshal event data: %w", err)
		db.logger.Error("CreateAuditLogEvent error", "error", err)
		return AuditLogEvent{}, err
	}

	event := AuditLogEvent{
		ID:        uuid.New(),
		OwnerID:   params.OwnerID,
		EventType: params.EventType,
		EventData: eventData,
		CreatedAt: params.CreatedAt,
	}

	if _, err := db.Exec(ctx, `INSERT INTO tbl_audit_log_event (id, owner_id, event_type, event_data, created_at) VALUES ($1, $2, $3, $4, $5)`,
		event.ID, event.OwnerID, event.EventType, event.EventData, event.CreatedAt); err != nil {
		err = fmt.Errorf("CreateAuditLogEvent: failed to insert audit log event (owner_id=%s): %w", event.OwnerID, err)
		db.logger.Error("CreateAuditLogEvent error", "error", err)
		return event, err
	}
	return event, nil
}

type ListAuditLogEventsParams struct {
	OwnerID   util.Optional[uuid.UUID]
	StartTime util.Optional[time.Time]
	EndTime   util.Optional[time.Time]
}

func (db *Database) ListAuditLogEvents(ctx context.Context, params ListAuditLogEventsParams) ([]AuditLogEvent, error) {
	var events []AuditLogEvent

	var query strings.Builder
	query.WriteString(`SELECT id, owner_id, event_type, event_data, created_at FROM tbl_audit_log_event WHERE 1=1`)
	var args []any
	argNum := 1

	if params.OwnerID.Some {
		query.WriteString(fmt.Sprintf(" AND owner_id = $%d", argNum))
		args = append(args, params.OwnerID.Data)
		argNum++
	}

	if params.StartTime.Some {
		query.WriteString(fmt.Sprintf(" AND created_at >= $%d", argNum))
		args = append(args, params.StartTime.Data)
		argNum++
	}

	if params.EndTime.Some {
		query.WriteString(fmt.Sprintf(" AND created_at <= $%d", argNum))
		args = append(args, params.EndTime.Data)
		argNum++
	}

	rows, err := db.Query(ctx, query.String(), args...)
	if err != nil {
		db.logger.Error("ListAuditLogEvents error", "error", err)
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var event AuditLogEvent
		if err := rows.Scan(&event.ID, &event.OwnerID, &event.EventType, &event.EventData, &event.CreatedAt); err != nil {
			return nil, err
		}
		events = append(events, event)
	}

	if err := rows.Err(); err != nil {
		db.logger.Error("ListAuditLogEvents error", "error", err)
		return nil, err
	}

	return events, nil
}

type CreateWebhookSubscriptionParams struct {
	OwnerID     uuid.UUID
	Name        string
	Description string
	URL         string
	Secret      string
	EventTypes  []WebhookEventType
	IsActive    bool
}

func (db *Database) CreateWebhookSubscription(ctx context.Context, params CreateWebhookSubscriptionParams) (WebhookSubscription, error) {
	subscription := WebhookSubscription{
		ID:          uuid.New(),
		OwnerID:     params.OwnerID,
		Name:        params.Name,
		Description: params.Description,
		URL:         params.URL,
		Secret:      params.Secret,
		EventTypes:  params.EventTypes,
		IsActive:    params.IsActive,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if _, err := db.Exec(ctx, `INSERT INTO tbl_webhook_subscription (id, owner_id, name, description, url, secret, event_types, is_active, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		subscription.ID, subscription.OwnerID, subscription.Name, subscription.Description, subscription.URL, subscription.Secret, subscription.EventTypes, subscription.IsActive, subscription.CreatedAt, subscription.UpdatedAt); err != nil {
		err = fmt.Errorf("CreateWebhookSubscription: failed to insert webhook subscription (owner_id=%s, url=%s): %w", subscription.OwnerID, subscription.URL, err)
		db.logger.Error("CreateWebhookSubscription error", "error", err)
		return subscription, err
	}
	return subscription, nil
}

type ListWebhookSubscriptionsParams struct {
	OwnerID util.Optional[uuid.UUID]
	Active  util.Optional[bool]
}

func (db *Database) ListWebhookSubscriptions(ctx context.Context, params ListWebhookSubscriptionsParams) ([]WebhookSubscription, error) {
	var subscriptions []WebhookSubscription

	var query strings.Builder
	query.WriteString(`SELECT id, owner_id, name, description, url, secret, event_types, is_active, created_at, updated_at FROM tbl_webhook_subscription WHERE 1=1`)
	var args []any
	argNum := 1

	if params.OwnerID.Some {
		query.WriteString(fmt.Sprintf(" AND owner_id = $%d", argNum))
		args = append(args, params.OwnerID.Data)
		argNum++
	}

	if params.Active.Some {
		query.WriteString(fmt.Sprintf(" AND active = $%d", argNum))
		args = append(args, params.Active.Data)
		argNum++
	}

	rows, err := db.Query(ctx, query.String(), args...)
	if err != nil {
		db.logger.Error("ListWebhookSubscriptions error", "error", err)
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var subscription WebhookSubscription
		if err := rows.Scan(&subscription.ID, &subscription.OwnerID, &subscription.Name, &subscription.Description, &subscription.URL, &subscription.Secret, &subscription.EventTypes, &subscription.IsActive, &subscription.CreatedAt, &subscription.UpdatedAt); err != nil {
			return nil, err
		}
		subscriptions = append(subscriptions, subscription)
	}

	if err := rows.Err(); err != nil {
		db.logger.Error("ListWebhookSubscriptions error", "error", err)
		return nil, err
	}

	return subscriptions, nil
}

type UpdateWebhookSubscriptionParams struct {
	Name        util.Optional[string]
	Description util.Optional[string]
	URL         util.Optional[string]
	Secret      util.Optional[string]
	EventTypes  util.Optional[[]string]
	IsActive    util.Optional[bool]
}

func (db *Database) UpdateWebhookSubscriptionByID(ctx context.Context, id uuid.UUID, params UpdateWebhookSubscriptionParams) error {
	var query strings.Builder
	query.WriteString(`UPDATE tbl_webhook_subscription SET `)
	args := []any{}
	argNum := 1

	if params.Name.Some {
		query.WriteString(fmt.Sprintf("name = $%d, ", argNum))
		args = append(args, params.Name.Data)
		argNum++
	}

	if params.Description.Some {
		query.WriteString(fmt.Sprintf("description = $%d, ", argNum))
		args = append(args, params.Description.Data)
		argNum++
	}

	if params.URL.Some {
		query.WriteString(fmt.Sprintf("url = $%d, ", argNum))
		args = append(args, params.URL.Data)
		argNum++
	}

	if params.Secret.Some {
		query.WriteString(fmt.Sprintf("secret = $%d, ", argNum))
		args = append(args, params.Secret.Data)
		argNum++
	}

	if params.EventTypes.Some {
		query.WriteString(fmt.Sprintf("event_types = $%d, ", argNum))
		args = append(args, params.EventTypes.Data)
		argNum++
	}

	if params.IsActive.Some {
		query.WriteString(fmt.Sprintf("is_active = $%d, ", argNum))
		args = append(args, params.IsActive.Data)
		argNum++
	}

	query.WriteString(fmt.Sprintf("updated_at = $%d WHERE id = $%d", argNum, argNum+1))
	args = append(args, time.Now(), id)

	if _, err := db.Exec(ctx, query.String(), args...); err != nil {
		err = fmt.Errorf("UpdateWebhook: failed to update webhook (id=%s): %w", id, err)
		db.logger.Error("UpdateWebhook error", "error", err)
		return err
	}
	return nil
}

type DeleteWebhookParams struct {
	OwnerID util.Optional[uuid.UUID]
}

func (db *Database) DeleteWebhookByID(ctx context.Context, id uuid.UUID, params DeleteWebhookParams) error {
	var query strings.Builder
	query.WriteString(`DELETE FROM tbl_webhook WHERE id = $1`)
	args := []any{id}
	argNum := 2

	if params.OwnerID.Some {
		query.WriteString(fmt.Sprintf(" AND owner_id = $%d", argNum))
		args = append(args, params.OwnerID.Data)
		argNum++
	}

	if _, err := db.Exec(ctx, query.String(), args...); err != nil {
		err = fmt.Errorf("DeleteWebhookByID: failed to delete webhook (id=%s): %w", id, err)
		db.logger.Error("DeleteWebhookByID error", "error", err)
		return err
	}
	return nil
}

type CreateWebhookEventParams struct {
	EventType WebhookEventType
	Payload   json.RawMessage
}

func (db *Database) CreateWebhookEvent(ctx context.Context, params CreateWebhookEventParams) (WebhookEvent, error) {
	event := WebhookEvent{
		ID:        uuid.New(),
		EventType: params.EventType,
		Payload:   params.Payload,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if _, err := db.Exec(ctx, `INSERT INTO tbl_webhook_event (id, event_type, payload, created_at, updated_at) VALUES ($1, $2, $3, $4, $5)`,
		event.ID, event.EventType, event.Payload, event.CreatedAt, event.UpdatedAt); err != nil {
		db.logger.Error("CreateWebhookEvent error", "error", err)
		return event, err
	}

	if _, err := db.Exec(ctx, `
        INSERT INTO tbl_webhook_delivery (id, event_id, subscription_id, status, retry_count, created_at, updated_at)
        SELECT gen_random_uuid(), $1, s.id, $3, 0, NOW(), NOW()
        FROM tbl_webhook_subscription s
        WHERE s.is_active = true AND $2 = ANY(s.event_types)
    `, event.ID, string(event.EventType), WebhookDeliveryStatusPending); err != nil {
		db.logger.Error("CreateWebhookEvent delivery creation error", "error", err)
		return event, err
	}

	return event, nil
}

type ListWebhookEventsParams struct {
	EventTypes util.Optional[[]string]
}

func (db *Database) ListWebhookEvents(ctx context.Context, params ListWebhookEventsParams) ([]WebhookEvent, error) {
	var events []WebhookEvent

	var query strings.Builder
	query.WriteString(`SELECT id, event_type, payload, status, attempts, last_attempt_at, response_code, response_body, created_at, updated_at FROM tbl_webhook_event WHERE 1=1`)
	var args []any
	argNum := 1

	if params.EventTypes.Some && len(params.EventTypes.Data) > 0 {
		query.WriteString(fmt.Sprintf(" AND event_type = ANY($%d)", argNum))
		args = append(args, params.EventTypes.Data)
		argNum++
	}

	rows, err := db.Query(ctx, query.String(), args...)
	if err != nil {
		db.logger.Error("ListWebhookEvents error", "error", err)
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var event WebhookEvent
		if err := rows.Scan(&event.ID, &event.EventType, &event.Payload, &event.CreatedAt, &event.UpdatedAt); err != nil {
			db.logger.Error("ListWebhookEvents error", "error", err)
			return nil, err
		}
		events = append(events, event)
	}

	if err := rows.Err(); err != nil {
		db.logger.Error("ListWebhookEvents error", "error", err)
		return nil, err
	}

	return events, nil
}

type ListWebhookDeliveriesParams struct {
	Status         util.Optional[WebhookDeliveryStatus]
	SubscriptionID util.Optional[uuid.UUID]
	EventID        util.Optional[uuid.UUID]
	MaxRetries     util.Optional[int]
	ReadyForRetry  util.Optional[bool] // For deliveries that should be retried (NextAttemptAt <= NOW())
}

func (db *Database) ListWebhookDeliveries(ctx context.Context, params ListWebhookDeliveriesParams) ([]WebhookDelivery, error) {
	var query strings.Builder
	query.WriteString(`
		SELECT 
			wd.id, wd.event_id, wd.subscription_id, 
			ws.url, ws.secret, 
			we.payload, we.event_type,
			wd.status, wd.retry_count, wd.last_attempt_at, wd.next_attempt_at,
			wd.last_response_code, wd.last_response_body, wd.created_at, wd.updated_at
		FROM tbl_webhook_delivery wd
		JOIN tbl_webhook_subscription ws ON wd.subscription_id = ws.id
		JOIN tbl_webhook_event we ON wd.event_id = we.id
		WHERE 1=1`)

	args := []any{}
	argIndex := 1

	if params.Status.Some {
		query.WriteString(fmt.Sprintf(` AND wd.status = $%d`, argIndex))
		args = append(args, params.Status.Data)
		argIndex++
	}

	if params.SubscriptionID.Some {
		query.WriteString(fmt.Sprintf(` AND wd.subscription_id = $%d`, argIndex))
		args = append(args, params.SubscriptionID.Data)
		argIndex++
	}

	if params.EventID.Some {
		query.WriteString(fmt.Sprintf(` AND wd.event_id = $%d`, argIndex))
		args = append(args, params.EventID.Data)
		argIndex++
	}

	if params.MaxRetries.Some {
		query.WriteString(fmt.Sprintf(` AND wd.retry_count < $%d`, argIndex))
		args = append(args, params.MaxRetries.Data)
		argIndex++
	}

	if params.ReadyForRetry.Some && params.ReadyForRetry.Data {
		query.WriteString(` AND (wd.next_attempt_at IS NULL OR wd.next_attempt_at <= NOW())`)
	}

	query.WriteString(` ORDER BY wd.created_at ASC LIMIT 100`)

	rows, err := db.Query(ctx, query.String(), args...)
	if err != nil {
		db.logger.Error("ListWebhookDeliveries query error", "error", err)
		return nil, err
	}
	defer rows.Close()

	var deliveries []WebhookDelivery
	for rows.Next() {
		var delivery WebhookDelivery
		err := rows.Scan(
			&delivery.ID, &delivery.EventID, &delivery.SubscriptionID,
			&delivery.URL, &delivery.Secret,
			&delivery.Payload, &delivery.EventType,
			&delivery.Status, &delivery.RetryCount, &delivery.LastAttemptAt, &delivery.NextAttemptAt,
			&delivery.LastResponseCode, &delivery.LastResponseBody, &delivery.CreatedAt, &delivery.UpdatedAt,
		)
		if err != nil {
			db.logger.Error("ListWebhookDeliveries scan error", "error", err)
			return nil, err
		}
		deliveries = append(deliveries, delivery)
	}

	if err := rows.Err(); err != nil {
		db.logger.Error("ListWebhookDeliveries rows error", "error", err)
		return nil, err
	}

	return deliveries, nil
}

type UpdateWebhookDeliveryParams struct {
	Status           util.Optional[WebhookDeliveryStatus]
	RetryCount       util.Optional[int]
	LastAttemptAt    util.Optional[util.Optional[time.Time]]
	NextAttemptAt    util.Optional[util.Optional[time.Time]]
	LastResponseCode util.Optional[util.Optional[int]]
	LastResponseBody util.Optional[util.Optional[string]]
}

func (db *Database) UpdateWebhookDeliveryByID(ctx context.Context, id uuid.UUID, params UpdateWebhookDeliveryParams) error {
	var query strings.Builder
	query.WriteString(`UPDATE tbl_webhook_delivery SET `)
	args := []any{}
	argNum := 1

	if params.Status.Some {
		query.WriteString(fmt.Sprintf("status = $%d, ", argNum))
		args = append(args, params.Status.Data)
		argNum++
	}

	if params.RetryCount.Some {
		query.WriteString(fmt.Sprintf("retry_count = $%d, ", argNum))
		args = append(args, params.RetryCount.Data)
		argNum++
	}

	if params.LastAttemptAt.Some {
		query.WriteString(fmt.Sprintf("last_attempt_at = $%d, ", argNum))
		args = append(args, params.LastAttemptAt.Data)
		argNum++
	}

	if params.NextAttemptAt.Some {
		query.WriteString(fmt.Sprintf("next_attempt_at = $%d, ", argNum))
		args = append(args, params.NextAttemptAt.Data)
		argNum++
	}

	if params.LastResponseCode.Some {
		query.WriteString(fmt.Sprintf("last_response_code = $%d, ", argNum))
		args = append(args, params.LastResponseCode.Data)
		argNum++
	}

	if params.LastResponseBody.Some {
		query.WriteString(fmt.Sprintf("last_response_body = $%d, ", argNum))
		args = append(args, params.LastResponseBody.Data)
		argNum++
	}

	query.WriteString(fmt.Sprintf("updated_at = $%d WHERE id = $%d", argNum, argNum+1))
	args = append(args, time.Now(), id)

	if _, err := db.Exec(ctx, query.String(), args...); err != nil {
		err = fmt.Errorf("UpdateWebhookDelivery: failed to update webhook delivery (id=%s): %w", id, err)
		db.logger.Error("UpdateWebhookDelivery error", "error", err)
		return err
	}
	return nil
}

func (db *Database) DeleteWebhookDeliveryByID(ctx context.Context, id uuid.UUID) error {
	if _, err := db.Exec(ctx, `DELETE FROM tbl_webhook_delivery WHERE id = $1`, id); err != nil {
		err = fmt.Errorf("DeleteWebhookDelivery: failed to delete webhook delivery (id=%s): %w", id, err)
		db.logger.Error("DeleteWebhookDelivery error", "error", err)
		return err
	}
	return nil
}

type CreateCalendarEventParams struct {
	OwnerID     uuid.UUID
	Title       string
	Description string
	StartTime   time.Time
	EndTime     time.Time
	AllDay      bool
	Status      CalendarEventStatus
	Location    util.Optional[string]
}

func (db *Database) CreateCalendarEvent(ctx context.Context, params CreateCalendarEventParams) (CalendarEvent, error) {
	event := CalendarEvent{
		ID:          uuid.New(),
		OwnerID:     params.OwnerID,
		Title:       params.Title,
		Description: params.Description,
		StartTime:   params.StartTime,
		EndTime:     params.EndTime,
		AllDay:      params.AllDay,
		Status:      params.Status,
		Location:    params.Location,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if _, err := db.Exec(ctx, `INSERT INTO tbl_calendar_event (id, owner_id, title, description, start_time, end_time, all_day, status, location, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		event.ID, event.OwnerID, event.Title, event.Description, event.StartTime, event.EndTime, event.AllDay, event.Status, event.Location, event.CreatedAt, event.UpdatedAt); err != nil {
		err = fmt.Errorf("CreateCalendarEvent: failed to insert calendar event (owner_id=%s, title=%s): %w", event.OwnerID, event.Title, err)
		db.logger.Error("CreateCalendarEvent error", "error", err)
		return event, err
	}
	return event, nil
}

type ListCalendarEventsParams struct {
	OwnerID   util.Optional[uuid.UUID]
	StartDate util.Optional[time.Time]
	EndDate   util.Optional[time.Time]
}

func (db *Database) ListCalendarEvents(ctx context.Context, params ListCalendarEventsParams) ([]CalendarEvent, error) {
	var events []CalendarEvent

	var query strings.Builder
	query.WriteString(`SELECT id, owner_id, title, description, start_time, end_time, all_day, status, location, created_at, updated_at FROM tbl_calendar_event WHERE 1=1`)
	var args []any
	argNum := 1

	if params.OwnerID.Some {
		query.WriteString(fmt.Sprintf(" AND owner_id = $%d", argNum))
		args = append(args, params.OwnerID.Data)
		argNum++
	}

	if params.StartDate.Some {
		query.WriteString(fmt.Sprintf(" AND start_time >= $%d", argNum))
		args = append(args, params.StartDate.Data)
		argNum++
	}

	if params.EndDate.Some {
		query.WriteString(fmt.Sprintf(" AND end_time <= $%d", argNum))
		args = append(args, params.EndDate.Data)
		argNum++
	}

	rows, err := db.Query(ctx, query.String(), args...)
	if err != nil {
		db.logger.Error("ListCalendarEvents error", "error", err)
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var event CalendarEvent
		if err := rows.Scan(&event.ID, &event.OwnerID, &event.Title, &event.Description, &event.StartTime, &event.EndTime, &event.AllDay, &event.Status, &event.Location, &event.CreatedAt, &event.UpdatedAt); err != nil {
			return nil, err
		}
		events = append(events, event)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return events, nil
}

type UpdateCalendarEventParams struct {
	Title       util.Optional[string]
	Description util.Optional[string]
	StartTime   util.Optional[time.Time]
	EndTime     util.Optional[time.Time]
	AllDay      util.Optional[bool]
	Status      util.Optional[CalendarEventStatus]
	Location    util.Optional[util.Optional[string]]
}

func (db *Database) UpdateCalendarEventByID(ctx context.Context, id uuid.UUID, params UpdateCalendarEventParams) error {
	var query strings.Builder
	query.WriteString(`UPDATE tbl_calendar_event SET `)
	args := []any{}
	argNum := 1

	if params.Title.Some {
		query.WriteString(fmt.Sprintf("title = $%d, ", argNum))
		args = append(args, params.Title.Data)
		argNum++
	}
	if params.Description.Some {
		query.WriteString(fmt.Sprintf("description = $%d, ", argNum))
		args = append(args, params.Description.Data)
		argNum++
	}
	if params.StartTime.Some {
		query.WriteString(fmt.Sprintf("start_time = $%d, ", argNum))
		args = append(args, params.StartTime.Data)
		argNum++
	}
	if params.EndTime.Some {
		query.WriteString(fmt.Sprintf("end_time = $%d, ", argNum))
		args = append(args, params.EndTime.Data)
		argNum++
	}
	if params.AllDay.Some {
		query.WriteString(fmt.Sprintf("all_day = $%d, ", argNum))
		args = append(args, params.AllDay.Data)
		argNum++
	}
	if params.Status.Some {
		query.WriteString(fmt.Sprintf("status = $%d, ", argNum))
		args = append(args, params.Status.Data)
		argNum++
	}
	if params.Location.Some {
		if params.Location.Data.Some {
			query.WriteString(fmt.Sprintf("location = $%d, ", argNum))
			args = append(args, params.Location.Data.Data)
			argNum++
		} else {
			query.WriteString("location = NULL, ")
		}
	}
	query.WriteString(fmt.Sprintf("updated_at = $%d WHERE id = $%d", argNum, argNum+1))
	args = append(args, time.Now(), id)

	if _, err := db.Exec(ctx, query.String(), args...); err != nil {
		err = fmt.Errorf("UpdateCalendarEvent: failed to update calendar event (id=%s): %w", id, err)
		db.logger.Error("UpdateCalendarEvent error", "error", err)
		return err
	}
	return nil
}

func (db *Database) DeleteCalendarEventByID(ctx context.Context, id uuid.UUID) error {
	if _, err := db.Exec(ctx, `DELETE FROM tbl_calendar_event WHERE id = $1`, id); err != nil {
		err = fmt.Errorf("DeleteCalendarEvent: failed to delete calendar event (id=%s): %w", id, err)
		db.logger.Error("DeleteCalendarEvent error", "error", err)
		return err
	}
	return nil
}

type CreateCalendarEventAttendeeParams struct {
	CalendarEventID uuid.UUID
	UserID          util.Optional[uuid.UUID]
	Email           util.Optional[string]
	Status          CalendarEventAttendeeStatus
}

func (db *Database) CreateCalendarEventAttendee(ctx context.Context, params CreateCalendarEventAttendeeParams) (CalendarEventAttendee, error) {
	attendee := CalendarEventAttendee{
		ID:              uuid.New(),
		CalendarEventID: params.CalendarEventID,
		UserID:          params.UserID,
		Email:           params.Email,
		Status:          params.Status,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	if !params.UserID.Some && !params.Email.Some {
		err := errors.New("CreateCalendarEventAttendee: either UserID or Email must be provided")
		db.logger.Error("CreateCalendarEventAttendee error", "error", err)
		return attendee, err
	}

	if _, err := db.Exec(ctx, `INSERT INTO tbl_calendar_event_attendee (id, calendar_event_id, user_id, email, status, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		attendee.ID, attendee.CalendarEventID, attendee.UserID, attendee.Email, attendee.Status, attendee.CreatedAt, attendee.UpdatedAt); err != nil {
		err = fmt.Errorf("CreateCalendarEventAttendee: failed to insert calendar event attendee (calendar_event_id=%s): %w", attendee.CalendarEventID, err)
		db.logger.Error("CreateCalendarEventAttendee error", "error", err)
		return attendee, err
	}
	return attendee, nil
}

func (db *Database) DeleteCalendarEventAttendee(ctx context.Context, attendeeID uuid.UUID) error {
	if _, err := db.Exec(ctx, `DELETE FROM tbl_calendar_event_attendee WHERE id = $1`, attendeeID); err != nil {
		err = fmt.Errorf("DeleteCalendarEventAttendee: failed to delete calendar event attendee (id=%s): %w", attendeeID, err)
		db.logger.Error("DeleteCalendarEventAttendee error", "error", err)
		return err
	}
	return nil
}

type CreateNotificationParams struct {
	OwnerID uuid.UUID
	Type    NotificationType
	Message string
	Read    bool
}

func (db *Database) CreateNotification(ctx context.Context, params CreateNotificationParams) (Notification, error) {
	notification := Notification{
		ID:        uuid.New(),
		OwnerID:   params.OwnerID,
		Type:      params.Type,
		Message:   params.Message,
		Read:      params.Read,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if _, err := db.Exec(ctx, `INSERT INTO tbl_notification (id, owner_id, type, message, read, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		notification.ID, notification.OwnerID, notification.Type, notification.Message, notification.Read, notification.CreatedAt, notification.UpdatedAt); err != nil {
		err = fmt.Errorf("CreateNotification: failed to insert notification (owner_id=%s): %w", notification.OwnerID, err)
		db.logger.Error("CreateNotification error", "error", err)
		return notification, err
	}
	return notification, nil
}

type CreateOAuthClientParams struct {
	OwnerID       uuid.UUID
	Name          string
	Secret        string
	RedirectURIs  []string
	IsPublic      bool
	AllowedScopes []string
}

func (db *Database) CreateOAuthClient(ctx context.Context, params CreateOAuthClientParams) (OAuthClient, error) {
	client := OAuthClient{
		ID:            uuid.New(),
		OwnerID:       params.OwnerID,
		Name:          params.Name,
		Secret:        params.Secret,
		RedirectURIs:  params.RedirectURIs,
		IsPublic:      params.IsPublic,
		AllowedScopes: params.AllowedScopes,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	if _, err := db.Exec(ctx, `INSERT INTO tbl_oauth_client (id, owner_id, name, secret, redirect_uris, is_public, allowed_scopes, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		client.ID, client.OwnerID, client.Name, client.Secret, client.RedirectURIs, client.IsPublic, client.AllowedScopes, client.CreatedAt, client.UpdatedAt); err != nil {
		err = fmt.Errorf("CreateOAuthClient: failed to insert OAuth client (owner_id=%s): %w", client.OwnerID, err)
		db.logger.Error("CreateOAuthClient error", "error", err)
		return client, err
	}
	return client, nil
}

type ListOAuthClientsParams struct {
	OwnerID util.Optional[uuid.UUID]
}

func (db *Database) ListOAuthClients(ctx context.Context, params ListOAuthClientsParams) ([]OAuthClient, error) {
	var clients []OAuthClient

	var query strings.Builder
	query.WriteString(`SELECT id, owner_id, name, secret, redirect_uris, is_public, allowed_scopes, created_at, updated_at FROM tbl_oauth_client WHERE 1=1`)
	var args []any
	argNum := 1

	if params.OwnerID.Some {
		query.WriteString(fmt.Sprintf(" AND owner_id = $%d", argNum))
		args = append(args, params.OwnerID.Data)
		argNum++
	}

	rows, err := db.Query(ctx, query.String(), args...)
	if err != nil {
		db.logger.Error("ListOAuthClients error", "error", err)
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var client OAuthClient
		if err := rows.Scan(&client.ID, &client.OwnerID, &client.Name, &client.Secret, &client.RedirectURIs, &client.IsPublic, &client.AllowedScopes, &client.CreatedAt, &client.UpdatedAt); err != nil {
			return nil, err
		}
		clients = append(clients, client)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return clients, nil
}

func (db *Database) GetOAuthClientByID(ctx context.Context, id uuid.UUID) (OAuthClient, error) {
	var client OAuthClient
	err := db.QueryRow(ctx, `SELECT id, owner_id, name, secret, redirect_uris, is_public, allowed_scopes, created_at, updated_at FROM tbl_oauth_client WHERE id = $1`, id).Scan(
		&client.ID, &client.OwnerID, &client.Name, &client.Secret, &client.RedirectURIs, &client.IsPublic, &client.AllowedScopes, &client.CreatedAt, &client.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return client, ErrOAuthClientNotFound
		}
		err = fmt.Errorf("GetOAuthClient: failed to scan OAuth client (id=%s): %w", id, err)
		db.logger.Error("GetOAuthClient error", "error", err)
		return client, err
	}
	return client, nil
}

type UpdateOAuthClientParams struct {
	Name          util.Optional[string]
	Secret        util.Optional[string]
	RedirectURIs  util.Optional[[]string]
	IsPublic      util.Optional[bool]
	AllowedScopes util.Optional[[]string]
}

func (db *Database) UpdateOAuthClientByID(ctx context.Context, id uuid.UUID, params UpdateOAuthClientParams) error {
	var query strings.Builder
	query.WriteString(`UPDATE tbl_oauth_client SET `)
	args := []any{}
	argNum := 1

	if params.Name.Some {
		query.WriteString(fmt.Sprintf("name = $%d, ", argNum))
		args = append(args, params.Name.Data)
		argNum++
	}

	if params.Secret.Some {
		query.WriteString(fmt.Sprintf("secret = $%d, ", argNum))
		args = append(args, params.Secret.Data)
		argNum++
	}

	if params.RedirectURIs.Some {
		query.WriteString(fmt.Sprintf("redirect_uris = $%d, ", argNum))
		args = append(args, params.RedirectURIs.Data)
		argNum++
	}

	if params.IsPublic.Some {
		query.WriteString(fmt.Sprintf("is_public = $%d, ", argNum))
		args = append(args, params.IsPublic.Data)
		argNum++
	}

	if params.AllowedScopes.Some {
		query.WriteString(fmt.Sprintf("allowed_scopes = $%d, ", argNum))
		args = append(args, params.AllowedScopes.Data)
		argNum++
	}

	query.WriteString(fmt.Sprintf("updated_at = $%d WHERE id = $%d", argNum, argNum+1))
	args = append(args, time.Now(), id)

	if _, err := db.Exec(ctx, query.String(), args...); err != nil {
		err = fmt.Errorf("UpdateOAuthClient: failed to update OAuth client (id=%s): %w", id, err)
		db.logger.Error("UpdateOAuthClient error", "error", err)
		return err
	}
	return nil
}

func (db *Database) DeleteOAuthClientByID(ctx context.Context, id uuid.UUID) error {
	if _, err := db.Exec(ctx, `DELETE FROM tbl_oauth_client WHERE id = $1`, id); err != nil {
		err = fmt.Errorf("DeleteOAuthClient: failed to delete OAuth client (id=%s): %w", id, err)
		db.logger.Error("DeleteOAuthClient error", "error", err)
		return err
	}
	return nil
}

type CreateOAuthAccessTokenParams struct {
	Token     string
	ClientID  uuid.UUID
	UserID    uuid.UUID
	Data      OAuthAccessTokenData
	ExpiresAt time.Time
}

func (db *Database) CreateOAuthAccessToken(ctx context.Context, params CreateOAuthAccessTokenParams) (OAuthAccessToken, error) {
	token := OAuthAccessToken{
		ID:        uuid.New(),
		Token:     params.Token,
		ClientID:  params.ClientID,
		UserID:    params.UserID,
		Data:      params.Data,
		ExpiresAt: params.ExpiresAt,
		RevokedAt: util.None[time.Time](),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if _, err := db.Exec(ctx, `INSERT INTO tbl_oauth_access_token (id, token, client_id, user_id, data, expires_at, revoked_at, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`, token.ID, token.Token, token.ClientID, token.UserID, token.Data, token.ExpiresAt, token.RevokedAt, token.CreatedAt, token.UpdatedAt); err != nil {
		err = fmt.Errorf("CreateOAuthAccessToken: failed to insert OAuth access token (id=%s): %w", token.ID, err)
		db.logger.Error("CreateOAuthAccessToken error", "error", err)
		return token, err
	}
	return token, nil
}

func (db *Database) GetOAuthAccessTokenByID(ctx context.Context, id uuid.UUID) (OAuthAccessToken, error) {
	return db.GetOAuthAccessToken(ctx, GetOAuthAccessTokenParams{ID: util.Some(id)})
}

func (db *Database) GetOAuthAccessTokenByToken(ctx context.Context, token string) (OAuthAccessToken, error) {
	return db.GetOAuthAccessToken(ctx, GetOAuthAccessTokenParams{Token: util.Some(token)})
}

type GetOAuthAccessTokenParams struct {
	ID    util.Optional[uuid.UUID]
	Token util.Optional[string]
}

func (db *Database) GetOAuthAccessToken(ctx context.Context, params GetOAuthAccessTokenParams) (OAuthAccessToken, error) {
	var accessToken OAuthAccessToken

	var query strings.Builder
	query.WriteString(`SELECT id, client_id, user_id, token, data, expires_at, revoked_at, created_at, updated_at FROM tbl_oauth_access_token WHERE 1=1`)
	var args []any
	argNum := 1

	if params.ID.Some {
		query.WriteString(fmt.Sprintf(" AND id = $%d", argNum))
		args = append(args, params.ID.Data)
		argNum++
	}

	if params.Token.Some {
		query.WriteString(fmt.Sprintf(" AND token = $%d", argNum))
		args = append(args, params.Token.Data)
		argNum++
	}

	if err := db.QueryRow(ctx, query.String(), args...).Scan(
		&accessToken.ID, &accessToken.ClientID, &accessToken.UserID, &accessToken.Token, &accessToken.Data, &accessToken.ExpiresAt, &accessToken.RevokedAt, &accessToken.CreatedAt, &accessToken.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return accessToken, ErrOAuthAccessTokenNotFound
		}
		err = fmt.Errorf("GetOAuthAccessToken: failed to scan OAuth access token: %w", err)
		db.logger.Error("GetOAuthAccessToken error", "error", err)
		return accessToken, err
	}
	return accessToken, nil
}

type UpdateOAuthAccessTokenParams struct {
	RevokedAt util.Optional[time.Time]
}

func (db *Database) UpdateOAuthAccessTokenByID(ctx context.Context, id uuid.UUID, params UpdateOAuthAccessTokenParams) error {
	var query strings.Builder
	query.WriteString(`UPDATE tbl_oauth_access_token SET `)
	args := []any{}
	argNum := 1

	if params.RevokedAt.Some {
		query.WriteString(fmt.Sprintf("revoked_at = $%d, ", argNum))
		args = append(args, params.RevokedAt.Data)
		argNum++
	}

	query.WriteString(fmt.Sprintf("updated_at = $%d WHERE id = $%d", argNum, argNum+1))
	args = append(args, time.Now(), id)

	if _, err := db.Exec(ctx, query.String(), args...); err != nil {
		err = fmt.Errorf("UpdateOAuthAccessToken: failed to update OAuth access token (id=%s): %w", id, err)
		db.logger.Error("UpdateOAuthAccessToken error", "error", err)
		return err
	}
	return nil
}

type CreateOAuthAuthorizationCodeParams struct {
	ClientID            uuid.UUID
	Token               string
	UserID              uuid.UUID
	Scopes              []string
	CodeChallenge       util.Optional[string]
	CodeChallengeMethod util.Optional[string]
	RedirectURI         string
	ExpiresAt           time.Time
}

func (db *Database) CreateOAuthAuthorizationCode(ctx context.Context, params CreateOAuthAuthorizationCodeParams) (OAuthAuthorizationCode, error) {
	authCode := OAuthAuthorizationCode{
		ID:                  uuid.New(),
		Token:               params.Token,
		ClientID:            params.ClientID,
		UserID:              params.UserID,
		Scopes:              params.Scopes,
		CodeChallenge:       params.CodeChallenge,
		CodeChallengeMethod: params.CodeChallengeMethod,
		RedirectURI:         params.RedirectURI,
		ExpiresAt:           params.ExpiresAt,
		UsedAt:              util.None[time.Time](),
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
	}

	if _, err := db.Exec(ctx, `INSERT INTO tbl_oauth_auth_code (id, token, client_id, user_id, scopes, code_challenge, code_challenge_method, redirect_uri, expires_at, used_at, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		authCode.ID, authCode.Token, authCode.ClientID, authCode.UserID, authCode.Scopes, authCode.CodeChallenge, authCode.CodeChallengeMethod, authCode.RedirectURI, authCode.ExpiresAt, authCode.UsedAt, authCode.CreatedAt, authCode.UpdatedAt); err != nil {
		err = fmt.Errorf("CreateOAuthAuthorizationCode: failed to insert OAuth authorization code (token=%s): %w", authCode.Token, err)
		db.logger.Error("CreateOAuthAuthorizationCode error", "error", err)
		return authCode, err
	}
	return authCode, nil
}

func (db *Database) GetOAuthAuthorizationCodeByID(ctx context.Context, id uuid.UUID) (OAuthAuthorizationCode, error) {
	return db.GetOAuthAuthorizationCode(ctx, GetOAuthAuthorizationCodeParams{ID: util.Some(id)})
}

func (db *Database) GetOAuthAuthorizationCodeByCode(ctx context.Context, code string) (OAuthAuthorizationCode, error) {
	return db.GetOAuthAuthorizationCode(ctx, GetOAuthAuthorizationCodeParams{Token: util.Some(code)})
}

type GetOAuthAuthorizationCodeParams struct {
	ID    util.Optional[uuid.UUID]
	Token util.Optional[string]
}

func (db *Database) GetOAuthAuthorizationCode(ctx context.Context, params GetOAuthAuthorizationCodeParams) (OAuthAuthorizationCode, error) {
	var authCode OAuthAuthorizationCode
	var query strings.Builder
	query.WriteString(`SELECT id, token, client_id, user_id, scopes, code_challenge, code_challenge_method, redirect_uri, expires_at, created_at, updated_at FROM tbl_oauth_auth_code WHERE 1=1`)
	var args []any
	argNum := 1

	if params.ID.Some {
		query.WriteString(fmt.Sprintf(" AND id = $%d", argNum))
		args = append(args, params.ID.Data)
		argNum++
	}

	if params.Token.Some {
		query.WriteString(fmt.Sprintf(" AND token = $%d", argNum))
		args = append(args, params.Token.Data)
		argNum++
	}

	err := db.QueryRow(ctx, query.String(), args...).Scan(
		&authCode.ID, &authCode.Token, &authCode.ClientID, &authCode.UserID, &authCode.Scopes, &authCode.CodeChallenge, &authCode.CodeChallengeMethod, &authCode.RedirectURI, &authCode.ExpiresAt, &authCode.CreatedAt, &authCode.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return authCode, ErrOAuthAuthorizationCodeNotFound
		}
		err = fmt.Errorf("GetOAuthAuthorizationCode: failed to scan OAuth authorization code: %w", err)
		db.logger.Error("GetOAuthAuthorizationCode error", "error", err)
		return authCode, err
	}
	return authCode, nil
}

type UpdateOAuthAuthorizationCodeParams struct {
	UsedAt util.Optional[time.Time]
}

func (db *Database) UpdateOAuthAuthorizationCode(ctx context.Context, codeID uuid.UUID, params UpdateOAuthAuthorizationCodeParams) error {
	var query strings.Builder
	query.WriteString(`UPDATE tbl_oauth_auth_code SET `)
	args := []any{}
	argNum := 1

	if params.UsedAt.Some {
		query.WriteString(fmt.Sprintf("used_at = $%d, ", argNum))
		args = append(args, params.UsedAt.Data)
		argNum++
	}
	query.WriteString(fmt.Sprintf("updated_at = $%d WHERE id = $%d", argNum, argNum+1))
	args = append(args, time.Now(), codeID)

	if _, err := db.Exec(ctx, query.String(), args...); err != nil {
		err = fmt.Errorf("UpdateOAuthAuthorizationCode: failed to update OAuth authorization code (id=%s): %w", codeID, err)
		db.logger.Error("UpdateOAuthAuthorizationCode error", "error", err)
		return err
	}
	return nil
}

type CreateOAuthRefreshTokenChainParams struct {
	ClientID uuid.UUID
	UserID   uuid.UUID
	Scopes   []string
}

func (db *Database) CreateOAuthRefreshTokenChain(ctx context.Context, params CreateOAuthRefreshTokenChainParams) (OAuthRefreshTokenChain, error) {
	chain := OAuthRefreshTokenChain{
		ID:        uuid.New(),
		ClientID:  params.ClientID,
		UserID:    params.UserID,
		Scopes:    params.Scopes,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if _, err := db.Exec(ctx, `INSERT INTO tbl_oauth_refresh_token_chain (id, client_id, user_id, scopes, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6)`,
		chain.ID, chain.ClientID, chain.UserID, chain.Scopes, chain.CreatedAt, chain.UpdatedAt); err != nil {
		err = fmt.Errorf("CreateOAuthRefreshTokenChain: failed to insert OAuth refresh token chain (id=%s): %w", chain.ID, err)
		db.logger.Error("CreateOAuthRefreshTokenChain error", "error", err)
		return chain, err
	}
	return chain, nil
}

func (db *Database) GetOAuthRefreshTokenChainByID(ctx context.Context, id uuid.UUID) (OAuthRefreshTokenChain, error) {
	var chain OAuthRefreshTokenChain
	err := db.QueryRow(ctx, `SELECT id, client_id, user_id, scopes, created_at, updated_at FROM tbl_oauth_refresh_token_chain WHERE id = $1`, id).Scan(
		&chain.ID, &chain.ClientID, &chain.UserID, &chain.Scopes, &chain.CreatedAt, &chain.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return chain, ErrOAuthRefreshTokenChainNotFound
		}
		err = fmt.Errorf("GetOAuthRefreshTokenChain: failed to scan OAuth refresh token chain (id=%s): %w", id, err)
		db.logger.Error("GetOAuthRefreshTokenChain error", "error", err)
		return chain, err
	}
	return chain, nil
}

type CreateOAuthRefreshTokenParams struct {
	Token     string
	ChainID   uuid.UUID
	ExpiresAt time.Time
	UsedAt    util.Optional[time.Time]
}

func (db *Database) CreateOAuthRefreshToken(ctx context.Context, params CreateOAuthRefreshTokenParams) (OAuthRefreshToken, error) {
	token := OAuthRefreshToken{
		ID:        uuid.New(),
		Token:     params.Token,
		ChainID:   params.ChainID,
		ExpiresAt: params.ExpiresAt,
		UsedAt:    params.UsedAt,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if _, err := db.Exec(ctx, `INSERT INTO tbl_oauth_refresh_token (id, token, chain_id, expires_at, used_at, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		token.ID, token.Token, token.ChainID, token.ExpiresAt, token.UsedAt, token.CreatedAt, token.UpdatedAt); err != nil {
		err = fmt.Errorf("CreateOAuthRefreshToken: failed to insert OAuth refresh token (id=%s): %w", token.ID, err)
		db.logger.Error("CreateOAuthRefreshToken error", "error", err)
		return token, err
	}
	return token, nil
}

func (db *Database) GetOAuthRefreshTokenByID(ctx context.Context, id uuid.UUID) (OAuthRefreshToken, error) {
	return db.GetOAuthRefreshToken(ctx, GetOAuthRefreshTokenParams{ID: util.Some(id)})
}

func (db *Database) GetOAuthRefreshTokenByToken(ctx context.Context, token string) (OAuthRefreshToken, error) {
	return db.GetOAuthRefreshToken(ctx, GetOAuthRefreshTokenParams{Token: util.Some(token)})
}

type GetOAuthRefreshTokenParams struct {
	ID    util.Optional[uuid.UUID]
	Token util.Optional[string]
}

func (db *Database) GetOAuthRefreshToken(ctx context.Context, params GetOAuthRefreshTokenParams) (OAuthRefreshToken, error) {
	var refreshToken OAuthRefreshToken
	var query strings.Builder
	query.WriteString(`SELECT id, chain_id, token, expires_at, used_at, created_at, updated_at FROM tbl_oauth_refresh_token WHERE 1=1`)
	var args []any
	argNum := 1

	if params.ID.Some {
		query.WriteString(fmt.Sprintf(" AND id = $%d", argNum))
		args = append(args, params.ID.Data)
		argNum++
	}

	if params.Token.Some {
		query.WriteString(fmt.Sprintf(" AND token = $%d", argNum))
		args = append(args, params.Token.Data)
		argNum++
	}

	err := db.QueryRow(ctx, query.String(), args...).Scan(
		&refreshToken.ID, &refreshToken.ChainID, &refreshToken.Token, &refreshToken.ExpiresAt, &refreshToken.UsedAt, &refreshToken.CreatedAt, &refreshToken.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return refreshToken, ErrOAuthRefreshTokenNotFound
		}
		err = fmt.Errorf("GetOAuthRefreshToken: failed to scan OAuth refresh token: %w", err)
		db.logger.Error("GetOAuthRefreshToken error", "error", err)
		return refreshToken, err
	}
	return refreshToken, nil
}

type UpdateOAuthRefreshTokenParams struct {
	UsedAt util.Optional[time.Time]
}

func (db *Database) UpdateOAuthRefreshToken(ctx context.Context, tokenID uuid.UUID, params UpdateOAuthRefreshTokenParams) error {
	var query strings.Builder
	query.WriteString(`UPDATE tbl_oauth_refresh_token SET `)
	args := []any{}
	argNum := 1

	if params.UsedAt.Some {
		query.WriteString(fmt.Sprintf("used_at = $%d, ", argNum))
		args = append(args, params.UsedAt.Data)
		argNum++
	}
	query.WriteString(fmt.Sprintf("updated_at = $%d WHERE id = $%d", argNum, argNum+1))
	args = append(args, time.Now(), tokenID)

	if _, err := db.Exec(ctx, query.String(), args...); err != nil {
		err = fmt.Errorf("UpdateOAuthRefreshToken: failed to update OAuth refresh token (id=%s): %w", tokenID, err)
		db.logger.Error("UpdateOAuthRefreshToken error", "error", err)
		return err
	}
	return nil
}

type CreateSessionParams struct {
	UserID    util.Optional[uuid.UUID]
	Token     string
	UserAgent string
	IPAddress string
	Data      map[string]any
	ExpiresAt time.Time
	RevokedAt util.Optional[time.Time]
}

func (db *Database) CreateSession(ctx context.Context, params CreateSessionParams) (Session, error) {
	session := Session{
		ID:        uuid.New(),
		UserID:    params.UserID,
		Token:     params.Token,
		UserAgent: params.UserAgent,
		IPAddress: params.IPAddress,
		Data:      params.Data,
		ExpiresAt: params.ExpiresAt,
		RevokedAt: params.RevokedAt,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if _, err := db.Exec(ctx, `INSERT INTO tbl_session (id, user_id, token, user_agent, ip_address, data, expires_at, created_at, updated_at, revoked_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		session.ID, session.UserID, session.Token, session.UserAgent, session.IPAddress, session.Data, session.ExpiresAt, session.CreatedAt, session.UpdatedAt, session.RevokedAt); err != nil {
		err = fmt.Errorf("CreateSession: failed to insert session (user_id=%s): %w", session.UserID, err)
		db.logger.Error("CreateSession error", "error", err)
		return session, err
	}
	return session, nil
}

func (db *Database) GetSessionByID(ctx context.Context, id uuid.UUID) (Session, error) {
	return db.GetSession(ctx, GetSessionParams{ID: util.Some(id)})
}

func (db *Database) GetSessionByToken(ctx context.Context, token string) (Session, error) {
	return db.GetSession(ctx, GetSessionParams{Token: util.Some(token)})
}

type GetSessionParams struct {
	ID    util.Optional[uuid.UUID]
	Token util.Optional[string]
}

func (db *Database) GetSession(ctx context.Context, params GetSessionParams) (Session, error) {
	var session Session

	var query strings.Builder
	query.WriteString(`SELECT id, token, user_id, user_agent, ip_address, data, expires_at, created_at, updated_at, revoked_at FROM tbl_session WHERE 1=1`)
	var args []any
	argNum := 1

	if params.ID.Some {
		query.WriteString(fmt.Sprintf(" AND id = $%d", argNum))
		args = append(args, params.ID.Data)
		argNum++
	}

	if params.Token.Some {
		query.WriteString(fmt.Sprintf(" AND token = $%d", argNum))
		args = append(args, params.Token.Data)
		argNum++
	}

	err := db.QueryRow(ctx, query.String(), args...).Scan(
		&session.ID, &session.Token, &session.UserID, &session.UserAgent, &session.IPAddress, &session.Data, &session.ExpiresAt, &session.CreatedAt, &session.UpdatedAt, &session.RevokedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return session, ErrSessionNotFound
		}
		err = fmt.Errorf("RetrieveSession: failed to scan session: %w", err)
		db.logger.Error("RetrieveSession error", "error", err)
		return session, err
	}
	return session, nil
}

type UpdateSessionParams struct {
	Token     util.Optional[string]
	UserID    util.Optional[uuid.UUID]
	Data      util.Optional[map[string]any]
	RevokedAt util.Optional[time.Time]
}

func (db *Database) UpdateSessionByID(ctx context.Context, id uuid.UUID, params UpdateSessionParams) error {
	var query strings.Builder
	query.WriteString(`UPDATE tbl_session SET `)
	args := []any{}
	argNum := 1

	if params.Token.Some {
		query.WriteString(fmt.Sprintf("token = $%d, ", argNum))
		args = append(args, params.Token.Data)
		argNum++
	}

	if params.UserID.Some {
		query.WriteString(fmt.Sprintf("user_id = $%d, ", argNum))
		args = append(args, params.UserID.Data)
		argNum++
	}

	if params.Data.Some {
		query.WriteString(fmt.Sprintf("data = $%d, ", argNum))
		args = append(args, params.Data.Data)
		argNum++
	}

	if params.RevokedAt.Some {
		query.WriteString(fmt.Sprintf("revoked_at = $%d, ", argNum))
		args = append(args, params.RevokedAt.Data)
		argNum++
	}

	query.WriteString(fmt.Sprintf("updated_at = $%d WHERE id = $%d", argNum, argNum+1))
	args = append(args, time.Now(), id)

	if _, err := db.Exec(ctx, query.String(), args...); err != nil {
		err = fmt.Errorf("UpdateSession: failed to update session (id=%s): %w", id, err)
		db.logger.Error("UpdateSession error", "error", err)
		return err
	}
	return nil
}

func (db *Database) DeleteSessionByID(ctx context.Context, id uuid.UUID) error {
	if _, err := db.Exec(ctx, `DELETE FROM tbl_session WHERE id = $1`, id); err != nil {
		err = fmt.Errorf("DeleteSession: failed to delete session (id=%s): %w", id, err)
		db.logger.Error("DeleteSession error", "error", err)
		return err
	}
	return nil
}

func (db *Database) DeleteUserSessions(ctx context.Context, userID uuid.UUID) error {
	if _, err := db.Exec(ctx, `DELETE FROM tbl_session WHERE user_id = $1`, userID); err != nil {
		err = fmt.Errorf("DeleteUserSessions: failed to delete sessions for user (user_id=%s): %w", userID, err)
		db.logger.Error("DeleteUserSessions error", "error", err)
		return err
	}
	return nil
}
