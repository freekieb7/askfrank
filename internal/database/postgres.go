package database

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hp/internal/config"
	"log/slog"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresDatabase struct {
	*pgxpool.Pool
	logger *slog.Logger
}

func NewPostgresDatabase(logger *slog.Logger) PostgresDatabase {
	return PostgresDatabase{
		Pool:   nil,
		logger: logger,
	}
}

func (db *PostgresDatabase) Init(cfg config.DatabaseConfig) error {
	// Construct the connection string
	dsn := "host=" + cfg.Host +
		" port=" + strconv.Itoa(cfg.Port) +
		" user=" + cfg.User +
		" password=" + cfg.Password +
		" dbname=" + cfg.Name +
		" sslmode=" + cfg.SSLMode

	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		// Handle error
		return fmt.Errorf("unable to parse database configuration: %w", err)
	}

	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		// Handle error
		return fmt.Errorf("unable to connect to database: %w", err)
	}

	// Set the connection pool to be used by the PostgresDatabase
	if err := pool.Ping(context.Background()); err != nil {
		// Handle error
		return fmt.Errorf("unable to ping database: %w", err)
	}

	db.Pool = pool
	return nil
}

func (db *PostgresDatabase) Close() {
	if db.Pool != nil {
		db.Pool.Close()
	}
}

var (
	ErrUserNotFound              = errors.New("user not found")
	ErrOAuthRefreshTokenNotFound = errors.New("oAuth refresh token not found")
	ErrOAuthAccessTokenNotFound  = errors.New("oAuth access token not found")
	ErrOAuthAuthCodeNotFound     = errors.New("oAuth authorization code not found")
	ErrOAuthSigningKeyNotFound   = errors.New("oAuth signing key not found")
	ErrOAuthClientNotFound       = errors.New("oAuth client not found")
	ErrFileNotFound              = errors.New("file not found")
)

type User struct {
	ID              uuid.UUID
	Name            string
	Email           string
	PasswordHash    []byte
	IsEmailVerified bool
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type CreateUserParams struct {
	Name         string
	Email        string
	PasswordHash []byte
}

func (db *PostgresDatabase) CreateUser(ctx context.Context, params CreateUserParams) (User, error) {
	var user User
	user.ID = uuid.New()
	user.Name = params.Name
	user.Email = params.Email
	user.PasswordHash = params.PasswordHash
	user.IsEmailVerified = false
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	if _, err := db.Exec(ctx, `INSERT INTO tbl_user (id, name, email, password_hash, is_email_verified, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		user.ID, user.Name, user.Email, user.PasswordHash, user.IsEmailVerified, user.CreatedAt, user.UpdatedAt); err != nil {
		err = fmt.Errorf("CreateUser: failed to insert user (email=%s): %w", user.Email, err)
		db.logger.Error("CreateUser error", "error", err)
		return user, err
	}
	return user, nil
}

func (db *PostgresDatabase) GetUser(ctx context.Context, userID uuid.UUID) (User, error) {
	var user User

	query := `SELECT id, name, email, password_hash, is_email_verified, created_at, updated_at FROM tbl_user WHERE id = $1 LIMIT 1`
	args := []any{userID}

	err := db.QueryRow(ctx, query, args...).Scan(
		&user.ID, &user.Name, &user.Email, &user.PasswordHash, &user.IsEmailVerified, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return user, ErrUserNotFound
		}
		err = fmt.Errorf("GetUser: failed to scan user (id=%s): %w", userID, err)
		db.logger.Error("GetUser error", "error", err)
		return user, err
	}
	return user, nil
}

type RetrieveUserParams struct {
	Email string
}

func (db *PostgresDatabase) RetrieveUser(ctx context.Context, params RetrieveUserParams) (User, error) {
	var user User

	query := `SELECT id, name, email, password_hash, is_email_verified, created_at, updated_at FROM tbl_user WHERE 1 = 1`
	args := []any{}

	if params.Email != "" {
		query += ` AND email = $1`
		args = append(args, params.Email)
	}

	query += ` LIMIT 1`

	err := db.QueryRow(ctx, query, args...).Scan(
		&user.ID, &user.Name, &user.Email, &user.PasswordHash, &user.IsEmailVerified, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return user, ErrUserNotFound
		}
		err = fmt.Errorf("RetrieveUser: failed to scan user (email=%s): %w", params.Email, err)
		db.logger.Error("RetrieveUser error", "error", err)
		return user, err
	}
	return user, nil
}

type UpdateUserParams struct {
	Name            *string
	Email           *string
	PasswordHash    []byte
	IsEmailVerified *bool
	DeletedAt       *time.Time
}

func (db *PostgresDatabase) UpdateUser(ctx context.Context, id uuid.UUID, params UpdateUserParams) error {
	if _, err := db.Exec(ctx, `UPDATE tbl_user SET name = $1, email = $2, password_hash = $3, is_email_verified = $4, updated_at = $5 WHERE id = $6`,
		params.Name, params.Email, params.PasswordHash, params.IsEmailVerified, time.Now(), id); err != nil {
		err = fmt.Errorf("UpdateUser: failed to update user (id=%s): %w", id, err)
		db.logger.Error("UpdateUser error", "error", err)
		return err
	}
	return nil
}

func (db *PostgresDatabase) DeleteUser(ctx context.Context, id uuid.UUID) error {
	if _, err := db.Exec(ctx, `DELETE FROM tbl_user WHERE id = $1`, id); err != nil {
		err = fmt.Errorf("DeleteUser: failed to delete user (id=%s): %w", id, err)
		db.logger.Error("DeleteUser error", "error", err)
		return err
	}
	return nil
}

const (
	MIMETYPE_FOLDER = "application/askfrank.folder"
	MIMETYPE_PDF    = "application/pdf"
	MIMETYPE_JPEG   = "image/jpeg"
	MIMETYPE_PNG    = "image/png"
)

type File struct {
	ID        uuid.UUID
	OwnerID   uuid.UUID
	ParentID  uuid.NullUUID
	Name      string
	MimeType  string
	S3Key     string
	SizeBytes int64
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (f File) IsFolder() bool {
	return f.MimeType == MIMETYPE_FOLDER
}

func (f File) IsPDF() bool {
	return f.MimeType == MIMETYPE_PDF
}

func (f File) IsImage() bool {
	return f.MimeType == MIMETYPE_JPEG || f.MimeType == MIMETYPE_PNG
}

type RetrieveFileListParams struct {
	OwnerID    uuid.UUID
	InFolder   uuid.UUID
	AllowedIDs []uuid.UUID
}

func (db *PostgresDatabase) RetrieveFileList(ctx context.Context, params RetrieveFileListParams) ([]File, error) {
	query := `SELECT id, owner_id, parent_id, name, mime_type, s3_key, size_bytes, created_at, updated_at FROM tbl_file WHERE 1 = 1`
	args := []any{}
	argNum := 1

	if params.AllowedIDs != nil {
		query += fmt.Sprintf(" AND id = ANY($%d)", argNum)
		args = append(args, params.AllowedIDs)
		argNum++
	}

	if params.OwnerID != uuid.Nil {
		query += fmt.Sprintf(" AND owner_id = $%d", argNum)
		args = append(args, params.OwnerID)
		argNum++
	}

	if params.InFolder == uuid.Nil {
		query += ` AND parent_id IS NULL`
	} else {
		query += fmt.Sprintf(" AND parent_id = $%d", argNum)
		args = append(args, params.InFolder)
		argNum++
	}

	rows, err := db.Query(ctx, query, args...)
	if err != nil {
		db.logger.Error("Failed to execute query", "error", err, "query", query, "args", args)
		return nil, err
	}
	defer rows.Close()

	var files []File
	for rows.Next() {
		var file File
		if err := rows.Scan(&file.ID, &file.OwnerID, &file.ParentID, &file.Name, &file.MimeType, &file.S3Key, &file.SizeBytes, &file.CreatedAt, &file.UpdatedAt); err != nil {
			return nil, err
		}
		files = append(files, file)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return files, nil
}

type CreateFileParams struct {
	OwnerID   uuid.UUID
	ParentID  uuid.NullUUID
	Name      string
	MimeType  string
	S3Key     string
	SizeBytes int64
}

func (db *PostgresDatabase) CreateFile(ctx context.Context, params CreateFileParams) (File, error) {
	file := File{
		ID:        uuid.New(),
		OwnerID:   params.OwnerID,
		ParentID:  params.ParentID,
		Name:      params.Name,
		MimeType:  params.MimeType,
		S3Key:     params.S3Key,
		SizeBytes: params.SizeBytes,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if _, err := db.Exec(ctx, `INSERT INTO tbl_file (id, owner_id, parent_id, name, mime_type, s3_key, size_bytes, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		file.ID, file.OwnerID, file.ParentID, file.Name, file.MimeType, file.S3Key, file.SizeBytes, file.CreatedAt, file.UpdatedAt); err != nil {
		// Handle error
		return file, err
	}
	return file, nil
}

func (db *PostgresDatabase) GetFile(ctx context.Context, fileID uuid.UUID) (File, error) {
	var file File
	err := db.QueryRow(ctx, `SELECT id, owner_id, parent_id, name, mime_type, s3_key, size_bytes, created_at, updated_at FROM tbl_file WHERE id = $1`, fileID).Scan(
		&file.ID, &file.OwnerID, &file.ParentID, &file.Name, &file.MimeType, &file.S3Key, &file.SizeBytes, &file.CreatedAt, &file.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return file, ErrFileNotFound
		}
		return file, err
	}
	return file, nil
}

func (db *PostgresDatabase) DeleteFile(ctx context.Context, fileID uuid.UUID) error {
	if _, err := db.Exec(ctx, `DELETE FROM tbl_file WHERE id = $1`, fileID); err != nil {
		// Handle error
		return err
	}
	return nil
}

type RetrieveSharedFilesParams struct {
	UserID uuid.UUID
}

func (db *PostgresDatabase) RetrieveSharedFiles(ctx context.Context, params RetrieveSharedFilesParams) ([]File, error) {
	var files []File

	rows, err := db.Query(ctx, `
		SELECT f.id, f.owner_id, f.parent_id, f.name, f.mime_type, f.s3_key, f.size_bytes, f.created_at, f.updated_at
		FROM tbl_shared_files sf
		INNER JOIN tbl_file f ON sf.file_id = f.id
		WHERE sf.receiving_user_id = $1
	`, params.UserID)
	if err != nil {
		return files, err
	}
	defer rows.Close()

	files = make([]File, 0)
	for rows.Next() {
		var file File
		if err := rows.Scan(&file.ID, &file.OwnerID, &file.ParentID, &file.Name, &file.MimeType, &file.S3Key, &file.SizeBytes, &file.CreatedAt, &file.UpdatedAt); err != nil {
			return files, err
		}
		files = append(files, file)
	}
	if err := rows.Err(); err != nil {
		return files, err
	}

	return files, nil
}

type CreateSharedFileParams struct {
	FileID          uuid.UUID
	SharingUserID   uuid.UUID
	ReceivingUserID uuid.UUID
	GrantedAt       time.Time
}

func (db *PostgresDatabase) CreateSharedFile(ctx context.Context, params CreateSharedFileParams) error {
	if _, err := db.Exec(ctx, `INSERT INTO tbl_shared_files (file_id, sharing_user_id, receiving_user_id, granted_at) VALUES ($1, $2, $3, $4)`,
		params.FileID, params.SharingUserID, params.ReceivingUserID, params.GrantedAt); err != nil {
		// Handle error
		return err
	}
	return nil
}

func (db *PostgresDatabase) DeleteSharedFile(ctx context.Context, fileID, receivingUserID uuid.UUID) error {
	if _, err := db.Exec(ctx, `DELETE FROM tbl_shared_files WHERE file_id = $1 AND receiving_user_id = $2`, fileID, receivingUserID); err != nil {
		// Handle error
		return err
	}
	return nil
}

type OAuthClient struct {
	ID            uuid.UUID
	Name          string
	RedirectURIs  []string
	Public        bool
	Secret        string
	AllowedScopes []string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

func (db *PostgresDatabase) RetrieveOAuthClientList(ctx context.Context) ([]OAuthClient, error) {
	var clients []OAuthClient

	rows, err := db.Query(ctx, `SELECT id, name, redirect_uris, public, secret_hash, allowed_scopes, created_at, updated_at FROM tbl_oauth_client`)
	if err != nil {
		return clients, err
	}
	defer rows.Close()

	clients = make([]OAuthClient, 0)
	for rows.Next() {
		var client OAuthClient
		if err := rows.Scan(&client.ID, &client.Name, &client.RedirectURIs, &client.Public, &client.Secret, &client.AllowedScopes, &client.CreatedAt, &client.UpdatedAt); err != nil {
			return clients, err
		}
		clients = append(clients, client)
	}
	if err := rows.Err(); err != nil {
		return clients, err
	}

	return clients, nil
}

type CreateOAuthClientParams struct {
	ClientID      uuid.UUID
	ClientSecret  string
	Name          string
	RedirectURIs  []string
	AllowedScopes []string
	Public        bool
}

func (db *PostgresDatabase) CreateOAuthClient(ctx context.Context, params CreateOAuthClientParams) (OAuthClient, error) {
	client := OAuthClient{
		ID:            params.ClientID,
		Name:          params.Name,
		RedirectURIs:  params.RedirectURIs,
		Public:        params.Public,
		Secret:        params.ClientSecret,
		AllowedScopes: params.AllowedScopes,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	if _, err := db.Exec(ctx, `INSERT INTO tbl_oauth_client (id, name, redirect_uris, public, secret, allowed_scopes, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		client.ID, client.Name, client.RedirectURIs, client.Public, client.Secret, client.AllowedScopes, client.CreatedAt, client.UpdatedAt); err != nil {
		// Handle error
		return client, err
	}

	return client, nil
}

func (db *PostgresDatabase) GetOAuthClient(ctx context.Context, clientID uuid.UUID) (OAuthClient, error) {
	var client OAuthClient
	err := db.QueryRow(ctx, `SELECT id, name, redirect_uris, public, secret, allowed_scopes, created_at, updated_at FROM tbl_oauth_client WHERE id = $1`, clientID).Scan(
		&client.ID, &client.Name, &client.RedirectURIs, &client.Public, &client.Secret, &client.AllowedScopes, &client.CreatedAt, &client.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return client, ErrOAuthClientNotFound
		}
		return client, err
	}
	return client, nil
}

func (db *PostgresDatabase) DeleteOAuthClient(ctx context.Context, clientID uuid.UUID) error {
	if _, err := db.Exec(ctx, `DELETE FROM tbl_oauth_client WHERE id = $1`, clientID); err != nil {
		// Handle error
		return err

	}
	return nil
}

type OAuthSigningKey struct {
	ID        uuid.UUID
	Key       []byte
	CreatedAt time.Time
}

// RetrieveOAuthSigningKeyList fetches all signing keys from the database, ordered by creation date descending.
func (db *PostgresDatabase) RetrieveOAuthSigningKeyList(ctx context.Context) ([]OAuthSigningKey, error) {
	var keys []OAuthSigningKey
	rows, err := db.Query(ctx, `SELECT id, key, created_at FROM tbl_oauth_signing_key ORDER BY created_at DESC`)
	if err != nil {
		return keys, err
	}
	defer rows.Close()

	for rows.Next() {
		var key OAuthSigningKey
		if err := rows.Scan(&key.ID, &key.Key, &key.CreatedAt); err != nil {
			return keys, err
		}
		keys = append(keys, key)
	}
	if err := rows.Err(); err != nil {
		return keys, err
	}

	return keys, nil
}

type CreateOAuthSigningKeyParams struct {
	Key []byte
}

func (db *PostgresDatabase) CreateOAuthSigningKey(ctx context.Context, params CreateOAuthSigningKeyParams) (OAuthSigningKey, error) {
	signingKey := OAuthSigningKey{
		ID:        uuid.New(),
		Key:       params.Key,
		CreatedAt: time.Now(),
	}

	if _, err := db.Exec(ctx, `INSERT INTO tbl_oauth_signing_key (id, key, created_at) VALUES ($1, $2, $3)`,
		signingKey.ID, signingKey.Key, signingKey.CreatedAt); err != nil {
		// Handle error
		return signingKey, err
	}
	return signingKey, nil
}

func (db *PostgresDatabase) GetOAuthSigningKey(ctx context.Context, keyID uuid.UUID) (OAuthSigningKey, error) {
	var key OAuthSigningKey
	err := db.QueryRow(ctx, `SELECT id, key, created_at FROM tbl_oauth_signing_key WHERE id = $1`, keyID).Scan(
		&key.ID, &key.Key, &key.CreatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return key, ErrOAuthSigningKeyNotFound
		}
		return key, err
	}
	return key, nil
}

func (db *PostgresDatabase) DeleteOAuthSigningKey(ctx context.Context, keyID uuid.UUID) error {
	if _, err := db.Exec(ctx, `DELETE FROM tbl_oauth_signing_key WHERE id = $1`, keyID); err != nil {
		// Handle error
		return err
	}
	return nil
}

type OAuthCode struct {
	Code                string    `json:"code"`
	ClientID            uuid.UUID `json:"client_id"`
	UserID              uuid.UUID `json:"user_id"`
	RedirectURI         string    `json:"redirect_uri"`
	CodeChallenge       string    `json:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method"` // "S256" or "plain"
	Scopes              []string  `json:"scopes"`
	CreatedAt           time.Time `json:"created_at"`
	ExpiresAt           time.Time `json:"expires_at"`
}

type CreateOAuthAuthCodeParams struct {
	Code                string
	ClientID            uuid.UUID
	UserID              uuid.UUID
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string // "S256" or "plain"
	Scopes              []string
	ExpiresAt           time.Time
}

func (db *PostgresDatabase) CreateOAuthAuthCode(ctx context.Context, params CreateOAuthAuthCodeParams) (OAuthCode, error) {
	authCode := OAuthCode{
		Code:                params.Code,
		ClientID:            params.ClientID,
		UserID:              params.UserID,
		RedirectURI:         params.RedirectURI,
		CodeChallenge:       params.CodeChallenge,
		CodeChallengeMethod: params.CodeChallengeMethod,
		Scopes:              params.Scopes,
		CreatedAt:           time.Now(),
		ExpiresAt:           params.ExpiresAt,
	}

	// Serialize Data to JSON
	authCodeJSON, err := json.Marshal(authCode)
	if err != nil {
		err = fmt.Errorf("CreateOAuthAuthCode: failed to marshal auth code: %w", err)
		db.logger.Error("Failed to marshal auth code", "error", err)
		return authCode, err
	}

	if _, err := db.Exec(ctx, `INSERT INTO tbl_oauth_auth_code (code, data, created_at, expires_at) VALUES ($1, $2, $3, $4)`,
		authCode.Code, authCodeJSON, time.Now(), authCode.ExpiresAt,
	); err != nil {
		err = fmt.Errorf("CreateOAuthAuthCode: failed to insert auth code: %w", err)
		db.logger.Error("Failed to insert auth code", "error", err)
		return authCode, err
	}
	return authCode, nil
}

func (db *PostgresDatabase) GetOAuthAuthCode(ctx context.Context, code string) (OAuthCode, error) {
	var authCode OAuthCode
	var dataJSON []byte
	err := db.QueryRow(ctx, `SELECT code, data, created_at FROM tbl_oauth_auth_code WHERE code = $1`, code).Scan(
		&authCode.Code, &dataJSON, &authCode.CreatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return authCode, ErrOAuthAuthCodeNotFound
		}

		err = fmt.Errorf("GetOAuthAuthCode: failed to query auth code: %w", err)
		db.logger.Error("Failed to query auth code", "error", err)
		return authCode, err
	}

	// Deserialize JSON to Data map
	if err := json.Unmarshal(dataJSON, &authCode); err != nil {
		err = fmt.Errorf("GetOAuthAuthCode: failed to unmarshal auth code data: %w", err)
		db.logger.Error("Failed to unmarshal auth code data", "error", err)
		return authCode, err
	}

	return authCode, nil
}

func (db *PostgresDatabase) DeleteOAuthAuthCode(ctx context.Context, code string) error {
	if _, err := db.Exec(ctx, `DELETE FROM tbl_oauth_auth_code WHERE code = $1`, code); err != nil {
		err = fmt.Errorf("DeleteOAuthAuthCode: failed to delete auth code: %w", err)
		db.logger.Error("Failed to delete auth code", "error", err)
		return err
	}
	return nil
}

type AccessToken struct {
	Token     string    `json:"token"`
	ClientID  uuid.UUID `json:"client_id"`
	UserID    uuid.UUID `json:"user_id"`
	Scopes    []string  `json:"scopes"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type CreateOAuthAccessTokenParams struct {
	Token     string
	ClientID  uuid.UUID
	UserID    uuid.UUID
	Scopes    []string
	ExpiresAt time.Time
}

func (db *PostgresDatabase) CreateOAuthAccessToken(ctx context.Context, params CreateOAuthAccessTokenParams) (AccessToken, error) {
	accessToken := AccessToken{
		Token:     params.Token,
		ClientID:  params.ClientID,
		UserID:    params.UserID,
		Scopes:    params.Scopes,
		CreatedAt: time.Now(),
		ExpiresAt: params.ExpiresAt,
	}
	// Serialize Data to JSON
	accessTokenJSON, err := json.Marshal(accessToken)
	if err != nil {
		err = fmt.Errorf("CreateOAuthAccessToken: failed to marshal access token: %w", err)
		db.logger.Error("Failed to marshal access token", "error", err)
		return accessToken, err
	}

	if _, err := db.Exec(ctx, `INSERT INTO tbl_oauth_access_token (token, clientID, data, created_at, expires_at) VALUES ($1, $2, $3, $4, $5)`,
		params.Token, params.ClientID, accessTokenJSON, time.Now(), params.ExpiresAt,
	); err != nil {
		err = fmt.Errorf("CreateOAuthAccessToken: failed to insert access token: %w", err)
		db.logger.Error("Failed to insert access token", "error", err)
		return accessToken, err
	}
	return accessToken, nil
}

func (db *PostgresDatabase) GetOAuthAccessToken(ctx context.Context, token string) (AccessToken, error) {
	var accessToken AccessToken
	var dataJSON []byte
	err := db.QueryRow(ctx, `SELECT token, data, created_at, expires_at FROM tbl_oauth_access_token WHERE token = $1`, token).Scan(
		&accessToken.Token, &dataJSON, &accessToken.CreatedAt, &accessToken.ExpiresAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return accessToken, ErrOAuthAccessTokenNotFound
		}

		err = fmt.Errorf("GetOAuthAccessToken: failed to query access token: %w", err)
		db.logger.Error("Failed to query access token", "error", err)
		return accessToken, err
	}

	// Deserialize JSON to Data map
	if err := json.Unmarshal(dataJSON, &accessToken); err != nil {
		err = fmt.Errorf("GetOAuthAccessToken: failed to unmarshal access token data: %w", err)
		db.logger.Error("Failed to unmarshal access token data", "error", err)
		return accessToken, err
	}

	return accessToken, nil
}

func (db *PostgresDatabase) DeleteOAuthAccessToken(ctx context.Context, token string) error {
	if _, err := db.Exec(ctx, `DELETE FROM tbl_oauth_access_token WHERE token = $1`, token); err != nil {
		err = fmt.Errorf("DeleteOAuthAccessToken: failed to delete access token: %w", err)
		db.logger.Error("Failed to delete access token", "error", err)
		return err
	}
	return nil
}

type RefreshToken struct {
	Token     string    `json:"token"`
	ClientID  uuid.UUID `json:"client_id"`
	UserID    uuid.UUID `json:"user_id"`
	Scopes    []string  `json:"scopes"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type CreateOAuthRefreshTokenParams struct {
	Token     string
	ClientID  uuid.UUID
	UserID    uuid.UUID
	Scopes    []string
	ExpiresAt time.Time
}

func (db *PostgresDatabase) CreateOAuthRefreshToken(ctx context.Context, params CreateOAuthRefreshTokenParams) (RefreshToken, error) {
	refreshToken := RefreshToken{
		Token:     params.Token,
		ClientID:  params.ClientID,
		UserID:    params.UserID,
		Scopes:    params.Scopes,
		CreatedAt: time.Now(),
		ExpiresAt: params.ExpiresAt,
	}
	// Serialize Data to JSON
	refreshTokenJSON, err := json.Marshal(refreshToken)
	if err != nil {
		err = fmt.Errorf("CreateOAuthRefreshToken: failed to marshal refresh token: %w", err)
		db.logger.Error("Failed to marshal refresh token", "error", err)
		return refreshToken, err
	}

	if _, err := db.Exec(ctx, `INSERT INTO tbl_oauth_refresh_token (token, clientID, data, created_at, expires_at) VALUES ($1, $2, $3, $4, $5)`,
		params.Token, params.ClientID, refreshTokenJSON, time.Now(), params.ExpiresAt,
	); err != nil {
		err = fmt.Errorf("CreateOAuthRefreshToken: failed to insert refresh token: %w", err)
		db.logger.Error("Failed to insert refresh token", "error", err)
		return refreshToken, err
	}
	return refreshToken, nil
}

func (db *PostgresDatabase) GetOAuthRefreshToken(ctx context.Context, token string) (RefreshToken, error) {
	var refreshToken RefreshToken
	var dataJSON []byte
	err := db.QueryRow(ctx, `SELECT token, data, created_at, expires_at FROM tbl_oauth_refresh_token WHERE token = $1`, token).Scan(
		&refreshToken.Token, &dataJSON, &refreshToken.CreatedAt, &refreshToken.ExpiresAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return refreshToken, ErrOAuthRefreshTokenNotFound
		}

		err = fmt.Errorf("GetOAuthRefreshToken: failed to query refresh token: %w", err)
		db.logger.Error("Failed to query refresh token", "error", err)
		return refreshToken, err
	}

	// Deserialize JSON to Data map
	if err := json.Unmarshal(dataJSON, &refreshToken); err != nil {
		err = fmt.Errorf("GetOAuthRefreshToken: failed to unmarshal refresh token data: %w", err)
		db.logger.Error("Failed to unmarshal refresh token data", "error", err)
		return refreshToken, err
	}

	return refreshToken, nil
}

func (db *PostgresDatabase) DeleteOAuthRefreshToken(ctx context.Context, token string) error {
	if _, err := db.Exec(ctx, `DELETE FROM tbl_oauth_refresh_token WHERE token = $1`, token); err != nil {
		err := fmt.Errorf("DeleteOAuthRefreshToken: failed to delete refresh token: %w", err)
		db.logger.Error("Failed to delete refresh token", "error", err)
		return err
	}
	return nil
}

func (db *PostgresDatabase) DeleteExpiredOAuthData(ctx context.Context) error {
	if _, err := db.Exec(ctx, `DELETE FROM tbl_oauth_auth_code WHERE expires_at < $1`, time.Now()); err != nil {
		err = fmt.Errorf("DeleteExpiredOAuthData: failed to delete expired auth codes: %w", err)
		db.logger.Error("Failed to delete expired auth codes", "error", err)
		return err
	}
	if _, err := db.Exec(ctx, `DELETE FROM tbl_oauth_access_token WHERE expires_at < $1`, time.Now()); err != nil {
		err = fmt.Errorf("DeleteExpiredOAuthData: failed to delete expired access tokens: %w", err)
		db.logger.Error("Failed to delete expired access tokens", "error", err)
		return err
	}
	if _, err := db.Exec(ctx, `DELETE FROM tbl_oauth_refresh_token WHERE expires_at < $1`, time.Now()); err != nil {
		err = fmt.Errorf("DeleteExpiredOAuthData: failed to delete expired refresh tokens: %w", err)
		db.logger.Error("Failed to delete expired refresh tokens", "error", err)
		return err
	}
	return nil
}
