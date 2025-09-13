package database

import (
	"context"
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

func NewDatabase(cfg config.DatabaseConfig, logger *slog.Logger) *PostgresDatabase {
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
		panic("Unable to parse database configuration: " + err.Error())
	}

	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		// Handle error
		panic("Unable to connect to database: " + err.Error())
	}

	// Set the connection pool to be used by the PostgresDatabase
	if err := pool.Ping(context.Background()); err != nil {
		// Handle error
		panic("Unable to ping database: " + err.Error())
	}

	return &PostgresDatabase{
		pool,
		logger,
	}
}

func (db *PostgresDatabase) Close() {
	if db.Pool != nil {
		db.Pool.Close()
	}
}

var (
	ErrUserNotFound = errors.New("User not found")
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
		// Handle error
		return user, err
	}
	return user, nil
}

type GetUserParams struct {
	ID    uuid.UUID
	Email string
}

func (db *PostgresDatabase) GetUser(ctx context.Context, params GetUserParams) (User, error) {
	var user User

	query := `SELECT id, name, email, password_hash, is_email_verified, created_at, updated_at FROM tbl_user WHERE 1 = 1`
	args := []any{}

	if params.ID != uuid.Nil {
		query += ` AND id = $1`
		args = append(args, params.ID)
	}

	if params.Email != "" {
		query += ` AND email = $2`
		args = append(args, params.Email)
	}

	query += ` LIMIT 1`

	err := db.QueryRow(ctx, query, args...).Scan(
		&user.ID, &user.Name, &user.Email, &user.PasswordHash, &user.IsEmailVerified, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return user, ErrUserNotFound
		}
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
		// Handle error
		return err
	}
	return nil
}

func (db *PostgresDatabase) DeleteUser(ctx context.Context, id uuid.UUID) error {
	if _, err := db.Exec(ctx, `DELETE FROM tbl_user WHERE id = $1`, id); err != nil {
		// Handle error
		return err
	}
	return nil
}

var (
	ErrFileNotFound = errors.New("File not found")
)

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

func (f File) IsFile() bool {
	return f.MimeType != MIMETYPE_FOLDER
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

type GetFilesParams struct {
	OwnerID    uuid.UUID
	InFolder   uuid.UUID
	InRoot     bool
	AllowedIDs []uuid.UUID
}

func (db *PostgresDatabase) GetFiles(ctx context.Context, params GetFilesParams) ([]File, error) {
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

	if params.InFolder != uuid.Nil {
		query += fmt.Sprintf(" AND parent_id = $%d", argNum)
		args = append(args, params.InFolder)
		argNum++
	}

	if params.InRoot {
		query += ` AND parent_id IS NULL`
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

type GetFileByIDParams struct {
}

func (db *PostgresDatabase) GetFileByID(ctx context.Context, fileID uuid.UUID, params GetFileByIDParams) (File, error) {
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

type GetFileWithParentsParams struct {
}

func (db *PostgresDatabase) GetFileWithParents(ctx context.Context, fileID uuid.UUID, params GetFileWithParentsParams) ([]File, error) {
	var files []File

	rows, err := db.Query(ctx, `
		WITH RECURSIVE folder_path AS (
			SELECT id, owner_id, parent_id, name, mime_type, s3_key, size_bytes, created_at, updated_at
			FROM tbl_file
			WHERE id = $1
			UNION ALL
			SELECT f.id, f.owner_id, f.parent_id, f.name, f.mime_type, f.s3_key, f.size_bytes, f.created_at, f.updated_at
			FROM tbl_file f
			INNER JOIN folder_path fp ON f.id = fp.parent_id
		)
		SELECT id, owner_id, parent_id, name, mime_type, s3_key, size_bytes, created_at, updated_at
		FROM folder_path
		ORDER BY created_at DESC
	`, fileID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return files, ErrFileNotFound
		}
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

type DeleteFileParams struct {
}

func (db *PostgresDatabase) DeleteFile(ctx context.Context, fileID uuid.UUID, params DeleteFileParams) error {
	if _, err := db.Exec(ctx, `DELETE FROM tbl_file WHERE id = $1`, fileID); err != nil {
		// Handle error
		return err
	}
	return nil
}

type GetSharedFilesParams struct {
	UserID uuid.UUID
}

func (db *PostgresDatabase) GetSharedFiles(ctx context.Context, params GetSharedFilesParams) ([]File, error) {
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
