package database

import (
	"context"
	"errors"
	"hp/internal/config"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresDatabase struct {
	*pgxpool.Pool
}

func NewDatabase(cfg config.DatabaseConfig) *PostgresDatabase {
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

func (db *PostgresDatabase) CreateUser(ctx context.Context, user User) error {
	if _, err := db.Exec(ctx, `INSERT INTO tbl_user (id, name, email, password_hash, is_email_verified, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		user.ID, user.Name, user.Email, user.PasswordHash, user.IsEmailVerified, user.CreatedAt, user.UpdatedAt); err != nil {
		// Handle error
		return err
	}
	return nil
}

func (db *PostgresDatabase) GetUserByID(ctx context.Context, id uuid.UUID) (User, error) {
	var user User
	err := db.QueryRow(ctx, `SELECT id, name, email, password_hash, is_email_verified, created_at, updated_at FROM tbl_user WHERE id = $1`, id).Scan(
		&user.ID, &user.Name, &user.Email, &user.PasswordHash, &user.IsEmailVerified, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return user, ErrUserNotFound
		}
		return user, err
	}
	return user, nil
}

func (db *PostgresDatabase) GetUserByEmail(ctx context.Context, email string) (User, error) {
	var user User
	err := db.QueryRow(ctx, `SELECT id, name, email, password_hash, is_email_verified, created_at, updated_at FROM tbl_user WHERE email = $1`, email).Scan(
		&user.ID, &user.Name, &user.Email, &user.PasswordHash, &user.IsEmailVerified, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return user, ErrUserNotFound
		}
		return user, err
	}
	return user, nil
}

func (db *PostgresDatabase) UpdateUser(ctx context.Context, user User) error {
	if _, err := db.Exec(ctx, `UPDATE tbl_user SET name = $1, email = $2, password_hash = $3, is_email_verified = $4, updated_at = $5 WHERE id = $6`,
		user.Name, user.Email, user.PasswordHash, user.IsEmailVerified, user.UpdatedAt, user.ID); err != nil {
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

type File struct {
	ID        uuid.UUID
	OwnerID   uuid.UUID
	ParentID  uuid.NullUUID
	Name      string
	MimeType  string
	S3Key     string
	SizeBytes int64
	IsFolder  bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

type SearchFilesOptions struct {
	InFolder uuid.NullUUID // Optional folder ID to search within
}

func (db *PostgresDatabase) SearchFiles(ctx context.Context, ownerID uuid.UUID, options SearchFilesOptions) ([]File, error) {
	query := `SELECT id, owner_id, parent_id, name, mime_type, s3_key, size_bytes, is_folder, created_at, updated_at FROM tbl_file WHERE owner_id = $1`
	args := []any{ownerID}

	if options.InFolder.Valid {
		query += ` AND parent_id = $2`
		args = append(args, options.InFolder.UUID)
	} else {
		query += ` AND parent_id IS NULL`
	}

	rows, err := db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var files []File
	for rows.Next() {
		var file File
		if err := rows.Scan(&file.ID, &file.OwnerID, &file.ParentID, &file.Name, &file.MimeType, &file.S3Key, &file.SizeBytes, &file.IsFolder, &file.CreatedAt, &file.UpdatedAt); err != nil {
			return nil, err
		}
		files = append(files, file)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return files, nil
}

func (db *PostgresDatabase) CreateFile(ctx context.Context, file File) error {
	if _, err := db.Exec(ctx, `INSERT INTO tbl_file (id, owner_id, parent_id, name, mime_type, s3_key, size_bytes, is_folder, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		file.ID, file.OwnerID, file.ParentID, file.Name, file.MimeType, file.S3Key, file.SizeBytes, file.IsFolder, file.CreatedAt, file.UpdatedAt); err != nil {
		// Handle error
		return err
	}
	return nil
}

func (db *PostgresDatabase) GetFileByID(ctx context.Context, ownerID, id uuid.UUID) (File, error) {
	var file File
	err := db.QueryRow(ctx, `SELECT id, owner_id, parent_id, name, mime_type, s3_key, size_bytes, is_folder, created_at, updated_at FROM tbl_file WHERE id = $1 AND owner_id = $2`, id, ownerID).Scan(
		&file.ID, &file.OwnerID, &file.ParentID, &file.Name, &file.MimeType, &file.S3Key, &file.SizeBytes, &file.IsFolder, &file.CreatedAt, &file.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return file, ErrFileNotFound
		}
		return file, err
	}
	return file, nil
}

func (db *PostgresDatabase) GetParentFolders(ctx context.Context, ownerID, fileID uuid.UUID) ([]File, error) {
	var parents []File
	rows, err := db.Query(ctx, `
		WITH RECURSIVE folder_path AS (
			SELECT id, owner_id, parent_id, name, mime_type, s3_key, size_bytes, is_folder, created_at, updated_at
			FROM tbl_file
			WHERE id = $1 AND owner_id = $2
			UNION ALL
			SELECT f.id, f.owner_id, f.parent_id, f.name, f.mime_type, f.s3_key, f.size_bytes, f.is_folder, f.created_at, f.updated_at
			FROM tbl_file f
			INNER JOIN folder_path fp ON f.id = fp.parent_id
		)
		SELECT id, owner_id, parent_id, name, mime_type, s3_key, size_bytes, is_folder, created_at, updated_at
		FROM folder_path
		ORDER BY created_at DESC
	`, fileID, ownerID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return parents, ErrFileNotFound
		}
		return parents, err
	}
	defer rows.Close()

	for rows.Next() {
		var file File
		if err := rows.Scan(&file.ID, &file.OwnerID, &file.ParentID, &file.Name, &file.MimeType, &file.S3Key, &file.SizeBytes, &file.IsFolder, &file.CreatedAt, &file.UpdatedAt); err != nil {
			return parents, err
		}
		parents = append(parents, file)
	}
	if err := rows.Err(); err != nil {
		return parents, err
	}

	return parents, nil
}

func (db *PostgresDatabase) DeleteFile(ctx context.Context, ownerID, id uuid.UUID) error {
	if _, err := db.Exec(ctx, `DELETE FROM tbl_file WHERE id = $1 AND owner_id = $2`, id, ownerID); err != nil {
		// Handle error
		return err
	}
	return nil
}
