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

type Folder struct {
	ID        uuid.UUID
	Name      string
	OwnerID   uuid.UUID
	ParentID  uuid.NullUUID
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (db *PostgresDatabase) CreateFolder(ctx context.Context, folder Folder) error {
	if _, err := db.Exec(ctx, `INSERT INTO tbl_folder (id, name, owner_id, parent_id, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6)`,
		folder.ID, folder.Name, folder.OwnerID, folder.ParentID, folder.CreatedAt, folder.UpdatedAt); err != nil {
		// Handle error
		return err
	}
	return nil
}

func (db *PostgresDatabase) GetFoldersByParentID(ctx context.Context, ownerID uuid.UUID, parentID uuid.NullUUID) ([]Folder, error) {
	query := `SELECT id, name, owner_id, parent_id, created_at, updated_at FROM tbl_folder WHERE owner_id = $1`
	args := []any{ownerID}

	if parentID.Valid {
		query += ` AND parent_id = $2`
		args = append(args, parentID)
	} else {
		query += ` AND parent_id IS NULL`
	}

	rows, err := db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var folders []Folder
	for rows.Next() {
		var folder Folder
		if err := rows.Scan(&folder.ID, &folder.Name, &folder.OwnerID, &folder.ParentID, &folder.CreatedAt, &folder.UpdatedAt); err != nil {
			return nil, err
		}
		folders = append(folders, folder)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return folders, nil
}

func (db *PostgresDatabase) GetFolderByID(ctx context.Context, id uuid.UUID) (Folder, error) {
	var folder Folder
	err := db.QueryRow(ctx, `SELECT id, name, owner_id, parent_id, created_at, updated_at FROM tbl_folder WHERE id = $1`, id).Scan(
		&folder.ID, &folder.Name, &folder.OwnerID, &folder.ParentID, &folder.CreatedAt, &folder.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return folder, errors.New("Folder not found")
		}
		return folder, err
	}
	return folder, nil
}

func (db *PostgresDatabase) GetFoldersByOwnerID(ctx context.Context, ownerID uuid.UUID) ([]Folder, error) {
	query := `SELECT id, name, owner_id, parent_id, created_at, updated_at FROM tbl_folder WHERE owner_id = $1`

	rows, err := db.Query(ctx, query, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var folders []Folder
	for rows.Next() {
		var folder Folder
		if err := rows.Scan(&folder.ID, &folder.Name, &folder.OwnerID, &folder.ParentID, &folder.CreatedAt, &folder.UpdatedAt); err != nil {
			return nil, err
		}
		folders = append(folders, folder)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return folders, nil
}

func (db *PostgresDatabase) GetFilesByOwnerID(ctx context.Context, ownerID uuid.UUID) ([]File, error) {
	query := `SELECT id, owner_id, folder_id, filename, mime_type, s3_key, size_bytes, created_at, updated_at FROM tbl_file WHERE owner_id = $1`

	rows, err := db.Query(ctx, query, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var files []File
	for rows.Next() {
		var file File
		if err := rows.Scan(&file.ID, &file.OwnerID, &file.FolderID, &file.Filename, &file.MimeType, &file.S3Key, &file.SizeBytes, &file.CreatedAt, &file.UpdatedAt); err != nil {
			return nil, err
		}
		files = append(files, file)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return files, nil
}

func (db *PostgresDatabase) UpdateFolder(ctx context.Context, folder Folder) error {
	if _, err := db.Exec(ctx, `UPDATE tbl_folder SET name = $1, owner_id = $2, parent_id = $3, updated_at = $4 WHERE id = $5`,
		folder.Name, folder.OwnerID, folder.ParentID, folder.UpdatedAt, folder.ID); err != nil {
		// Handle error
		return err
	}
	return nil
}

func (db *PostgresDatabase) DeleteFolder(ctx context.Context, ownerID, folderID uuid.UUID) error {
	// Start a transaction to ensure atomicity
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// First, recursively delete all child folders and their contents
	if err := db.deleteFolderRecursively(ctx, tx, ownerID, folderID); err != nil {
		return err
	}

	// Commit the transaction
	return tx.Commit(ctx)
}

// deleteFolderRecursively deletes a folder and all its contents recursively
func (db *PostgresDatabase) deleteFolderRecursively(ctx context.Context, tx pgx.Tx, ownerID, folderID uuid.UUID) error {
	// First, get all child folders
	rows, err := tx.Query(ctx, `SELECT id FROM tbl_folder WHERE parent_id = $1 AND owner_id = $2`, folderID, ownerID)
	if err != nil {
		return err
	}
	defer rows.Close()

	var childFolderIDs []uuid.UUID
	for rows.Next() {
		var childID uuid.UUID
		if err := rows.Scan(&childID); err != nil {
			return err
		}
		childFolderIDs = append(childFolderIDs, childID)
	}

	// Recursively delete all child folders
	for _, childID := range childFolderIDs {
		if err := db.deleteFolderRecursively(ctx, tx, ownerID, childID); err != nil {
			return err
		}
	}

	// Delete all files in this folder
	if _, err := tx.Exec(ctx, `DELETE FROM tbl_file WHERE folder_id = $1 AND owner_id = $2`, folderID, ownerID); err != nil {
		return err
	}

	// Finally, delete the folder itself
	if _, err := tx.Exec(ctx, `DELETE FROM tbl_folder WHERE id = $1 AND owner_id = $2`, folderID, ownerID); err != nil {
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
	FolderID  uuid.NullUUID
	Filename  string
	MimeType  string
	S3Key     string
	SizeBytes uint64
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (db *PostgresDatabase) CreateFile(ctx context.Context, file File) error {
	if _, err := db.Exec(ctx, `INSERT INTO tbl_file (id, owner_id, folder_id, filename, mime_type, s3_key, size_bytes, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		file.ID, file.OwnerID, file.FolderID, file.Filename, file.MimeType, file.S3Key, file.SizeBytes, file.CreatedAt, file.UpdatedAt); err != nil {
		// Handle error
		return err
	}
	return nil
}

func (db *PostgresDatabase) GetFilesByFolderID(ctx context.Context, ownerID uuid.UUID, folderID uuid.NullUUID) ([]File, error) {
	query := `SELECT id, owner_id, folder_id, filename, mime_type, s3_key, size_bytes, created_at, updated_at FROM tbl_file WHERE owner_id = $1`
	args := []any{ownerID}
	if folderID.Valid {
		query += ` AND folder_id = $2`
		args = append(args, folderID)
	} else {
		query += ` AND folder_id IS NULL`
	}

	rows, err := db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var files []File
	for rows.Next() {
		var file File
		if err := rows.Scan(&file.ID, &file.OwnerID, &file.FolderID, &file.Filename, &file.MimeType, &file.S3Key, &file.SizeBytes, &file.CreatedAt, &file.UpdatedAt); err != nil {
			return nil, err
		}
		files = append(files, file)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return files, nil
}

func (db *PostgresDatabase) GetFileByID(ctx context.Context, ownerID, fileID uuid.UUID) (File, error) {
	var file File
	err := db.QueryRow(ctx, `SELECT id, owner_id, folder_id, filename, mime_type, s3_key, size_bytes, created_at, updated_at FROM tbl_file WHERE id = $1 AND owner_id = $2`, fileID, ownerID).Scan(
		&file.ID, &file.OwnerID, &file.FolderID, &file.Filename, &file.MimeType, &file.S3Key, &file.SizeBytes, &file.CreatedAt, &file.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return file, ErrFileNotFound
		}
		return file, err
	}
	return file, nil
}

func (db *PostgresDatabase) UpdateFile(ctx context.Context, file File) error {
	if _, err := db.Exec(ctx, `UPDATE tbl_file SET owner_id = $1, folder_id = $2, filename = $3, mime_type = $4, s3_key = $5, size_bytes = $6, updated_at = $7 WHERE id = $8`,
		file.OwnerID, file.FolderID, file.Filename, file.MimeType, file.S3Key, file.SizeBytes, file.UpdatedAt, file.ID); err != nil {
		// Handle error
		return err
	}
	return nil
}

func (db *PostgresDatabase) DeleteFile(ctx context.Context, ownerID, id uuid.UUID) error {
	if _, err := db.Exec(ctx, `DELETE FROM tbl_file WHERE id = $1 AND owner_id = $2`, id, ownerID); err != nil {
		// Handle error
		return err
	}
	return nil
}
