package drive

import (
	"context"
	"errors"
	"fmt"
	"hp/internal/database"
	"hp/internal/util"
	"log/slog"
	"time"

	"github.com/google/uuid"
)

const FolderMimeType = "application/askfrank.folder"

type Manager struct {
	DB     *database.Database
	Logger *slog.Logger
}

func NewManager(db *database.Database, logger *slog.Logger) Manager {
	return Manager{
		DB:     db,
		Logger: logger,
	}
}

type File struct {
	ID         uuid.UUID
	Name       string
	MimeType   string
	SizeBytes  uint64 // in bytes
	ModifiedAt time.Time
}

type Folder struct {
	ID         uuid.UUID
	Name       string
	ModifiedAt time.Time
}

// Util function to get a user's drive ID, maybe better to move this info to collective user info in the future
func (m *Manager) UserDriveID(ctx context.Context, userID uuid.UUID) (uuid.UUID, error) {
	var driveID uuid.UUID

	dbDrive, err := m.DB.GetDrive(ctx, database.GetDriveParams{
		OwnerUserID: util.Some(userID),
	})
	if err != nil {
		return driveID, fmt.Errorf("failed to get drive by ID: %w", err)
	}

	driveID = dbDrive.ID
	return driveID, nil
}

type ListParams struct {
	DriveID  uuid.UUID
	FolderID util.Optional[uuid.UUID]
}

func (m *Manager) List(ctx context.Context, params ListParams) ([]File, error) {
	dbFiles, err := m.DB.ListFiles(ctx, database.ListFilesParams{
		DriveID:  util.Some(params.DriveID),
		ParentID: util.Some(params.FolderID),
	})
	if err != nil {
		return nil, err
	}

	files := make([]File, len(dbFiles))
	for i, dbFile := range dbFiles {
		files[i] = File{
			ID:   dbFile.ID,
			Name: dbFile.Name,
		}
	}

	return files, nil
}

type CreateFolderParams struct {
	DriveID  uuid.UUID
	ParentID util.Optional[uuid.UUID]
	Name     string
}

func (m *Manager) CreateFolder(ctx context.Context, params CreateFolderParams) (File, error) {
	var folder File

	// Validate folder name
	if params.Name == "" {
		return folder, fmt.Errorf("folder name cannot be empty")
	}

	// Check if parent folder exists if ParentID is provided
	if params.ParentID.Some {
		dbFolder, err := m.DB.GetFile(ctx, database.GetFileParams{
			ID:      util.Some(params.ParentID.Data),
			DriveID: util.Some(params.DriveID),
		})
		if err != nil {
			if errors.Is(err, database.ErrFileNotFound) {
				return folder, fmt.Errorf("parent folder not found: %w", err)
			}

			return folder, fmt.Errorf("failed to get parent folder: %w", err)
		}

		if dbFolder.MimeType != "application/askfrank.folder" {
			return folder, fmt.Errorf("parent ID does not refer to a folder")
		}
	}

	// Check if folder with the same name already exists in the parent directory
	existingFiles, err := m.DB.ListFiles(ctx, database.ListFilesParams{
		DriveID:  util.Some(params.DriveID),
		ParentID: util.Some(params.ParentID),
	})
	if err != nil {
		return folder, fmt.Errorf("failed to check existing folders: %w", err)
	}

	for _, file := range existingFiles {
		if file.Name == params.Name {
			return folder, fmt.Errorf("a folder or file with the name '%s' already exists", params.Name)
		}
	}

	// Create folder in database
	dbFile, err := m.DB.CreateFile(ctx, database.CreateFileParams{
		DriveID:  params.DriveID,
		ParentID: params.ParentID,
		Name:     params.Name,
		MimeType: FolderMimeType,
	})
	if err != nil {
		return folder, fmt.Errorf("failed to create folder: %w", err)
	}

	folder = File{
		ID:         dbFile.ID,
		Name:       dbFile.Name,
		MimeType:   FolderMimeType,
		ModifiedAt: dbFile.UpdatedAt,
		SizeBytes:  0,
	}

	return folder, nil
}
