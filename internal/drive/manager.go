package drive

import (
	"context"
	"errors"
	"fmt"
	"hp/internal/audit"
	"hp/internal/database"
	"hp/internal/notifications"
	"hp/internal/util"
	"log/slog"
	"time"

	"github.com/google/uuid"
)

const FolderMimeType = "application/askfrank.folder"

type Manager struct {
	Logger   *slog.Logger
	DB       *database.Database
	Auditor  *audit.Auditor
	Notifier *notifications.Manager
}

func NewManager(logger *slog.Logger, db *database.Database, auditor *audit.Auditor, notifier *notifications.Manager) Manager {
	return Manager{
		Logger:   logger,
		DB:       db,
		Auditor:  auditor,
		Notifier: notifier,
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

type ListFilesParams struct {
	DriveID  uuid.UUID
	FolderID util.Optional[uuid.UUID]
}

func (m *Manager) ListFiles(ctx context.Context, params ListFilesParams) ([]File, error) {
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

type StoreFileParams struct {
	DriveID  uuid.UUID
	FolderID util.Optional[uuid.UUID]
	Name     string
	Path     string // Path to the file on the local filesystem
}

// func (m *Manager) StoreFile(ctx context.Context, params StoreFileParams) (File, error) {
// 	var file File

// 	// Validate file name
// 	if params.Name == "" {
// 		return file, fmt.Errorf("file name cannot be empty")
// 	}

// 	// Check if parent folder exists if FolderID is provided
// 	if params.FolderID.Some {
// 		_, err := m.DB.GetFile(ctx, database.GetFileParams{
// 			ID:      util.Some(params.FolderID.Data),
// 			DriveID: util.Some(params.DriveID),
// 		})
// 		if err != nil {
// 			if errors.Is(err, database.ErrFileNotFound) {
// 				return file, fmt.Errorf("parent folder not found: %w", err)
// 			}

// 			return file, fmt.Errorf("failed to get parent folder: %w", err)
// 		}
// 	}

// 	// Check if file with the same name already exists in the parent directory
// 	existingFiles, err := m.DB.ListFiles(ctx, database.ListFilesParams{
// 		DriveID:  util.Some(params.DriveID),
// 		ParentID: util.Some(params.FolderID),
// 	})
// 	if err != nil {
// 		return file, fmt.Errorf("failed to check existing files: %w", err)
// 	}

// 	for _, f := range existingFiles {
// 		if f.Name == params.Name {
// 			return file, fmt.Errorf("a folder or file with the name '%s' already exists", params.Name)
// 		}
// 	}

// 	// Here you would typically upload the file to a storage service (e.g., AWS S3, Google Cloud Storage)
// 	// For simplicity, we'll skip that step and assume the file is stored successfully.

// 	// Get file info to determine size and mime type
// 	fileInfo, err := util.GetFileInfo(params.Path)
// 	if err != nil {
// 		return file, fmt.Errorf("failed to get file info: %w", err)
// 	}

// 	// Create file in database
// 	dbFile, err := m.DB.CreateFile(ctx, database.CreateFileParams{
// 		DriveID:  params.DriveID,
// 		ParentID: params.FolderID,
// 		Name:     params.Name,
// 		MimeType: fileInfo.MimeType,
// 		SizeBytes: func() uint64 {
// 			if fileInfo.Size < 0 {
// 				return 0
// 			}
// 			return uint64(fileInfo.Size)
// 		}(),
// 	})
// 	if err != nil {
// 		return file, fmt.Errorf("failed to create file record: %w", err)
// 	}

// 	file = File{
// 		ID:         dbFile.ID,
// 		Name:       dbFile.Name,
// 		MimeType:   dbFile.MimeType,
// 		SizeBytes:  dbFile.SizeBytes,
// 		ModifiedAt: dbFile.UpdatedAt,
// 	}

// 	return file, nil

// }

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
