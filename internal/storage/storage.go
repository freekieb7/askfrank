package storage

import (
	"context"
	"io"
	"time"

	"github.com/google/uuid"
)

// Storage defines the interface for file storage operations
type Storage interface {
	// Store saves a file and returns the storage key
	Store(ctx context.Context, userID uuid.UUID, filename string, content io.Reader, contentType string) (string, error)

	// Retrieve gets a file by storage key
	Retrieve(ctx context.Context, key string) (io.ReadCloser, error)

	// Delete removes a file by storage key
	Delete(ctx context.Context, key string) error

	// GetURL returns a signed URL for accessing the file (for S3) or local path
	GetURL(ctx context.Context, key string, expiration time.Duration) (string, error)

	// Exists checks if a file exists
	Exists(ctx context.Context, key string) (bool, error)

	// GetMetadata returns file metadata
	GetMetadata(ctx context.Context, key string) (FileMetadata, error)
}

type FileMetadata struct {
	Size         int64     `json:"size"`
	ContentType  string    `json:"content_type"`
	LastModified time.Time `json:"last_modified"`
	ETag         string    `json:"etag"`
}

// StorageConfig holds configuration for different storage backends
type StorageType string

const (
	StorageTypeLocal StorageType = "local"
	StorageTypeS3    StorageType = "s3"
)

type StorageConfig struct {
	Type      StorageType
	LocalPath string
	S3        *S3Config
}

type S3Config struct {
	Bucket string
	Region string
}
