package storage

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

type LocalStorage struct {
	basePath string
}

func NewLocalStorage(basePath string) (*LocalStorage, error) {
	// Ensure base path exists
	if err := os.MkdirAll(basePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create storage directory: %w", err)
	}

	return &LocalStorage{
		basePath: basePath,
	}, nil
}

func (ls *LocalStorage) Store(ctx context.Context, userID uuid.UUID, filename string, content io.Reader, contentType string) (string, error) {
	// Generate storage key: user_id/year/month/uuid_filename
	now := time.Now()
	key := fmt.Sprintf("%s/%d/%02d/%s_%s",
		userID.String(),
		now.Year(),
		now.Month(),
		uuid.New().String(),
		sanitizeFilename(filename),
	)

	fullPath := filepath.Join(ls.basePath, key)

	// Create directory structure
	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		return "", fmt.Errorf("failed to create directory: %w", err)
	}

	// Create and write file
	file, err := os.Create(fullPath)
	if err != nil {
		return "", fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	_, err = io.Copy(file, content)
	if err != nil {
		os.Remove(fullPath) // Cleanup on error
		return "", fmt.Errorf("failed to write file: %w", err)
	}

	return key, nil
}

func (ls *LocalStorage) Retrieve(ctx context.Context, key string) (io.ReadCloser, error) {
	fullPath := filepath.Join(ls.basePath, key)

	// Security check: ensure path is within base directory
	absBasePath, err := filepath.Abs(ls.basePath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve base path: %w", err)
	}

	absFullPath, err := filepath.Abs(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve file path: %w", err)
	}

	if !strings.HasPrefix(absFullPath, absBasePath) {
		return nil, fmt.Errorf("invalid file path: path traversal detected")
	}

	file, err := os.Open(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("file not found")
		}
		return nil, fmt.Errorf("failed to open file: %w", err)
	}

	return file, nil
}

func (ls *LocalStorage) Delete(ctx context.Context, key string) error {
	fullPath := filepath.Join(ls.basePath, key)

	// Security check
	absBasePath, err := filepath.Abs(ls.basePath)
	if err != nil {
		return fmt.Errorf("failed to resolve base path: %w", err)
	}

	absFullPath, err := filepath.Abs(fullPath)
	if err != nil {
		return fmt.Errorf("failed to resolve file path: %w", err)
	}

	if !strings.HasPrefix(absFullPath, absBasePath) {
		return fmt.Errorf("invalid file path: path traversal detected")
	}

	err = os.Remove(fullPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete file: %w", err)
	}

	return nil
}

func (ls *LocalStorage) GetURL(ctx context.Context, key string, expiration time.Duration) (string, error) {
	// For local storage, return a path that the web server can serve
	// This will be handled by a file server route
	return fmt.Sprintf("/files/%s", key), nil
}

func (ls *LocalStorage) Exists(ctx context.Context, key string) (bool, error) {
	fullPath := filepath.Join(ls.basePath, key)

	// Security check
	absBasePath, err := filepath.Abs(ls.basePath)
	if err != nil {
		return false, fmt.Errorf("failed to resolve base path: %w", err)
	}

	absFullPath, err := filepath.Abs(fullPath)
	if err != nil {
		return false, fmt.Errorf("failed to resolve file path: %w", err)
	}

	if !strings.HasPrefix(absFullPath, absBasePath) {
		return false, fmt.Errorf("invalid file path: path traversal detected")
	}

	_, err = os.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (ls *LocalStorage) GetMetadata(ctx context.Context, key string) (FileMetadata, error) {
	fullPath := filepath.Join(ls.basePath, key)

	// Security check
	absBasePath, err := filepath.Abs(ls.basePath)
	if err != nil {
		return FileMetadata{}, fmt.Errorf("failed to resolve base path: %w", err)
	}

	absFullPath, err := filepath.Abs(fullPath)
	if err != nil {
		return FileMetadata{}, fmt.Errorf("failed to resolve file path: %w", err)
	}

	if !strings.HasPrefix(absFullPath, absBasePath) {
		return FileMetadata{}, fmt.Errorf("invalid file path: path traversal detected")
	}

	stat, err := os.Stat(fullPath)
	if err != nil {
		return FileMetadata{}, fmt.Errorf("failed to get file stats: %w", err)
	}

	return FileMetadata{
		Size:         stat.Size(),
		ContentType:  "application/octet-stream", // Could be enhanced with mime detection
		LastModified: stat.ModTime(),
		ETag:         fmt.Sprintf("%d-%d", stat.Size(), stat.ModTime().Unix()),
	}, nil
}

func sanitizeFilename(filename string) string {
	// Remove path separators and other dangerous characters
	filename = strings.ReplaceAll(filename, "/", "_")
	filename = strings.ReplaceAll(filename, "\\", "_")
	filename = strings.ReplaceAll(filename, "..", "_")
	filename = strings.ReplaceAll(filename, ":", "_")
	filename = strings.ReplaceAll(filename, "*", "_")
	filename = strings.ReplaceAll(filename, "?", "_")
	filename = strings.ReplaceAll(filename, "\"", "_")
	filename = strings.ReplaceAll(filename, "<", "_")
	filename = strings.ReplaceAll(filename, ">", "_")
	filename = strings.ReplaceAll(filename, "|", "_")
	return filename
}
