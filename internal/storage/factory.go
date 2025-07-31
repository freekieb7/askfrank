package storage

import (
	"fmt"
	"os"
)

type Factory struct {
	config StorageConfig
}

func NewFactory(config StorageConfig) *Factory {
	return &Factory{
		config: config,
	}
}

func (f *Factory) CreateStorage() (Storage, error) {
	switch f.config.Type {
	case StorageTypeLocal:
		basePath := f.config.LocalPath
		if basePath == "" {
			basePath = "./uploads" // Default path
		}
		return NewLocalStorage(basePath)

	case StorageTypeS3:
		if f.config.S3 == nil {
			return nil, fmt.Errorf("S3 configuration is required for S3 storage type")
		}
		return NewS3Storage(*f.config.S3)

	default:
		return nil, fmt.Errorf("unknown storage type: %s", f.config.Type)
	}
}

// NewStorageFromEnv creates a storage instance based on environment variables
func NewStorageFromEnv() (Storage, error) {
	storageType := os.Getenv("STORAGE_TYPE")
	if storageType == "" {
		storageType = "local" // Default to local storage
	}

	config := StorageConfig{
		Type: StorageType(storageType),
	}

	switch StorageType(storageType) {
	case StorageTypeLocal:
		config.LocalPath = os.Getenv("STORAGE_LOCAL_PATH")
		if config.LocalPath == "" {
			config.LocalPath = "./uploads"
		}

	case StorageTypeS3:
		bucket := os.Getenv("STORAGE_S3_BUCKET")
		region := os.Getenv("STORAGE_S3_REGION")

		if bucket == "" || region == "" {
			return nil, fmt.Errorf("S3 storage requires STORAGE_S3_BUCKET and STORAGE_S3_REGION environment variables")
		}

		config.S3 = &S3Config{
			Bucket: bucket,
			Region: region,
		}

	default:
		return nil, fmt.Errorf("unsupported storage type: %s", storageType)
	}

	factory := NewFactory(config)
	return factory.CreateStorage()
}
