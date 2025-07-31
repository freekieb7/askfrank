package storage

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
)

type S3Storage struct {
	client *s3.Client
	bucket string
	region string
}

func NewS3Storage(s3Config S3Config) (*S3Storage, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(s3Config.Region),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := s3.NewFromConfig(cfg)

	return &S3Storage{
		client: client,
		bucket: s3Config.Bucket,
		region: s3Config.Region,
	}, nil
}

func (s3s *S3Storage) Store(ctx context.Context, userID uuid.UUID, filename string, content io.Reader, contentType string) (string, error) {
	// Generate storage key: user_id/year/month/uuid_filename
	now := time.Now()
	key := fmt.Sprintf("%s/%d/%02d/%s_%s",
		userID.String(),
		now.Year(),
		now.Month(),
		uuid.New().String(),
		sanitizeFilename(filename),
	)

	_, err := s3s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(s3s.bucket),
		Key:         aws.String(key),
		Body:        content,
		ContentType: aws.String(contentType),
		Metadata: map[string]string{
			"user-id":           userID.String(),
			"original-filename": filename,
			"upload-time":       now.Format(time.RFC3339),
		},
	})
	if err != nil {
		return "", fmt.Errorf("failed to upload to S3: %w", err)
	}

	return key, nil
}

func (s3s *S3Storage) Retrieve(ctx context.Context, key string) (io.ReadCloser, error) {
	result, err := s3s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s3s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve from S3: %w", err)
	}

	return result.Body, nil
}

func (s3s *S3Storage) Delete(ctx context.Context, key string) error {
	_, err := s3s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s3s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("failed to delete from S3: %w", err)
	}

	return nil
}

func (s3s *S3Storage) GetURL(ctx context.Context, key string, expiration time.Duration) (string, error) {
	presignClient := s3.NewPresignClient(s3s.client)

	request, err := presignClient.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s3s.bucket),
		Key:    aws.String(key),
	}, func(opts *s3.PresignOptions) {
		opts.Expires = expiration
	})
	if err != nil {
		return "", fmt.Errorf("failed to create presigned URL: %w", err)
	}

	return request.URL, nil
}

func (s3s *S3Storage) Exists(ctx context.Context, key string) (bool, error) {
	_, err := s3s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s3s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		// Check if error is "not found"
		if strings.Contains(err.Error(), "NotFound") || strings.Contains(err.Error(), "404") {
			return false, nil
		}
		return false, fmt.Errorf("failed to check object existence: %w", err)
	}

	return true, nil
}

func (s3s *S3Storage) GetMetadata(ctx context.Context, key string) (FileMetadata, error) {
	result, err := s3s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s3s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return FileMetadata{}, fmt.Errorf("failed to get object metadata: %w", err)
	}

	contentType := "application/octet-stream"
	if result.ContentType != nil {
		contentType = *result.ContentType
	}

	size := int64(0)
	if result.ContentLength != nil {
		size = *result.ContentLength
	}

	lastModified := time.Now()
	if result.LastModified != nil {
		lastModified = *result.LastModified
	}

	etag := ""
	if result.ETag != nil {
		etag = *result.ETag
	}

	return FileMetadata{
		Size:         size,
		ContentType:  contentType,
		LastModified: lastModified,
		ETag:         etag,
	}, nil
}
