package openfga

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/openfga/go-sdk/client"
)

// Permission represents an OpenFGA permission check
type Permission struct {
	Object   string `json:"object"`   // e.g., "doc:document-id"
	Relation string `json:"relation"` // e.g., "can_read"
	User     string `json:"user"`     // e.g., "user:user-id"
}

// Tuple represents an OpenFGA relationship tuple
type Tuple struct {
	Object   string `json:"object"`   // e.g., "doc:document-id"
	Relation string `json:"relation"` // e.g., "owner"
	User     string `json:"user"`     // e.g., "user:user-id"
}

// AuthorizationService provides high-level authorization methods for AskFrank
type AuthorizationService struct {
	client *Client
}

// NewAuthorizationService creates a new authorization service
func NewAuthorizationService(client *Client) AuthorizationService {
	return AuthorizationService{
		client: client,
	}
}

func (s *AuthorizationService) ListObjectIds(ctx context.Context, perm Permission, pageSize int32) ([]uuid.UUID, error) {
	// options := client.ClientReadOptions{
	// 	PageSize:          &pageSize,
	// 	ContinuationToken: continuationToken,
	// }

	res, err := s.client.fga.ListObjects(ctx).Body(client.ClientListObjectsRequest{
		User:     perm.User,
		Relation: perm.Relation,
		Type:     perm.Object,
		Context:  &map[string]any{"ViewCount": 100},
	}).Execute()
	if err != nil {
		return nil, err
	}

	ids := make([]uuid.UUID, 0)
	for _, object := range res.Objects {
		parts := strings.Split(object, ":")
		if len(parts) == 2 {
			id, err := uuid.Parse(parts[1])
			if err == nil {
				ids = append(ids, id)
			}
		}
	}

	// res, err := s.client.fga.Read(ctx).Body(client.ClientReadRequest{
	// 	User:     &perm.User,
	// 	Relation: openfga.PtrString("reader"),
	// 	Object:   openfga.PtrString("file:"),
	// }).Execute()

	// if err != nil {
	// 	return nil, err
	// }

	// slog.Info("ListObjectIds", "res", len(res.GetTuples()))

	// ids := make([]uuid.UUID, 0)
	// for _, tuple := range res.Tuples {
	// 	parts := strings.Split(tuple.Key.Object, ":")
	// 	if len(parts) == 2 {
	// 		id, err := uuid.Parse(parts[1])
	// 		if err == nil {
	// 			ids = append(ids, id)
	// 		}
	// 	}
	// }

	return ids, nil
}

// Check verifies if a user has permission to perform an action on a resource
func (s *AuthorizationService) Check(ctx context.Context, perm Permission) (bool, error) {
	// Parse the user and object to extract IDs
	// Expected format: "user:id", "doc:id", "folder:id", etc.
	userParts := strings.Split(perm.User, ":")
	objectParts := strings.Split(perm.Object, ":")

	if len(userParts) != 2 || len(objectParts) != 2 {
		return false, fmt.Errorf("invalid user or object format: user=%s, object=%s", perm.User, perm.Object)
	}

	userType := userParts[0]
	userID := userParts[1]
	objectType := objectParts[0]
	objectID := objectParts[1]

	return s.client.CheckPermission(ctx, userType, userID, perm.Relation, objectType, objectID)
}

// WriteTuple creates a relationship tuple in OpenFGA
func (s *AuthorizationService) WriteTuple(ctx context.Context, tuple Tuple) error {
	// Parse the user and object to extract IDs
	// Expected format: "user:id", "doc:id", "folder:id", etc.
	userParts := strings.Split(tuple.User, ":")
	objectParts := strings.Split(tuple.Object, ":")

	if len(userParts) != 2 || len(objectParts) != 2 {
		return fmt.Errorf("invalid user or object format: user=%s, object=%s", tuple.User, tuple.Object)
	}

	userID := userParts[1]
	objectType := objectParts[0]
	objectID := objectParts[1]

	return s.client.WriteTuple(ctx, userID, tuple.Relation, objectType, objectID)
}

// DeleteTuple removes a relationship tuple from OpenFGA
func (s *AuthorizationService) DeleteTuple(ctx context.Context, tuple Tuple) error {
	// Parse the user and object to extract IDs
	// Expected format: "user:id", "doc:id", "folder:id", etc.
	userParts := strings.Split(tuple.User, ":")
	objectParts := strings.Split(tuple.Object, ":")

	if len(userParts) != 2 || len(objectParts) != 2 {
		return fmt.Errorf("invalid user or object format: user=%s, object=%s", tuple.User, tuple.Object)
	}

	userType := userParts[0]
	userID := userParts[1]
	objectType := objectParts[0]
	objectID := objectParts[1]

	return s.client.DeleteTuple(ctx, userType, userID, tuple.Relation, objectType, objectID)
}

func (s *AuthorizationService) AddGroupMember(ctx context.Context, groupID, userID uuid.UUID) error {
	return s.WriteTuple(ctx, Tuple{
		User:     fmt.Sprintf("user:%s", userID.String()),
		Relation: "member",
		Object:   fmt.Sprintf("group:%s", groupID.String()),
	})
}

func (s *AuthorizationService) RemoveGroupMember(ctx context.Context, groupID, userID uuid.UUID) error {
	return s.DeleteTuple(ctx, Tuple{
		User:     fmt.Sprintf("user:%s", userID.String()),
		Relation: "member",
		Object:   fmt.Sprintf("group:%s", groupID.String()),
	})
}

func (s *AuthorizationService) ListCanReadFiles(ctx context.Context, userID uuid.UUID) ([]uuid.UUID, error) {
	return s.ListObjectIds(ctx, Permission{
		User:     fmt.Sprintf("user:%s", userID.String()),
		Relation: "can_read",
		Object:   "file",
	}, 100)
}

func (s *AuthorizationService) CanReadFile(ctx context.Context, userID, fileID uuid.UUID) (bool, error) {
	return s.Check(ctx, Permission{
		User:     fmt.Sprintf("user:%s", userID.String()),
		Relation: "can_read",
		Object:   fmt.Sprintf("file:%s", fileID.String()),
	})
}

func (s *AuthorizationService) CanWriteFile(ctx context.Context, userID, fileID uuid.UUID) (bool, error) {
	return s.Check(ctx, Permission{
		User:     fmt.Sprintf("user:%s", userID.String()),
		Relation: "can_write",
		Object:   fmt.Sprintf("file:%s", fileID.String()),
	})
}

func (s *AuthorizationService) AddFileReader(ctx context.Context, userID, fileID uuid.UUID) error {
	return s.WriteTuple(ctx, Tuple{
		User:     fmt.Sprintf("user:%s", userID.String()),
		Relation: "reader",
		Object:   fmt.Sprintf("file:%s", fileID.String()),
	})
}

func (s *AuthorizationService) AddFileWriter(ctx context.Context, userID, fileID uuid.UUID) error {
	return s.WriteTuple(ctx, Tuple{
		User:     fmt.Sprintf("user:%s", userID.String()),
		Relation: "writer",
		Object:   fmt.Sprintf("file:%s", fileID.String()),
	})
}

func (s *AuthorizationService) AddFileParent(ctx context.Context, parentFileID, childFileID uuid.UUID) error {
	return s.WriteTuple(ctx, Tuple{
		User:     fmt.Sprintf("file:%s", parentFileID.String()),
		Relation: "parent",
		Object:   fmt.Sprintf("file:%s", childFileID.String()),
	})
}

func (s *AuthorizationService) RemoveFileReader(ctx context.Context, userID, fileID uuid.UUID) error {
	return s.DeleteTuple(ctx, Tuple{
		User:     fmt.Sprintf("user:%s", userID.String()),
		Relation: "reader",
		Object:   fmt.Sprintf("file:%s", fileID.String()),
	})
}

func (s *AuthorizationService) RemoveFileWriter(ctx context.Context, userID, fileID uuid.UUID) error {
	return s.DeleteTuple(ctx, Tuple{
		User:     fmt.Sprintf("user:%s", userID.String()),
		Relation: "writer",
		Object:   fmt.Sprintf("file:%s", fileID.String()),
	})
}

func (s *AuthorizationService) RemoveFileParent(ctx context.Context, userID, fileID uuid.UUID) error {
	return s.DeleteTuple(ctx, Tuple{
		User:     fmt.Sprintf("user:%s", userID.String()),
		Relation: "parent",
		Object:   fmt.Sprintf("file:%s", fileID.String()),
	})
}
