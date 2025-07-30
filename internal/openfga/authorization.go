package openfga

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"
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
func NewAuthorizationService(client *Client) *AuthorizationService {
	return &AuthorizationService{
		client: client,
	}
}

// Check verifies if a user has permission to perform an action on a resource
func (s *AuthorizationService) Check(ctx context.Context, perm Permission) (bool, error) {
	if !s.client.IsEnabled() {
		// When OpenFGA is disabled, allow all operations for development/testing
		slog.Debug("OpenFGA disabled, allowing operation",
			"user", perm.User, "relation", perm.Relation, "object", perm.Object)
		return true, nil
	}

	// Parse the user and object to extract IDs
	// Expected format: "user:id", "doc:id", "folder:id", etc.
	userParts := strings.Split(perm.User, ":")
	objectParts := strings.Split(perm.Object, ":")

	if len(userParts) != 2 || len(objectParts) != 2 {
		return false, fmt.Errorf("invalid user or object format: user=%s, object=%s", perm.User, perm.Object)
	}

	userID := userParts[1]
	objectType := objectParts[0]
	objectID := objectParts[1]

	return s.client.CheckPermission(ctx, userID, perm.Relation, objectType, objectID)
}

// WriteTuple creates a relationship tuple in OpenFGA
func (s *AuthorizationService) WriteTuple(ctx context.Context, tuple Tuple) error {
	if !s.client.IsEnabled() {
		slog.Debug("OpenFGA disabled, skipping tuple write",
			"user", tuple.User, "relation", tuple.Relation, "object", tuple.Object)
		return nil
	}

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
	if !s.client.IsEnabled() {
		slog.Debug("OpenFGA disabled, skipping tuple deletion",
			"user", tuple.User, "relation", tuple.Relation, "object", tuple.Object)
		return nil
	}

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

	return s.client.DeleteTuple(ctx, userID, tuple.Relation, objectType, objectID)
}

// AskFrank-specific authorization methods following the schema

// CanReadDocument checks if user can read a document
func (s *AuthorizationService) CanReadDocument(ctx context.Context, userID, documentID uuid.UUID) (bool, error) {
	return s.Check(ctx, Permission{
		User:     fmt.Sprintf("user:%s", userID.String()),
		Relation: "can_read",
		Object:   fmt.Sprintf("doc:%s", documentID.String()),
	})
}

// CanWriteDocument checks if user can write to a document
func (s *AuthorizationService) CanWriteDocument(ctx context.Context, userID, documentID uuid.UUID) (bool, error) {
	return s.Check(ctx, Permission{
		User:     fmt.Sprintf("user:%s", userID.String()),
		Relation: "can_write",
		Object:   fmt.Sprintf("doc:%s", documentID.String()),
	})
}

// CanShareDocument checks if user can share a document
func (s *AuthorizationService) CanShareDocument(ctx context.Context, userID, documentID uuid.UUID) (bool, error) {
	return s.Check(ctx, Permission{
		User:     fmt.Sprintf("user:%s", userID.String()),
		Relation: "can_share",
		Object:   fmt.Sprintf("doc:%s", documentID.String()),
	})
}

// CanChangeDocumentOwner checks if user can change document ownership
func (s *AuthorizationService) CanChangeDocumentOwner(ctx context.Context, userID, documentID uuid.UUID) (bool, error) {
	return s.Check(ctx, Permission{
		User:     fmt.Sprintf("user:%s", userID.String()),
		Relation: "can_change_owner",
		Object:   fmt.Sprintf("doc:%s", documentID.String()),
	})
}

// CanViewFolder checks if user can view a folder
func (s *AuthorizationService) CanViewFolder(ctx context.Context, userID, folderID uuid.UUID) (bool, error) {
	return s.Check(ctx, Permission{
		User:     fmt.Sprintf("user:%s", userID.String()),
		Relation: "viewer",
		Object:   fmt.Sprintf("folder:%s", folderID.String()),
	})
}

// CanCreateFileInFolder checks if user can create files in a folder
func (s *AuthorizationService) CanCreateFileInFolder(ctx context.Context, userID, folderID uuid.UUID) (bool, error) {
	return s.Check(ctx, Permission{
		User:     fmt.Sprintf("user:%s", userID.String()),
		Relation: "can_create_file",
		Object:   fmt.Sprintf("folder:%s", folderID.String()),
	})
}

// SetDocumentOwner sets the owner of a document
func (s *AuthorizationService) SetDocumentOwner(ctx context.Context, userID, documentID uuid.UUID) error {
	return s.WriteTuple(ctx, Tuple{
		User:     fmt.Sprintf("user:%s", userID.String()),
		Relation: "owner",
		Object:   fmt.Sprintf("doc:%s", documentID.String()),
	})
}

// SetFolderOwner sets the owner of a folder
func (s *AuthorizationService) SetFolderOwner(ctx context.Context, userID, folderID uuid.UUID) error {
	return s.WriteTuple(ctx, Tuple{
		User:     fmt.Sprintf("user:%s", userID.String()),
		Relation: "owner",
		Object:   fmt.Sprintf("folder:%s", folderID.String()),
	})
}

// SetDocumentParent sets the parent folder of a document
func (s *AuthorizationService) SetDocumentParent(ctx context.Context, documentID, folderID uuid.UUID) error {
	return s.WriteTuple(ctx, Tuple{
		User:     fmt.Sprintf("folder:%s", folderID.String()),
		Relation: "parent",
		Object:   fmt.Sprintf("doc:%s", documentID.String()),
	})
}

// SetFolderParent sets the parent folder of another folder
func (s *AuthorizationService) SetFolderParent(ctx context.Context, childFolderID, parentFolderID uuid.UUID) error {
	return s.WriteTuple(ctx, Tuple{
		User:     fmt.Sprintf("folder:%s", parentFolderID.String()),
		Relation: "parent",
		Object:   fmt.Sprintf("folder:%s", childFolderID.String()),
	})
}

// AddDocumentViewer adds a viewer to a document
func (s *AuthorizationService) AddDocumentViewer(ctx context.Context, userID, documentID uuid.UUID) error {
	return s.WriteTuple(ctx, Tuple{
		User:     fmt.Sprintf("user:%s", userID.String()),
		Relation: "viewer",
		Object:   fmt.Sprintf("doc:%s", documentID.String()),
	})
}

// AddFolderViewer adds a viewer to a folder
func (s *AuthorizationService) AddFolderViewer(ctx context.Context, userID, folderID uuid.UUID) error {
	return s.WriteTuple(ctx, Tuple{
		User:     fmt.Sprintf("user:%s", userID.String()),
		Relation: "viewer",
		Object:   fmt.Sprintf("folder:%s", folderID.String()),
	})
}

// RemoveDocumentViewer removes a viewer from a document
func (s *AuthorizationService) RemoveDocumentViewer(ctx context.Context, userID, documentID uuid.UUID) error {
	return s.DeleteTuple(ctx, Tuple{
		User:     fmt.Sprintf("user:%s", userID.String()),
		Relation: "viewer",
		Object:   fmt.Sprintf("doc:%s", documentID.String()),
	})
}

// RemoveFolderViewer removes a viewer from a folder
func (s *AuthorizationService) RemoveFolderViewer(ctx context.Context, userID, folderID uuid.UUID) error {
	return s.DeleteTuple(ctx, Tuple{
		User:     fmt.Sprintf("user:%s", userID.String()),
		Relation: "viewer",
		Object:   fmt.Sprintf("folder:%s", folderID.String()),
	})
}

// Group management methods

// AddUserToGroup adds a user to a group
func (s *AuthorizationService) AddUserToGroup(ctx context.Context, userID, groupID uuid.UUID) error {
	return s.WriteTuple(ctx, Tuple{
		User:     fmt.Sprintf("user:%s", userID.String()),
		Relation: "member",
		Object:   fmt.Sprintf("group:%s", groupID.String()),
	})
}

// RemoveUserFromGroup removes a user from a group
func (s *AuthorizationService) RemoveUserFromGroup(ctx context.Context, userID, groupID uuid.UUID) error {
	return s.DeleteTuple(ctx, Tuple{
		User:     fmt.Sprintf("user:%s", userID.String()),
		Relation: "member",
		Object:   fmt.Sprintf("group:%s", groupID.String()),
	})
}

// AddGroupViewerToDocument adds a group as viewer to a document
func (s *AuthorizationService) AddGroupViewerToDocument(ctx context.Context, groupID, documentID uuid.UUID) error {
	return s.WriteTuple(ctx, Tuple{
		User:     fmt.Sprintf("group:%s#member", groupID.String()),
		Relation: "viewer",
		Object:   fmt.Sprintf("doc:%s", documentID.String()),
	})
}

// AddGroupViewerToFolder adds a group as viewer to a folder
func (s *AuthorizationService) AddGroupViewerToFolder(ctx context.Context, groupID, folderID uuid.UUID) error {
	return s.WriteTuple(ctx, Tuple{
		User:     fmt.Sprintf("group:%s#member", groupID.String()),
		Relation: "viewer",
		Object:   fmt.Sprintf("folder:%s", folderID.String()),
	})
}
