package service

import (
	"context"
	"fmt"
	"log/slog"

	"askfrank/internal/config"
	"askfrank/internal/openfga"

	"github.com/google/uuid"
)

// AuthorizationService provides fine-grained access control using OpenFGA
type AuthorizationService struct {
	client *openfga.Client
	config config.OpenFGAConfig
	logger *slog.Logger
}

// NewAuthorizationService creates a new authorization service instance
func NewAuthorizationService(cfg config.Config, logger *slog.Logger) (*AuthorizationService, error) {
	if !cfg.OpenFGA.Enabled {
		logger.Info("OpenFGA is disabled, authorization service will operate in pass-through mode")
		return &AuthorizationService{
			client: nil,
			config: cfg.OpenFGA,
			logger: logger.With("component", "authorization"),
		}, nil
	}

	client, err := openfga.NewClient(cfg.OpenFGA)
	if err != nil {
		return nil, fmt.Errorf("failed to create OpenFGA client: %w", err)
	}

	return &AuthorizationService{
		client: client,
		config: cfg.OpenFGA,
		logger: logger.With("component", "authorization"),
	}, nil
}

// Document Authorization Methods

// CanReadDocument checks if a user can read a specific document
func (s *AuthorizationService) CanReadDocument(ctx context.Context, userID, documentID uuid.UUID) (bool, error) {
	if !s.config.Enabled {
		return true, nil // Pass-through mode when disabled
	}

	// Check multiple possible relationships that grant read access
	relationships := []string{"owner", "editor", "viewer"}

	for _, relation := range relationships {
		allowed, err := s.client.CheckPermission(ctx, userID.String(), relation, "document", documentID.String())
		if err != nil {
			s.logger.Error("error checking document read permission",
				"userID", userID,
				"documentID", documentID,
				"relation", relation,
				"error", err)
			continue
		}
		if allowed {
			return true, nil
		}
	}

	// Check if user has access through group membership
	return s.checkGroupDocumentAccess(ctx, userID, documentID, "viewer")
}

// CanWriteDocument checks if a user can modify a specific document
func (s *AuthorizationService) CanWriteDocument(ctx context.Context, userID, documentID uuid.UUID) (bool, error) {
	if !s.config.Enabled {
		return true, nil // Pass-through mode when disabled
	}

	// Check owner and editor relationships
	relationships := []string{"owner", "editor"}

	for _, relation := range relationships {
		allowed, err := s.client.CheckPermission(ctx, userID.String(), relation, "document", documentID.String())
		if err != nil {
			s.logger.Error("error checking document write permission",
				"userID", userID,
				"documentID", documentID,
				"relation", relation,
				"error", err)
			continue
		}
		if allowed {
			return true, nil
		}
	}

	// Check if user has write access through group membership
	return s.checkGroupDocumentAccess(ctx, userID, documentID, "editor")
}

// CanDeleteDocument checks if a user can delete a specific document
func (s *AuthorizationService) CanDeleteDocument(ctx context.Context, userID, documentID uuid.UUID) (bool, error) {
	if !s.config.Enabled {
		return true, nil // Pass-through mode when disabled
	}

	// Only owners can delete documents
	return s.client.CheckPermission(ctx, userID.String(), "owner", "document", documentID.String())
}

// SetDocumentOwner establishes ownership relationship for a document
func (s *AuthorizationService) SetDocumentOwner(ctx context.Context, userID, documentID uuid.UUID) error {
	if !s.config.Enabled {
		return nil // Pass-through mode when disabled
	}

	return s.client.WriteTuple(ctx, userID.String(), "owner", "document", documentID.String())
}

// GrantDocumentAccess grants specific access to a document
func (s *AuthorizationService) GrantDocumentAccess(ctx context.Context, userID, documentID uuid.UUID, relation string) error {
	if !s.config.Enabled {
		return nil // Pass-through mode when disabled
	}

	validRelations := map[string]bool{
		"owner":  true,
		"editor": true,
		"viewer": true,
	}

	if !validRelations[relation] {
		return fmt.Errorf("invalid relation: %s", relation)
	}

	return s.client.WriteTuple(ctx, userID.String(), relation, "document", documentID.String())
}

// RevokeDocumentAccess removes specific access from a document
func (s *AuthorizationService) RevokeDocumentAccess(ctx context.Context, userID, documentID uuid.UUID, relation string) error {
	if !s.config.Enabled {
		return nil // Pass-through mode when disabled
	}

	return s.client.DeleteTuple(ctx, userID.String(), relation, "document", documentID.String())
}

// Folder Authorization Methods

// CanReadFolder checks if a user can read a specific folder
func (s *AuthorizationService) CanReadFolder(ctx context.Context, userID, folderID uuid.UUID) (bool, error) {
	if !s.config.Enabled {
		return true, nil // Pass-through mode when disabled
	}

	relationships := []string{"owner", "editor", "viewer"}

	for _, relation := range relationships {
		allowed, err := s.client.CheckPermission(ctx, userID.String(), relation, "folder", folderID.String())
		if err != nil {
			s.logger.Error("error checking folder read permission",
				"userID", userID,
				"folderID", folderID,
				"relation", relation,
				"error", err)
			continue
		}
		if allowed {
			return true, nil
		}
	}

	return s.checkGroupFolderAccess(ctx, userID, folderID, "viewer")
}

// CanWriteFolder checks if a user can modify a specific folder
func (s *AuthorizationService) CanWriteFolder(ctx context.Context, userID, folderID uuid.UUID) (bool, error) {
	if !s.config.Enabled {
		return true, nil // Pass-through mode when disabled
	}

	relationships := []string{"owner", "editor"}

	for _, relation := range relationships {
		allowed, err := s.client.CheckPermission(ctx, userID.String(), relation, "folder", folderID.String())
		if err != nil {
			s.logger.Error("error checking folder write permission",
				"userID", userID,
				"folderID", folderID,
				"relation", relation,
				"error", err)
			continue
		}
		if allowed {
			return true, nil
		}
	}

	return s.checkGroupFolderAccess(ctx, userID, folderID, "editor")
}

// SetFolderOwner establishes ownership relationship for a folder
func (s *AuthorizationService) SetFolderOwner(ctx context.Context, userID, folderID uuid.UUID) error {
	if !s.config.Enabled {
		return nil // Pass-through mode when disabled
	}

	return s.client.WriteTuple(ctx, userID.String(), "owner", "folder", folderID.String())
}

// Group Management Methods

// AddUserToGroup adds a user to a group with a specific role
func (s *AuthorizationService) AddUserToGroup(ctx context.Context, userID, groupID uuid.UUID, role string) error {
	if !s.config.Enabled {
		return nil // Pass-through mode when disabled
	}

	validRoles := map[string]bool{
		"admin":  true,
		"member": true,
	}

	if !validRoles[role] {
		return fmt.Errorf("invalid group role: %s", role)
	}

	return s.client.WriteTuple(ctx, userID.String(), role, "group", groupID.String())
}

// RemoveUserFromGroup removes a user from a group
func (s *AuthorizationService) RemoveUserFromGroup(ctx context.Context, userID, groupID uuid.UUID, role string) error {
	if !s.config.Enabled {
		return nil // Pass-through mode when disabled
	}

	return s.client.DeleteTuple(ctx, userID.String(), role, "group", groupID.String())
}

// IsGroupAdmin checks if a user is an admin of a group
func (s *AuthorizationService) IsGroupAdmin(ctx context.Context, userID, groupID uuid.UUID) (bool, error) {
	if !s.config.Enabled {
		return true, nil // Pass-through mode when disabled
	}

	return s.client.CheckPermission(ctx, userID.String(), "admin", "group", groupID.String())
}

// IsGroupMember checks if a user is a member of a group
func (s *AuthorizationService) IsGroupMember(ctx context.Context, userID, groupID uuid.UUID) (bool, error) {
	if !s.config.Enabled {
		return true, nil // Pass-through mode when disabled
	}

	// Check both admin and member roles
	isAdmin, err := s.client.CheckPermission(ctx, userID.String(), "admin", "group", groupID.String())
	if err != nil {
		s.logger.Error("error checking group admin permission",
			"userID", userID,
			"groupID", groupID,
			"error", err)
	}
	if isAdmin {
		return true, nil
	}

	return s.client.CheckPermission(ctx, userID.String(), "member", "group", groupID.String())
}

// Helper methods for group-based access

// checkGroupDocumentAccess checks if user has document access through group membership
func (s *AuthorizationService) checkGroupDocumentAccess(ctx context.Context, userID, documentID uuid.UUID, minRelation string) (bool, error) {
	// This would require listing all groups the user belongs to and checking each group's permissions
	// For now, return false as this requires additional implementation
	// In a full implementation, you would:
	// 1. Get all groups where user is admin/member
	// 2. Check if any group has the required relation to the document
	// 3. Return true if any group grants access

	s.logger.Debug("group-based document access check not fully implemented",
		"userID", userID,
		"documentID", documentID,
		"minRelation", minRelation)

	return false, nil
}

// checkGroupFolderAccess checks if user has folder access through group membership
func (s *AuthorizationService) checkGroupFolderAccess(ctx context.Context, userID, folderID uuid.UUID, minRelation string) (bool, error) {
	// Similar to checkGroupDocumentAccess, this requires additional implementation
	// for querying group memberships and group permissions

	s.logger.Debug("group-based folder access check not fully implemented",
		"userID", userID,
		"folderID", folderID,
		"minRelation", minRelation)

	return false, nil
}

// Health check method
func (s *AuthorizationService) HealthCheck(ctx context.Context) error {
	if !s.config.Enabled {
		return nil // Always healthy when disabled
	}

	if s.client == nil {
		return fmt.Errorf("OpenFGA client is nil")
	}

	// Perform a simple check to verify the service is responding
	// This is a placeholder - actual implementation would depend on OpenFGA client capabilities
	s.logger.Debug("authorization service health check passed")
	return nil
}
