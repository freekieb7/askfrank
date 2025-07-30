package integration

import (
	"context"
	"testing"

	"askfrank/internal/config"
	"askfrank/internal/openfga"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthorizationIntegration(t *testing.T) {
	t.Run("OpenFGA Disabled Mode", func(t *testing.T) {
		cfg := config.OpenFGAConfig{
			Enabled: false,
		}

		client, err := openfga.NewClient(cfg)
		require.NoError(t, err)
		defer client.Close()

		ctx := context.Background()
		userID := uuid.New()
		documentID := uuid.New()

		// When OpenFGA is disabled, all permission checks should pass
		canRead, err := client.CheckPermission(ctx, userID.String(), "viewer", "document", documentID.String())
		require.NoError(t, err)
		assert.True(t, canRead, "Should allow read access when OpenFGA is disabled")

		// Write operations should also pass silently
		err = client.WriteTuple(ctx, userID.String(), "owner", "document", documentID.String())
		require.NoError(t, err, "Should allow write operations when OpenFGA is disabled")

		// Delete operations should also pass silently
		err = client.DeleteTuple(ctx, userID.String(), "owner", "document", documentID.String())
		require.NoError(t, err, "Should allow delete operations when OpenFGA is disabled")
	})

	t.Run("Authorization Service Integration", func(t *testing.T) {
		cfg := config.OpenFGAConfig{
			Enabled: false, // Use pass-through mode for testing
		}

		client, err := openfga.NewClient(cfg)
		require.NoError(t, err)
		defer client.Close()

		authService := openfga.NewAuthorizationService(client)

		ctx := context.Background()
		userID := uuid.New()
		documentID := uuid.New()
		folderID := uuid.New()
		groupID := uuid.New()

		// Test document permissions
		canRead, err := authService.CanReadDocument(ctx, userID, documentID)
		require.NoError(t, err)
		assert.True(t, canRead, "Should allow document read in pass-through mode")

		canWrite, err := authService.CanWriteDocument(ctx, userID, documentID)
		require.NoError(t, err)
		assert.True(t, canWrite, "Should allow document write in pass-through mode")

		canShare, err := authService.CanShareDocument(ctx, userID, documentID)
		require.NoError(t, err)
		assert.True(t, canShare, "Should allow document share in pass-through mode")

		canChangeOwner, err := authService.CanChangeDocumentOwner(ctx, userID, documentID)
		require.NoError(t, err)
		assert.True(t, canChangeOwner, "Should allow document owner change in pass-through mode")

		// Test setting document ownership
		err = authService.SetDocumentOwner(ctx, userID, documentID)
		require.NoError(t, err, "Should allow setting document owner in pass-through mode")

		// Test folder permissions
		canViewFolder, err := authService.CanViewFolder(ctx, userID, folderID)
		require.NoError(t, err)
		assert.True(t, canViewFolder, "Should allow folder view in pass-through mode")

		canCreateFile, err := authService.CanCreateFileInFolder(ctx, userID, folderID)
		require.NoError(t, err)
		assert.True(t, canCreateFile, "Should allow file creation in folder in pass-through mode")

		// Test setting folder ownership
		err = authService.SetFolderOwner(ctx, userID, folderID)
		require.NoError(t, err, "Should allow setting folder owner in pass-through mode")

		// Test document-folder relationships
		err = authService.SetDocumentParent(ctx, documentID, folderID)
		require.NoError(t, err, "Should allow setting document parent in pass-through mode")

		// Test adding/removing viewers
		err = authService.AddDocumentViewer(ctx, userID, documentID)
		require.NoError(t, err, "Should allow adding document viewer in pass-through mode")

		err = authService.RemoveDocumentViewer(ctx, userID, documentID)
		require.NoError(t, err, "Should allow removing document viewer in pass-through mode")

		err = authService.AddFolderViewer(ctx, userID, folderID)
		require.NoError(t, err, "Should allow adding folder viewer in pass-through mode")

		err = authService.RemoveFolderViewer(ctx, userID, folderID)
		require.NoError(t, err, "Should allow removing folder viewer in pass-through mode")

		// Test group management
		err = authService.AddUserToGroup(ctx, userID, groupID)
		require.NoError(t, err, "Should allow adding user to group in pass-through mode")

		err = authService.RemoveUserFromGroup(ctx, userID, groupID)
		require.NoError(t, err, "Should allow removing user from group in pass-through mode")

		// Test group-based permissions
		err = authService.AddGroupViewerToDocument(ctx, groupID, documentID)
		require.NoError(t, err, "Should allow adding group viewer to document in pass-through mode")

		err = authService.AddGroupViewerToFolder(ctx, groupID, folderID)
		require.NoError(t, err, "Should allow adding group viewer to folder in pass-through mode")
	})

	t.Run("Configuration Validation", func(t *testing.T) {
		// Test that client creation fails with invalid configuration
		invalidCfg := config.OpenFGAConfig{
			Enabled: true,
			StoreID: "", // Missing required field
		}

		_, err := openfga.NewClient(invalidCfg)
		require.Error(t, err, "Should fail with invalid configuration")
		// The actual error message may vary depending on OpenFGA client validation
		assert.Contains(t, err.Error(), "failed to create OpenFGA client")
	})

	t.Run("Permission and Tuple Operations", func(t *testing.T) {
		cfg := config.OpenFGAConfig{
			Enabled: false, // Use pass-through mode for testing
		}

		client, err := openfga.NewClient(cfg)
		require.NoError(t, err)
		defer client.Close()

		authService := openfga.NewAuthorizationService(client)

		ctx := context.Background()
		userID := uuid.New()
		documentID := uuid.New()

		// Test Permission struct
		perm := openfga.Permission{
			User:     "user:" + userID.String(),
			Relation: "can_read",
			Object:   "doc:" + documentID.String(),
		}

		allowed, err := authService.Check(ctx, perm)
		require.NoError(t, err)
		assert.True(t, allowed, "Should allow permission check in pass-through mode")

		// Test Tuple struct
		tuple := openfga.Tuple{
			User:     "user:" + userID.String(),
			Relation: "owner",
			Object:   "doc:" + documentID.String(),
		}

		err = authService.WriteTuple(ctx, tuple)
		require.NoError(t, err, "Should allow writing tuple in pass-through mode")

		err = authService.DeleteTuple(ctx, tuple)
		require.NoError(t, err, "Should allow deleting tuple in pass-through mode")
	})
}

func TestAuthorizationServiceCreation(t *testing.T) {
	t.Run("Create Authorization Service", func(t *testing.T) {
		cfg := config.OpenFGAConfig{
			Enabled: false,
		}

		client, err := openfga.NewClient(cfg)
		require.NoError(t, err)
		defer client.Close()

		authService := openfga.NewAuthorizationService(client)
		require.NotNil(t, authService, "Authorization service should be created successfully")

		// Test IsEnabled method
		assert.False(t, client.IsEnabled(), "Client should report disabled state")
	})

	t.Run("Client Enabled Check", func(t *testing.T) {
		// Test enabled configuration (would fail in real environment without valid OpenFGA server)
		enabledCfg := config.OpenFGAConfig{
			Enabled:  true,
			APIHost:  "localhost:8080",
			StoreID:  "01J3XXXXXXXXXXXXXXXXXXXXXX", // Valid ULID format
			ModelID:  "01J3XXXXXXXXXXXXXXXXXXXXXX", // Valid ULID format
			APIToken: "test-token",
		}

		// This will fail due to connection verification or invalid configuration
		_, err := openfga.NewClient(enabledCfg)
		require.Error(t, err, "Should fail connecting to non-existent OpenFGA server or due to invalid config")
		// The error could be due to connection failure or configuration validation
		assert.True(t,
			len(err.Error()) > 0,
			"Should have a meaningful error message")
	})
}
