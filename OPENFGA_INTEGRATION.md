# OpenFGA Authorization Integration

This document describes the complete OpenFGA (Fine-Grained Authorization) integration added to AskFrank.

## Overview

OpenFGA has been integrated to provide fine-grained access control for documents, folders, users, and groups following the authorization schema model provided. The integration includes:

- **Client Layer**: OpenFGA SDK integration with AskFrank-specific configuration
- **Authorization Service**: High-level authorization methods for common operations
- **Configuration**: Environment-based configuration with pass-through mode for development
- **Testing**: Comprehensive integration tests with disabled mode support

## Components Added

### 1. Configuration (`internal/config/config.go`)

Added `OpenFGAConfig` struct with the following fields:
- `APIHost`: OpenFGA server host (default: "localhost:8080")
- `StoreID`: OpenFGA store identifier (required when enabled)
- `ModelID`: Authorization model identifier (optional)
- `APIToken`: API token for authentication (required when enabled)
- `Enabled`: Enable/disable OpenFGA (default: false)
- `Environment`: Environment name (default: "development")

Environment variables:
```bash
OPENFGA_API_HOST=localhost:8080
OPENFGA_STORE_ID=your-store-id
OPENFGA_MODEL_ID=your-model-id
OPENFGA_API_TOKEN=your-api-token
OPENFGA_ENABLED=false
OPENFGA_ENVIRONMENT=development
```

### 2. OpenFGA Client (`internal/openfga/client.go`)

Wraps the OpenFGA Go SDK with AskFrank-specific functionality:

- **Connection Management**: Automatic connection verification and error handling
- **Pass-through Mode**: When disabled, all operations succeed without contacting OpenFGA
- **Logging**: Structured logging for all authorization operations
- **Error Handling**: Comprehensive error handling with meaningful messages

Key methods:
- `NewClient(cfg config.OpenFGAConfig)`: Creates and verifies client connection
- `CheckPermission(ctx, userID, relation, objectType, objectID)`: Checks user permissions
- `WriteTuple(ctx, userID, relation, objectType, objectID)`: Creates relationships
- `DeleteTuple(ctx, userID, relation, objectType, objectID)`: Removes relationships
- `IsEnabled()`: Returns whether OpenFGA is enabled
- `Close()`: Cleans up client resources

### 3. Authorization Service (`internal/openfga/authorization.go`)

High-level authorization service implementing the provided schema model with methods for:

#### Document Operations
- `CanReadDocument(ctx, userID, documentID)`: Check read permissions
- `CanWriteDocument(ctx, userID, documentID)`: Check write permissions
- `CanShareDocument(ctx, userID, documentID)`: Check share permissions
- `CanChangeDocumentOwner(ctx, userID, documentID)`: Check ownership change permissions
- `SetDocumentOwner(ctx, userID, documentID)`: Set document ownership
- `SetDocumentParent(ctx, documentID, folderID)`: Set document parent folder
- `AddDocumentViewer(ctx, userID, documentID)`: Add viewer to document
- `RemoveDocumentViewer(ctx, userID, documentID)`: Remove viewer from document

#### Folder Operations
- `CanViewFolder(ctx, userID, folderID)`: Check folder view permissions
- `CanCreateFileInFolder(ctx, userID, folderID)`: Check file creation permissions
- `SetFolderOwner(ctx, userID, folderID)`: Set folder ownership
- `SetFolderParent(ctx, childFolderID, parentFolderID)`: Set folder hierarchy
- `AddFolderViewer(ctx, userID, folderID)`: Add viewer to folder
- `RemoveFolderViewer(ctx, userID, folderID)`: Remove viewer from folder

#### Group Management
- `AddUserToGroup(ctx, userID, groupID)`: Add user to group
- `RemoveUserFromGroup(ctx, userID, groupID)`: Remove user from group
- `AddGroupViewerToDocument(ctx, groupID, documentID)`: Grant group access to document
- `AddGroupViewerToFolder(ctx, groupID, folderID)`: Grant group access to folder

#### Low-level Operations
- `Check(ctx, Permission)`: Generic permission check
- `WriteTuple(ctx, Tuple)`: Generic tuple creation
- `DeleteTuple(ctx, Tuple)`: Generic tuple deletion

### 4. Data Structures

#### Permission
```go
type Permission struct {
    Object   string `json:"object"`   // e.g., "doc:document-id"
    Relation string `json:"relation"` // e.g., "can_read"
    User     string `json:"user"`     // e.g., "user:user-id"
}
```

#### Tuple
```go
type Tuple struct {
    Object   string `json:"object"`   // e.g., "doc:document-id"
    Relation string `json:"relation"` // e.g., "owner"
    User     string `json:"user"`     // e.g., "user:user-id"
}
```

## Authorization Schema Support

The implementation follows the provided OpenFGA authorization model with support for:

- **Users**: Individual user permissions and relationships
- **Groups**: Group-based permissions with member relationships
- **Documents**: File-level permissions (owner, editor, viewer)
- **Folders**: Folder-level permissions with hierarchical inheritance
- **Relationships**: Parent-child relationships between folders and documents

## Integration Testing

Comprehensive test suite (`tests/integration/authorization_integration_test.go`) covering:

- **Pass-through Mode**: All operations when OpenFGA is disabled
- **Client Operations**: Direct client method testing
- **Service Operations**: High-level authorization service testing
- **Configuration Validation**: Invalid configuration handling
- **Error Handling**: Proper error propagation and logging

## Usage Examples

### Basic Setup
```go
// Load configuration
cfg, err := config.Load()
if err != nil {
    log.Fatal("Failed to load config:", err)
}

// Create OpenFGA client
client, err := openfga.NewClient(cfg.OpenFGA)
if err != nil {
    log.Fatal("Failed to create OpenFGA client:", err)
}
defer client.Close()

// Create authorization service
authService := openfga.NewAuthorizationService(client)
```

### Document Permissions
```go
userID := uuid.New()
documentID := uuid.New()

// Check if user can read document
canRead, err := authService.CanReadDocument(ctx, userID, documentID)
if err != nil {
    log.Error("Permission check failed:", err)
    return
}

if canRead {
    // Allow document access
} else {
    // Deny access
}

// Set document ownership
err = authService.SetDocumentOwner(ctx, userID, documentID)
if err != nil {
    log.Error("Failed to set document owner:", err)
}
```

### Group Management
```go
userID := uuid.New()
groupID := uuid.New()
documentID := uuid.New()

// Add user to group
err := authService.AddUserToGroup(ctx, userID, groupID)
if err != nil {
    log.Error("Failed to add user to group:", err)
}

// Grant group access to document
err = authService.AddGroupViewerToDocument(ctx, groupID, documentID)
if err != nil {
    log.Error("Failed to grant group access:", err)
}
```

## Development vs Production

### Development Mode (OpenFGA Disabled)
- `OPENFGA_ENABLED=false` (default)
- All authorization checks return `true`
- No external dependencies required
- Full application functionality maintained
- Logging shows "pass-through" operations

### Production Mode (OpenFGA Enabled)
- `OPENFGA_ENABLED=true`
- Requires running OpenFGA server
- All authorization checks enforced
- Requires valid store ID and API token
- Connection verification on startup

## Dependencies Added

```go
require (
    github.com/openfga/go-sdk v0.6.2
    github.com/google/uuid v1.6.0
)
```

## Security Considerations

1. **API Token Security**: Store OpenFGA API tokens securely using environment variables
2. **Connection Verification**: Client verifies connection and model on startup
3. **Error Handling**: Comprehensive error handling prevents authorization bypass
4. **Logging**: All authorization operations are logged for audit purposes
5. **Pass-through Safety**: Disabled mode is safe for development but should not be used in production

## Performance Considerations

1. **Connection Pooling**: OpenFGA client manages connection pooling internally
2. **Async Operations**: All authorization calls are async and context-aware
3. **Caching**: Consider implementing application-level caching for frequently checked permissions
4. **Batch Operations**: For bulk operations, consider batching permission checks

## Monitoring and Observability

The integration provides structured logging for:
- Authorization checks (allowed/denied)
- Tuple operations (create/delete)
- Configuration loading
- Connection status
- Error conditions

All log entries include relevant context (user ID, object ID, operation type) for debugging and monitoring.

## Future Enhancements

1. **Repository Integration**: Integrate authorization checks into repository methods
2. **API Middleware**: Add authorization middleware for HTTP endpoints
3. **Permission Caching**: Implement Redis-based permission caching
4. **Admin Interface**: Add UI for managing permissions and relationships
5. **Audit Logging**: Enhanced audit logging for compliance requirements
6. **Bulk Operations**: Batch permission checking for list operations
7. **Policy Management**: Tools for managing OpenFGA authorization models

## Conclusion

The OpenFGA integration provides a solid foundation for fine-grained authorization in AskFrank while maintaining development-friendly defaults and comprehensive testing coverage. The implementation follows OpenFGA best practices and provides both low-level SDK access and high-level convenience methods for common authorization patterns.
