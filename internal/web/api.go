package web

import (
	"context"
	"log/slog"

	"github.com/freekieb7/askfrank/internal/database"
	"github.com/freekieb7/askfrank/internal/http"
	"github.com/freekieb7/askfrank/internal/oauth"
	"github.com/freekieb7/askfrank/internal/user"
)

type APIHandler struct {
	Logger       *slog.Logger
	DB           *database.Database
	UserManager  *user.Manager
	OAuthManager *oauth.Manager
}

func NewAPIHandler(logger *slog.Logger, db *database.Database, userManager *user.Manager, oauthManager *oauth.Manager) *APIHandler {
	return &APIHandler{
		Logger:       logger,
		DB:           db,
		UserManager:  userManager,
		OAuthManager: oauthManager,
	}
}

func (h *APIHandler) Healthy(ctx context.Context, req *http.Request, res *http.Response) error {
	// Check database connection
	if err := h.DB.Ping(ctx); err != nil {
		h.Logger.Error("Database connection failed", "error", err)

		return ErrorResponse(res, http.StatusInternalServerError, "SERVER_ERROR", "Internal server error")
	}

	return res.SendText("OK")
}

type ListClientsRequest struct {
	PageSize  int `query:"page_size"`
	PageToken int `query:"page_token"`
}

func (h *APIHandler) ListClients(ctx context.Context, req *http.Request, res *http.Response) error {
	clients, err := h.OAuthManager.ListClients(ctx)
	if err != nil {
		h.Logger.Error("Failed to list OAuth clients", "error", err)
		return ErrorResponse(res, http.StatusInternalServerError, "SERVER_ERROR", "Internal server error")
	}

	clientsResponse := make([]map[string]any, len(clients))
	for i, client := range clients {
		clientsResponse[i] = map[string]any{
			"id":            client.ID,
			"name":          client.Name,
			"redirect_uris": client.RedirectURIs,
		}
	}

	return PaginationResponse(res, clientsResponse, "")
}

// type CreateClientRequest struct {
// 	Name          string   `json:"name"`
// 	RedirectURIs  []string `json:"redirect_uris"`
// 	Public        bool     `json:"public"`
// 	AllowedScopes []string `json:"allowed_scopes"`
// }

// func (h *ApiHandler) CreateClient(w http.ResponseWriter, r *http.Request) error {
// 	ctx := r.Context()
// 	userID := ctx.Value(config.UserIDContextKey).(uuid.UUID)

// 	var requestBody CreateClientRequest
// 	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
// 		h.logger.Error("Failed to parse request body", "error", err)
// 		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Invalid request body",
// 		})
// 	}

// 	secret, err := util.RandomString(32)
// 	if err != nil {
// 		h.logger.Error("Failed to generate client secret", "error", err)
// 		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Failed to generate client secret",
// 		})
// 	}

// 	client, err := h.db.CreateOAuthClient(ctx, database.CreateOAuthClientParams{
// 		Name:         requestBody.Name,
// 		RedirectURIs: requestBody.RedirectURIs,
// 		OwnerID:      userID,
// 		Secret:       secret,
// 	})
// 	if err != nil {
// 		h.logger.Error("Failed to create OAuth client", "error", err)
// 		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Failed to create OAuth client",
// 		})
// 	}

// 	return JSONResponse(w, http.StatusCreated, ApiResponse{
// 		Status: APIResponseStatusSuccess,
// 		Data: map[string]any{
// 			"id":            client.ID,
// 			"name":          client.Name,
// 			"redirect_uris": client.RedirectURIs,
// 			"owner_id":      client.OwnerID,
// 			"client_secret": client.Secret, // Show secret only at creation time
// 			"created_at":    client.CreatedAt.Unix(),
// 			"updated_at":    client.UpdatedAt.Unix(),
// 		},
// 	})
// }

// func (h *ApiHandler) GetClient(w http.ResponseWriter, r *http.Request) error {
// 	ctx := r.Context()
// 	clientIDStrRaw := ctx.Value("client_id").(string)
// 	if clientIDStrRaw == "" {
// 		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Missing client ID",
// 		})
// 	}

// 	clientIDRaw, err := uuid.Parse(clientIDStrRaw)
// 	if err != nil {
// 		h.logger.Error("Invalid client ID format", "client_id", clientIDStrRaw)
// 		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Invalid client ID format",
// 		})
// 	}

// 	client, err := h.db.GetOAuthClientByID(ctx, clientIDRaw)
// 	if err != nil {
// 		h.logger.Error("Failed to get OAuth client", "error", err)

// 		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Failed to get OAuth client",
// 		})
// 	}

// 	return JSONResponse(w, http.StatusOK, ApiResponse{
// 		Status: APIResponseStatusSuccess,
// 		Data: map[string]any{
// 			"id":            client.ID,
// 			"name":          client.Name,
// 			"redirect_uris": client.RedirectURIs,
// 			"owner_id":      client.OwnerID,
// 			"created_at":    client.CreatedAt.Unix(),
// 			"updated_at":    client.UpdatedAt.Unix(),
// 		},
// 	})
// }

// func (h *ApiHandler) DeleteClient(w http.ResponseWriter, r *http.Request) error {
// 	ctx := r.Context()
// 	clientIDStrRaw := ctx.Value("client_id").(string)
// 	if clientIDStrRaw == "" {
// 		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Missing client ID",
// 		})
// 	}

// 	clientIDRaw, err := uuid.Parse(clientIDStrRaw)
// 	if err != nil {
// 		h.logger.Error("Invalid client ID format", "client_id", clientIDStrRaw)
// 		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Invalid client ID format",
// 		})
// 	}

// 	if err := h.db.DeleteOAuthClientByID(ctx, clientIDRaw); err != nil {
// 		h.logger.Error("Failed to delete OAuth client", "error", err)
// 		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Failed to delete OAuth client",
// 		})
// 	}

// 	return JSONResponse(w, http.StatusOK, ApiResponse{
// 		Status:  APIResponseStatusSuccess,
// 		Message: "OAuth client deleted successfully",
// 	})
// }

// func (h *ApiHandler) ListFiles(w http.ResponseWriter, r *http.Request) error {
// 	ctx := r.Context()
// 	userID := ctx.Value(config.UserIDContextKey).(uuid.UUID)

// 	// fileIDs, err := h.authorization.ListCanReadFiles(c.Context(), userID)
// 	// if err != nil {
// 	// 	h.logger.Error("Failed to list readable files", "error", err, "user_id", userID)
// 	// 	return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
// 	// 		"status":  "error",
// 	// 		"message": "Failed to list readable files",
// 	// 	})
// 	// }

// 	// For now, list all files owned by the user
// 	// In the future, we should allow filter by shared
// 	// params.AllowedIDs = fileIDs

// 	files, err := h.db.ListFiles(ctx, database.ListFilesParams{
// 		OwnerID: util.Some(userID),
// 	})
// 	if err != nil {
// 		h.logger.Error("Failed to list files", "error", err, "user_id", userID)
// 		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Failed to list files",
// 		})
// 	}

// 	filesResponse := make([]map[string]any, 0, len(files))
// 	for _, file := range files {
// 		filesResponse = append(filesResponse, map[string]any{
// 			"id":            file.ID,
// 			"name":          file.Name,
// 			"mime_type":     file.MimeType,
// 			"size_bytes":    file.SizeBytes,
// 			"last_modified": file.UpdatedAt.Unix(),
// 		})
// 	}

// 	return JSONResponse(w, http.StatusOK, ApiResponse{
// 		Status: APIResponseStatusSuccess,
// 		Data:   filesResponse,
// 	})
// }

// type CreateFileRequest struct {
// 	Name     string                   `json:"name"`
// 	MimeType string                   `json:"mime_type"`
// 	Parent   util.Optional[uuid.UUID] `json:"parent"` // Optional parent folder ID
// }

// func (h *ApiHandler) CreateFile(w http.ResponseWriter, r *http.Request) error {
// 	ctx := r.Context()
// 	userID := ctx.Value(config.UserIDContextKey).(uuid.UUID)

// 	// Parse the request body into a File struct
// 	var requestBody CreateFileRequest
// 	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
// 		h.logger.Error("Failed to parse request body", "error", err)
// 		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Invalid request body",
// 		})
// 	}

// 	// For now we only support creating folder through this endpoint
// 	// In the future, files should also be supported
// 	if requestBody.MimeType != "application/askfrank.folder" {
// 		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Only folder creation is supported",
// 		})
// 	}

// 	file, err := h.db.CreateFile(ctx, database.CreateFileParams{
// 		OwnerID:   userID,
// 		ParentID:  requestBody.Parent,
// 		Name:      requestBody.Name,
// 		MimeType:  requestBody.MimeType,
// 		Path:      "", // Path will be set later when file is uploaded
// 		SizeBytes: 0,
// 	})
// 	if err != nil {
// 		h.logger.Error("Failed to create file", "error", err, "user_id", userID)
// 		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Failed to create file",
// 		})
// 	}

// 	return JSONResponse(w, http.StatusCreated, ApiResponse{
// 		Status:  APIResponseStatusSuccess,
// 		Message: "File created successfully",
// 		Data: map[string]any{
// 			"id":            file.ID,
// 			"name":          file.Name,
// 			"mime_type":     file.MimeType,
// 			"size_bytes":    file.SizeBytes,
// 			"last_modified": file.UpdatedAt.Unix(),
// 		},
// 	})
// }

// func (h *ApiHandler) GetFile(w http.ResponseWriter, r *http.Request) error {
// 	ctx := r.Context()
// 	// userID := ctx.Value(config.UserIDContextKey).(uuid.UUID)

// 	fileIDStr := r.PathValue("file_id")
// 	if fileIDStr == "" {
// 		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "File ID is required",
// 		})
// 	}

// 	fileID, err := uuid.Parse(fileIDStr)
// 	if err != nil {
// 		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Invalid file ID",
// 		})
// 	}

// 	// if ok, err := h.authorization.CanReadFile(c.Context(), userID, fileID); !ok {
// 	// 	h.logger.Error("User does not have permission to read file", "user_id", userID, "file_id", fileID, "error", err)
// 	// 	return util.FormatResponse(c, fiber.StatusForbidden, util.ApiResponse{
// 	// 		Status:  util.APIResponseStatusError,
// 	// 		Message: "You do not have permission to read this file",
// 	// 	})
// 	// }

// 	file, err := h.db.GetFileByID(ctx, fileID)
// 	if err != nil {
// 		h.logger.Error("Failed to get file", "error", err, "file_id", fileID)
// 		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Failed to get file",
// 		})
// 	}

// 	return JSONResponse(w, http.StatusOK, ApiResponse{
// 		Status: APIResponseStatusSuccess,
// 		Data: map[string]any{
// 			"id":            file.ID,
// 			"name":          file.Name,
// 			"mime_type":     file.MimeType,
// 			"size_bytes":    file.SizeBytes,
// 			"last_modified": file.UpdatedAt.Unix(),
// 		},
// 	})
// }

// func (h *ApiHandler) DeleteFile(w http.ResponseWriter, r *http.Request) error {
// 	ctx := r.Context()
// 	// userID := c.Locals("user_id").(uuid.UUID)

// 	fileID := r.PathValue("file_id")
// 	if fileID == "" {
// 		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "File ID is required",
// 		})
// 	}

// 	// todo check permission
// 	// if err := h.authorization.CanDeleteFile(c.Context(), uuid.Nil, uuid.MustParse(fileID)); err != nil {
// 	// 	h.logger.Error("User does not have permission to delete file", "error", err, "file_id", fileID)
// 	// 	return h.formatResponse(c, fiber.StatusForbidden, ApiResponse{
// 	// 		Status:  APIResponseStatusError,
// 	// 		Message: "You do not have permission to delete this file",
// 	// 	})
// 	// }

// 	if err := h.db.DeleteFileByID(ctx, uuid.MustParse(fileID)); err != nil {
// 		h.logger.Error("Failed to delete file", "error", err, "file_id", fileID)
// 		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Failed to delete file",
// 		})
// 	}

// 	// if err := h.authorization.RemoveFileReader(c.Context(), uuid.Nil, uuid.MustParse(fileID)); err != nil {
// 	// 	h.logger.Error("Failed to remove file reader permission", "error", err, "file_id", fileID)
// 	// 	// Not returning error to user since the file deletion was successful
// 	// }

// 	return JSONResponse(w, http.StatusOK, ApiResponse{
// 		Status:  APIResponseStatusSuccess,
// 		Message: "File deleted successfully",
// 	})
// }

// // func (h *ApiHandler) UploadFile(w http.ResponseWriter, r *http.Request) error {
// // 	ctx := r.Context()
// // 	userID := ctx.Value(config.UserIDContextKey).(uuid.UUID)

// // 	// Get folder ID from form data (optional)
// // 	var folderID util.Optional[uuid.UUID]
// // 	if folderIDStr := r.FormValue("folder_id"); folderIDStr != "" {
// // 		id, err := uuid.Parse(folderIDStr)
// // 		if err != nil {
// // 			return JSONResponse(w, http.StatusBadRequest, ApiResponse{
// // 				Status:  APIResponseStatusError,
// // 				Message: "Invalid folder ID",
// // 			})
// // 		}
// // 		folderID = util.Some(id)
// // 	}

// // 	// Parse multipart form
// // 	form, err := r.ParseMultipartForm(10 << 20) // 10 MB limit
// // 	if err != nil {
// // 		h.logger.Error("Failed to parse multipart form", "error", err)
// // 		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
// // 			Status:  APIResponseStatusError,
// // 			Message: "Failed to parse multipart form",
// // 		})
// // 	}

// // 	files := form.File["files"]
// // 	if len(files) == 0 {
// // 		return util.FormatResponse(c, fiber.StatusBadRequest, util.ApiResponse{
// // 			Status:  util.APIResponseStatusError,
// // 			Message: "No files provided",
// // 		})
// // 	}

// // 	// Create uploads directory if it doesn't exist
// // 	uploadDir := "uploads"
// // 	if err := os.MkdirAll(uploadDir, 0755); err != nil {
// // 		h.logger.Error("Failed to create upload directory", "error", err)
// // 		return util.FormatResponse(c, fiber.StatusInternalServerError, util.ApiResponse{
// // 			Status:  util.APIResponseStatusError,
// // 			Message: "Failed to create upload directory",
// // 		})
// // 	}

// // 	var uploadedFiles []fiber.Map

// // 	for _, fileHeader := range files {
// // 		// Generate unique filename
// // 		ext := filepath.Ext(fileHeader.Filename)
// // 		baseFilename := strings.TrimSuffix(fileHeader.Filename, ext)
// // 		uniqueFilename := baseFilename + "_" + uuid.New().String() + ext
// // 		filePath := filepath.Join(uploadDir, uniqueFilename)

// // 		// Save file to disk
// // 		if err := c.SaveFile(fileHeader, filePath); err != nil {
// // 			h.logger.Error("Failed to save file", "error", err, "filename", fileHeader.Filename)
// // 			continue
// // 		}

// // 		// Determine MIME type
// // 		mimeType := fileHeader.Header.Get("Content-Type")
// // 		if mimeType == "" {
// // 			mimeType = "application/octet-stream"
// // 		}

// // 		// Create file record in database
// // 		file, err := h.db.CreateFile(c.Context(), database.CreateFileParams{
// // 			OwnerID:   userID,
// // 			ParentID:  folderID,
// // 			Name:      fileHeader.Filename,
// // 			MimeType:  mimeType,
// // 			S3Key:     util.None[string](),
// // 			Path:      util.Some(filePath),
// // 			SizeBytes: fileHeader.Size,
// // 		})
// // 		if err != nil {
// // 			h.logger.Error("Failed to create file record", "error", err, "filename", fileHeader.Filename)
// // 			// Try to delete the saved file
// // 			os.Remove(filePath)
// // 			continue
// // 		}

// // 		// if err := h.authorization.AddFileReader(c.Context(), userID, file.ID); err != nil {
// // 		// 	h.logger.Error("Failed to add file reader permission", "error", err, "user_id", userID, "file_id", file.ID)
// // 		// 	// Try to delete the saved file and database record
// // 		// 	os.Remove(filePath)
// // 		// 	if err := h.db.DeleteFile(c.Context(), file.ID); err != nil {
// // 		// 		h.logger.Error("Failed to delete file record after permission error", "error", err, "file_id", file.ID)
// // 		// 	}
// // 		// 	continue
// // 		// }

// // 		uploadedFiles = append(uploadedFiles, fiber.Map{
// // 			"id":       file.ID,
// // 			"name":     file.Name,
// // 			"size":     file.SizeBytes,
// // 			"mimeType": file.MimeType,
// // 		})
// // 	}

// // 	if len(uploadedFiles) == 0 {
// // 		h.logger.Error("No files were uploaded successfully")
// // 		return util.FormatResponse(c, fiber.StatusInternalServerError, util.ApiResponse{
// // 			Status:  util.APIResponseStatusError,
// // 			Message: "Failed to upload any files",
// // 		})
// // 	}

// // 	return util.FormatResponse(c, fiber.StatusCreated, util.ApiResponse{
// // 		Status: util.APIResponseStatusSuccess,
// // 		Data:   uploadedFiles,
// // 	})
// // }

// func (h *ApiHandler) DownloadFile(w http.ResponseWriter, r *http.Request) error {
// 	ctx := r.Context()
// 	// userID := c.Locals("user_id").(uuid.UUID)

// 	fileIDStr := r.PathValue("file_id")
// 	fileID, err := uuid.Parse(fileIDStr)
// 	if err != nil {
// 		h.logger.Error("Invalid file ID", "error", err)
// 		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Invalid file ID",
// 		})
// 	}

// 	// todo check file access

// 	file, err := h.db.GetFileByID(ctx, fileID)
// 	if err != nil {
// 		if err == database.ErrFileNotFound {
// 			h.logger.Error("File not found", "file_id", fileID)
// 			return JSONResponse(w, http.StatusNotFound, ApiResponse{
// 				Status:  APIResponseStatusError,
// 				Message: "File not found",
// 			})
// 		}
// 		h.logger.Error("Failed to retrieve file", "error", err, "file_id", fileID)
// 		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Failed to retrieve file",
// 		})
// 	}

// 	// Serve the file
// 	if err := Download(w, r, file.Path, file.Name); err != nil {
// 		h.logger.Error("Failed to serve file", "error", err, "file_id", fileID)
// 		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Failed to serve file",
// 		})
// 	}

// 	return nil
// }

// type APIShareFileRequest struct {
// 	Email string `json:"email"`
// }

// func (h *ApiHandler) ShareFile(w http.ResponseWriter, r *http.Request) error {
// 	ctx := r.Context()
// 	// userID := c.Locals("user_id").(uuid.UUID)

// 	// Get file ID from URL parameter
// 	fileIDStr := r.PathValue("file_id")
// 	fileID, err := uuid.Parse(fileIDStr)
// 	if err != nil {
// 		h.logger.Error("Invalid file ID", "error", err)
// 		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Invalid file ID",
// 		})
// 	}

// 	// Check if the user has permission to share the file
// 	// if ok, err := h.authorization.CanShareFile(c.Context(), userID, fileID); !ok {
// 	// 	h.logger.Error("User does not have permission to share file", "user_id", userID, "file_id", fileID, "error", err)
// 	// 	return h.formatResponse(c, fiber.StatusForbidden, ApiResponse{
// 	// 		Status:  APIResponseStatusError,
// 	// 		Message: "You do not have permission to share this file",
// 	// 	})
// 	// }

// 	var req ShareFileRequest
// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		h.logger.Error("Failed to parse request body", "error", err)
// 		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Invalid request",
// 		})
// 	}

// 	// Check if the file exists
// 	file, err := h.db.GetFileByID(ctx, fileID)
// 	if err != nil {
// 		if err == database.ErrFileNotFound {
// 			h.logger.Error("File not found", "file_id", fileID)
// 			return JSONResponse(w, http.StatusNotFound, ApiResponse{
// 				Status:  APIResponseStatusError,
// 				Message: "File not found",
// 			})
// 		}

// 		h.logger.Error("Failed to retrieve file", "error", err, "file_id", fileID)
// 		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Failed to retrieve file",
// 		})
// 	}

// 	targetUser, err := h.db.GetUserByEmail(ctx, req.Email)
// 	if err != nil {
// 		if err == database.ErrUserNotFound {
// 			h.logger.Error("User not found", "email", req.Email)
// 			return JSONResponse(w, http.StatusNotFound, ApiResponse{
// 				Status:  APIResponseStatusError,
// 				Message: "User not found",
// 			})
// 		}

// 		h.logger.Error("Failed to retrieve user", "error", err, "email", req.Email)
// 		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Failed to retrieve user",
// 		})
// 	}

// 	// Check if the requesting user has permission to share the file
// 	// if ok, err := h.authorization.CanShareFile(c.Context(), userID, fileID); !ok {
// 	// 	h.logger.Error("User does not have permission to share file", "user_id", userID, "file_id", fileID, "error", err)
// 	// 	return h.formatResponse(c, fiber.StatusForbidden, ApiResponse{
// 	// 		Status:  APIResponseStatusError,
// 	// 		Message: "You do not have permission to share this file",
// 	// 	})
// 	// }

// 	if _, err = h.db.CreateFileShare(ctx, database.CreateFileShareParams{
// 		FileID:           file.ID,
// 		SharedWithUserID: targetUser.ID,
// 		Permission:       "read", // For simplicity, only "read" permission is supported now
// 	}); err != nil {
// 		h.logger.Error("Failed to create file share", "error", err, "file_id", file.ID, "shared_with_user_id", targetUser.ID)
// 		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Failed to share file",
// 		})
// 	}

// 	// if err := h.authorization.AddFileReader(c.Context(), targetUser.ID, file.ID); err != nil {
// 	// 	h.logger.Error("Failed to add file reader permission", "error", err, "user_id", targetUser.ID, "file_id", file.ID)
// 	// 	return util.FormatResponse(c, fiber.StatusInternalServerError, util.ApiResponse{
// 	// 		Status:  util.APIResponseStatusError,
// 	// 		Message: "Failed to share file",
// 	// 	})
// 	// }

// 	// Optionally, send notification email to the target user
// 	// go func() {
// 	// 	if err := h.emailer.SendFileSharedEmail(targetUser.Email, file.Name); err != nil {
// 	// 		h.logger.Error("Failed to send file shared email", "error", err, "email", targetUser.Email)
// 	// 	}
// 	// }()

// 	return JSONResponse(w, http.StatusOK, ApiResponse{
// 		Status:  APIResponseStatusSuccess,
// 		Message: "File shared successfully",
// 	})
// }

// // MarkNotificationAsRead marks a specific notification as read
// func (h *ApiHandler) MarkNotificationAsRead(w http.ResponseWriter, r *http.Request) error {
// 	ctx := r.Context()

// 	userID := ctx.Value(config.UserIDContextKey).(uuid.UUID)

// 	// Get notification ID from URL path
// 	notificationIDStr := r.PathValue("notification_id")

// 	// Parse UUID
// 	notificationID, err := uuid.Parse(notificationIDStr)
// 	if err != nil {
// 		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Invalid notification ID",
// 		})
// 	}

// 	// Verify notification belongs to the user
// 	notification, err := h.db.GetNotificationByID(r.Context(), notificationID)
// 	if err != nil {
// 		if err == database.ErrNotificationNotFound {
// 			return JSONResponse(w, http.StatusNotFound, ApiResponse{
// 				Status:  APIResponseStatusError,
// 				Message: "Notification not found",
// 			})
// 		}

// 		h.logger.Error("Failed to get notification", "error", err, "notification_id", notificationID)
// 		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Failed to retrieve notification",
// 		})
// 	}

// 	if notification.OwnerID != userID {
// 		return JSONResponse(w, http.StatusForbidden, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "You do not have permission to modify this notification",
// 		})
// 	}

// 	// Mark notification as read in database
// 	if err := h.db.UpdateNotificationByID(r.Context(), notificationID, database.UpdateNotificationParams{
// 		IsRead: util.Some(true),
// 	}); err != nil {
// 		h.logger.Error("Failed to update notification", "error", err, "notification_id", notificationID)
// 		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Failed to mark notification as read",
// 		})
// 	}

// 	return JSONResponse(w, http.StatusOK, ApiResponse{
// 		Status:  APIResponseStatusSuccess,
// 		Message: "Notification marked as read",
// 	})
// }

// // MarkAllNotificationsAsRead marks all notifications for the current user as read
// func (h *ApiHandler) MarkAllNotificationsAsRead(w http.ResponseWriter, r *http.Request) error {
// 	ctx := r.Context()

// 	// Get user session
// 	sess, err := h.sessionStore.Get(ctx, r)
// 	if err != nil {
// 		h.logger.Error("Failed to get session", "error", err)
// 		return JSONResponse(w, http.StatusUnauthorized, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Authentication required",
// 		})
// 	}

// 	if !sess.UserID.Some {
// 		return JSONResponse(w, http.StatusUnauthorized, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Authentication required",
// 		})
// 	}

// 	user, err := h.db.GetUserByID(ctx, sess.UserID.Data)
// 	if err != nil {
// 		h.logger.Error("Failed to get user from database", "error", err)
// 		return JSONResponse(w, http.StatusUnauthorized, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Authentication required",
// 		})
// 	}

// 	// Mark all notifications as read in database
// 	err = h.db.MarkAllNotificationsAsRead(r.Context(), user.ID)
// 	if err != nil {
// 		h.logger.Error("Failed to mark all notifications as read", "error", err, "user_id", user.ID)
// 		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Failed to mark notifications as read",
// 		})
// 	}

// 	return JSONResponse(w, http.StatusOK, ApiResponse{
// 		Status:  APIResponseStatusSuccess,
// 		Message: "All notifications marked as read",
// 	})
// }

// // GetNotifications returns recent notifications for the current user
// func (h *ApiHandler) GetNotifications(w http.ResponseWriter, r *http.Request) error {
// 	ctx := r.Context()

// 	userID := ctx.Value(config.UserIDContextKey).(uuid.UUID)

// 	// Get limit from query parameter (default 20)
// 	limit := int32(20)
// 	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
// 		if parsedLimit, err := strconv.ParseInt(limitStr, 10, 32); err == nil && parsedLimit > 0 {
// 			limit = int32(parsedLimit)
// 		}
// 	}

// 	// Get notifications from database
// 	notifications, err := h.db.ListNotifications(r.Context(), database.ListNotificationsParams{
// 		OwnerID: util.Some(userID),
// 		Limit:   util.Some(limit),
// 	})
// 	if err != nil {
// 		h.logger.Error("Failed to get notifications", "error", err, "user_id", userID)
// 		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Failed to retrieve notifications",
// 		})
// 	}

// 	return JSONResponse(w, http.StatusOK, ApiResponse{
// 		Status:  APIResponseStatusSuccess,
// 		Message: "Notifications retrieved successfully",
// 		Data:    notifications,
// 	})
// }

// // Calendar API Endpoints

// // GetCalendarEvents returns calendar events for the current user
// func (h *ApiHandler) GetCalendarEvents(w http.ResponseWriter, r *http.Request) error {
// 	ctx := r.Context()

// 	// Get user session
// 	sess, err := h.sessionStore.Get(ctx, r)
// 	if err != nil {
// 		h.logger.Error("Failed to get session", "error", err)
// 		return JSONResponse(w, http.StatusUnauthorized, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Authentication required",
// 		})
// 	}

// 	if !sess.UserID.Some {
// 		return JSONResponse(w, http.StatusUnauthorized, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Authentication required",
// 		})
// 	}

// 	user, err := h.db.GetUserByID(ctx, sess.UserID.Data)
// 	if err != nil {
// 		h.logger.Error("Failed to get user from database", "error", err)
// 		return JSONResponse(w, http.StatusUnauthorized, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Authentication required",
// 		})
// 	}

// 	// Get date range from query parameters
// 	startDateStr := r.URL.Query().Get("start")
// 	endDateStr := r.URL.Query().Get("end")

// 	var startDate, endDate time.Time
// 	if startDateStr != "" {
// 		startDate, _ = time.Parse("2006-01-02", startDateStr)
// 	} else {
// 		startDate = time.Now().AddDate(0, -1, 0) // Default to 1 month ago
// 	}

// 	if endDateStr != "" {
// 		endDate, _ = time.Parse("2006-01-02", endDateStr)
// 	} else {
// 		endDate = time.Now().AddDate(0, 2, 0) // Default to 2 months from now
// 	}

// 	// Get events from database
// 	events, err := h.db.ListCalendarEvents(ctx, database.ListCalendarEventsParams{
// 		OwnerID:   util.Some(user.ID),
// 		StartDate: util.Some(startDate),
// 		EndDate:   util.Some(endDate),
// 	})

// 	if err != nil {
// 		h.logger.Error("Failed to get calendar events", "error", err, "user_id", user.ID)
// 		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Failed to retrieve calendar events",
// 		})
// 	}

// 	return JSONResponse(w, http.StatusOK, ApiResponse{
// 		Status:  APIResponseStatusSuccess,
// 		Message: "Events retrieved successfully",
// 		Data:    events,
// 	})
// }

// // CreateCalendarEvent creates a new calendar event
// func (h *ApiHandler) CreateCalendarEvent(w http.ResponseWriter, r *http.Request) error {
// 	ctx := r.Context()

// 	// Get user session
// 	sess, err := h.sessionStore.Get(ctx, r)
// 	if err != nil {
// 		return JSONResponse(w, http.StatusUnauthorized, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Authentication required",
// 		})
// 	}

// 	if !sess.UserID.Some {
// 		return JSONResponse(w, http.StatusUnauthorized, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Authentication required",
// 		})
// 	}

// 	user, err := h.db.GetUserByID(ctx, sess.UserID.Data)
// 	if err != nil {
// 		return JSONResponse(w, http.StatusUnauthorized, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Authentication required",
// 		})
// 	}

// 	// Parse request body
// 	var req struct {
// 		Title       string `json:"title"`
// 		Description string `json:"description"`
// 		Start       string `json:"start"`
// 		End         string `json:"end"`
// 		AllDay      bool   `json:"all_day"`
// 		Location    string `json:"location"`
// 		Status      string `json:"status"`
// 	}

// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Invalid request body",
// 		})
// 	}

// 	// Validate required fields
// 	if req.Title == "" {
// 		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Title is required",
// 		})
// 	}

// 	// Parse dates
// 	startTime, err := time.Parse(time.RFC3339, req.Start)
// 	if err != nil {
// 		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Invalid start time format",
// 		})
// 	}

// 	endTime, err := time.Parse(time.RFC3339, req.End)
// 	if err != nil {
// 		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Invalid end time format",
// 		})
// 	}

// 	if startTime.After(endTime) {
// 		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "End time must be after start time",
// 		})
// 	}

// 	// Set default status if not provided
// 	if req.Status == "" {
// 		req.Status = "confirmed"
// 	}

// 	// Create event in database
// 	event, err := h.db.CreateCalendarEvent(ctx, database.CreateCalendarEventParams{
// 		OwnerID:     user.ID,
// 		Title:       req.Title,
// 		Description: req.Description,
// 		StartTime:   startTime,
// 		EndTime:     endTime,
// 		AllDay:      req.AllDay,
// 		Status:      database.CalendarEventStatus(req.Status),
// 		Location:    util.Some(req.Location),
// 	})

// 	if err != nil {
// 		h.logger.Error("Failed to create calendar event", "error", err, "user_id", user.ID)
// 		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Failed to create event",
// 		})
// 	}

// 	return JSONResponse(w, http.StatusCreated, ApiResponse{
// 		Status:  APIResponseStatusSuccess,
// 		Message: "Event created successfully",
// 		Data: map[string]interface{}{
// 			"event_id": event.ID.String(),
// 			"title":    event.Title,
// 		},
// 	})
// }

// // UpdateCalendarEvent updates an existing calendar event
// func (h *ApiHandler) UpdateCalendarEvent(w http.ResponseWriter, r *http.Request) error {
// 	ctx := r.Context()

// 	// Get user session
// 	sess, err := h.sessionStore.Get(ctx, r)
// 	if err != nil {
// 		return JSONResponse(w, http.StatusUnauthorized, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Authentication required",
// 		})
// 	}

// 	if !sess.UserID.Some {
// 		return JSONResponse(w, http.StatusUnauthorized, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Authentication required",
// 		})
// 	}

// 	user, err := h.db.GetUserByID(ctx, sess.UserID.Data)
// 	if err != nil {
// 		return JSONResponse(w, http.StatusUnauthorized, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Authentication required",
// 		})
// 	}

// 	// Get event ID from URL path
// 	eventIDStr := r.URL.Path[len("/api/calendar/events/"):]
// 	eventID, err := uuid.Parse(eventIDStr)
// 	if err != nil {
// 		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Invalid event ID",
// 		})
// 	}

// 	// Parse request body
// 	var req struct {
// 		Title       string `json:"title"`
// 		Description string `json:"description"`
// 		Start       string `json:"start"`
// 		End         string `json:"end"`
// 		AllDay      bool   `json:"all_day"`
// 		Location    string `json:"location"`
// 		Status      string `json:"status"`
// 	}

// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Invalid request body",
// 		})
// 	}

// 	// Parse dates
// 	startTime, err := time.Parse(time.RFC3339, req.Start)
// 	if err != nil {
// 		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Invalid start time format",
// 		})
// 	}

// 	endTime, err := time.Parse(time.RFC3339, req.End)
// 	if err != nil {
// 		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Invalid end time format",
// 		})
// 	}

// 	// First, verify the event exists and user owns it
// 	events, err := h.db.ListCalendarEvents(ctx, database.ListCalendarEventsParams{
// 		OwnerID: util.Some(user.ID),
// 	})
// 	if err != nil {
// 		h.logger.Error("Failed to get calendar events", "error", err, "user_id", user.ID)
// 		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Failed to verify event ownership",
// 		})
// 	}

// 	// Check if the event exists and belongs to the user
// 	var foundEvent bool
// 	for _, event := range events {
// 		if event.ID == eventID {
// 			foundEvent = true
// 			break
// 		}
// 	}

// 	if !foundEvent {
// 		return JSONResponse(w, http.StatusNotFound, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Event not found or you don't have permission to update it",
// 		})
// 	}

// 	// Update event in database
// 	err = h.db.UpdateCalendarEventByID(ctx, eventID, database.UpdateCalendarEventParams{
// 		Title:       util.Some(req.Title),
// 		Description: util.Some(req.Description),
// 		StartTime:   util.Some(startTime),
// 		EndTime:     util.Some(endTime),
// 		AllDay:      util.Some(req.AllDay),
// 		Status:      util.Some(database.CalendarEventStatus(req.Status)),
// 		Location:    util.Some(util.Some(req.Location)),
// 	})

// 	if err != nil {
// 		h.logger.Error("Failed to update calendar event", "error", err, "event_id", eventID, "user_id", user.ID)
// 		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Failed to update event",
// 		})
// 	}

// 	return JSONResponse(w, http.StatusOK, ApiResponse{
// 		Status:  APIResponseStatusSuccess,
// 		Message: "Event updated successfully",
// 	})
// }

// // DeleteCalendarEvent deletes a calendar event
// func (h *ApiHandler) DeleteCalendarEvent(w http.ResponseWriter, r *http.Request) error {
// 	ctx := r.Context()

// 	// Get user session
// 	sess, err := h.sessionStore.Get(ctx, r)
// 	if err != nil {
// 		return JSONResponse(w, http.StatusUnauthorized, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Authentication required",
// 		})
// 	}

// 	if !sess.UserID.Some {
// 		return JSONResponse(w, http.StatusUnauthorized, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Authentication required",
// 		})
// 	}

// 	user, err := h.db.GetUserByID(ctx, sess.UserID.Data)
// 	if err != nil {
// 		return JSONResponse(w, http.StatusUnauthorized, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Authentication required",
// 		})
// 	}

// 	// Get event ID from URL path
// 	eventIDStr := r.URL.Path[len("/api/calendar/events/"):]
// 	eventID, err := uuid.Parse(eventIDStr)
// 	if err != nil {
// 		return JSONResponse(w, http.StatusBadRequest, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Invalid event ID",
// 		})
// 	}

// 	// First, verify the event exists and user owns it
// 	events, err := h.db.ListCalendarEvents(ctx, database.ListCalendarEventsParams{
// 		OwnerID: util.Some(user.ID),
// 	})
// 	if err != nil {
// 		h.logger.Error("Failed to get calendar events", "error", err, "user_id", user.ID)
// 		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Failed to verify event ownership",
// 		})
// 	}

// 	// Check if the event exists and belongs to the user
// 	var foundEvent bool
// 	for _, event := range events {
// 		if event.ID == eventID {
// 			foundEvent = true
// 			break
// 		}
// 	}

// 	if !foundEvent {
// 		return JSONResponse(w, http.StatusNotFound, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Event not found or you don't have permission to delete it",
// 		})
// 	}

// 	// Delete event from database
// 	err = h.db.DeleteCalendarEventByID(ctx, eventID)
// 	if err != nil {
// 		h.logger.Error("Failed to delete calendar event", "error", err, "event_id", eventID, "user_id", user.ID)
// 		return JSONResponse(w, http.StatusInternalServerError, ApiResponse{
// 			Status:  APIResponseStatusError,
// 			Message: "Failed to delete event",
// 		})
// 	}

// 	return JSONResponse(w, http.StatusOK, ApiResponse{
// 		Status:  APIResponseStatusSuccess,
// 		Message: "Event deleted successfully",
// 	})
// }

func ErrorResponse(res *http.Response, code http.StatusCode, status string, message string) error {
	res.SetStatus(code)
	return res.SendJSON(map[string]any{
		"error": map[string]any{
			"code":    status,
			"message": message,
			"status":  status,
		},
	})
}

func PaginationResponse(res *http.Response, items any, nextPageToken string) error {
	return res.SendJSON(map[string]any{
		"items":           items,
		"next_page_token": nextPageToken,
	})
}
