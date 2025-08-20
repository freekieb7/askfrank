package api

import (
	"encoding/json"
	"hp/internal/database"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stripe/stripe-go/v82/webhook"
)

type ApiHandler struct {
	db *database.PostgresDatabase
}

func NewApiHandler(db *database.PostgresDatabase) *ApiHandler {
	return &ApiHandler{
		db: db,
	}
}

func (h *ApiHandler) Healthy(c *fiber.Ctx) error {
	// Check database connection
	if err := h.db.Ping(c.Context()); err != nil {
		slog.Error("Database connection failed", "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "unhealthy",
			"message": "Database connection failed",
		})
	}

	// Additional health checks can be added here

	return c.JSON(fiber.Map{
		"status":  "healthy",
		"message": "Service is healthy",
	})
}

func (h *ApiHandler) StripeWebhook(c *fiber.Ctx) error {
	// Handle Stripe webhook events
	// This is a placeholder for actual webhook handling logic
	endpointSecret := "whsec_r0fySCr2f4JP6Sm2lXYK8HXJkRApaRhC"
	event, err := webhook.ConstructEvent(c.Body(), c.Get("Stripe-Signature"), endpointSecret)
	if err != nil {
		slog.Error("Failed to construct webhook event", "error", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Invalid webhook payload",
		})
	}
	// Process the event based on its type
	switch event.Type {
	case "customer.subscription.created":
		// Handle successful customer subscription creation
		slog.Info("Customer subscription created", "event", event)
	case "customer.subscription.updated":
		// Handle customer subscription updated
		slog.Info("Customer subscription updated", "event", event)
	case "customer.subscription.deleted":
		// Handle customer subscription deletion
		slog.Info("Customer subscription deleted", "event", event)
	case "invoice.payment_succeeded":
		// Handle successful invoice payment
		slog.Info("Invoice payment succeeded", "event", event)
	case "invoice.payment_failed":
		// Handle failed invoice payment
		slog.Info("Invoice payment failed", "event", event)
	default:
		slog.Info("Unhandled event type", "type", event.Type)
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "Webhook received successfully",
	})
}

func (h *ApiHandler) ListFiles(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)

	var params database.GetFilesParams

	files, err := h.db.GetFiles(c.Context(), params)
	if err != nil {
		slog.Error("Failed to list files", "error", err, "user_id", userID)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status": "error",
			"error":  "Failed to list files",
		})
	}

	jsonFiles := make([]fiber.Map, 0, len(files))
	for _, file := range files {
		jsonFiles = append(jsonFiles, fiber.Map{
			"id":            file.ID,
			"name":          file.Name,
			"mime_type":     file.MimeType,
			"size_bytes":    file.SizeBytes,
			"last_modified": file.UpdatedAt.Unix(),
		})
	}

	return c.JSON(fiber.Map{
		"status": "success",
		"files":  jsonFiles,
	})
}

type CreateFileRequest struct {
	Name     string        `json:"name"`
	MimeType string        `json:"mime_type"`
	Parent   uuid.NullUUID `json:"parent"` // Optional parent folder ID
}

func (h *ApiHandler) CreateFile(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)

	// Parse the request body into a File struct
	var requestBody CreateFileRequest
	if err := json.Unmarshal(c.Body(), &requestBody); err != nil {
		slog.Error("Failed to parse request body", "error", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status": "error",
			"error":  "Invalid request body",
		})
	}

	params := database.CreateFileParams{
		OwnerID:   userID,
		ParentID:  requestBody.Parent,
		Name:      requestBody.Name,
		MimeType:  requestBody.MimeType,
		S3Key:     "",
		SizeBytes: 0,
	}

	// For now we only support creating folder through this endpoint
	// In the future, files should also be supported
	// if !file.IsFolder() {
	// 	return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
	// 		"status": "error",
	// 		"error":  "Invalid mime type for folder",
	// 	})
	// }

	file, err := h.db.CreateFile(c.Context(), params)
	if err != nil {
		slog.Error("Failed to create file", "error", err, "user_id", userID)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status": "error",
			"error":  "Failed to create file",
		})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"status": "success",
		"file": fiber.Map{
			"id":            file.ID,
			"name":          file.Name,
			"mime_type":     file.MimeType,
			"size_bytes":    file.SizeBytes,
			"last_modified": file.UpdatedAt.Unix(),
		},
	})
}

func (h *ApiHandler) GetFile(c *fiber.Ctx) error {
	// userID := c.Locals("user_id").(uuid.UUID)

	fileID := c.Params("file_id")
	if fileID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status": "error",
			"error":  "File ID is required",
		})
	}

	// todo check permissions

	file, err := h.db.GetFileByID(c.Context(), uuid.MustParse(fileID), database.GetFileByIDParams{})
	if err != nil {
		slog.Error("Failed to get file", "error", err, "file_id", fileID)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status": "error",
			"error":  "Failed to get file",
		})
	}

	return c.JSON(fiber.Map{
		"status": "success",
		"file": fiber.Map{
			"id":            file.ID,
			"name":          file.Name,
			"mime_type":     file.MimeType,
			"size_bytes":    file.SizeBytes,
			"last_modified": file.UpdatedAt.Unix(),
		},
	})
}

func (h *ApiHandler) DeleteFile(c *fiber.Ctx) error {
	// userID := c.Locals("user_id").(uuid.UUID)

	fileID := c.Params("file_id")
	if fileID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status": "error",
			"error":  "File ID is required",
		})
	}

	// todo check permission

	if err := h.db.DeleteFile(c.Context(), uuid.MustParse(fileID), database.DeleteFileParams{}); err != nil {
		slog.Error("Failed to delete file", "error", err, "file_id", fileID)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status": "error",
			"error":  "Failed to delete file",
		})
	}

	return c.JSON(fiber.Map{
		"status":  "success",
		"message": "File deleted successfully",
	})
}

func (h *ApiHandler) UploadFile(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)

	// Get folder ID from form data (optional)
	var folderID uuid.NullUUID
	if folderIDStr := c.FormValue("folder_id"); folderIDStr != "" {
		id, err := uuid.Parse(folderIDStr)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"status": "error",
				"error":  "Invalid folder ID",
			})
		}
		folderID = uuid.NullUUID{Valid: true, UUID: id}
	}

	// Parse multipart form
	form, err := c.MultipartForm()
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status": "error",
			"error":  "Failed to parse multipart form",
		})
	}

	files := form.File["files"]
	if len(files) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status": "error",
			"error":  "No files provided",
		})
	}

	// Create uploads directory if it doesn't exist
	uploadDir := "uploads"
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		slog.Error("Failed to create upload directory", "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status": "error",
			"error":  "Failed to create upload directory",
		})
	}

	var uploadedFiles []fiber.Map

	for _, fileHeader := range files {
		// Generate unique filename
		ext := filepath.Ext(fileHeader.Filename)
		baseFilename := strings.TrimSuffix(fileHeader.Filename, ext)
		uniqueFilename := baseFilename + "_" + uuid.New().String() + ext
		filePath := filepath.Join(uploadDir, uniqueFilename)

		// Save file to disk
		if err := c.SaveFile(fileHeader, filePath); err != nil {
			slog.Error("Failed to save file", "error", err, "filename", fileHeader.Filename)
			continue
		}

		// Determine MIME type
		mimeType := fileHeader.Header.Get("Content-Type")
		if mimeType == "" {
			mimeType = "application/octet-stream"
		}

		// Create file record in database
		var params database.CreateFileParams
		params.OwnerID = userID
		params.ParentID = folderID
		params.Name = fileHeader.Filename
		params.MimeType = mimeType
		params.S3Key = filePath
		params.SizeBytes = fileHeader.Size

		file, err := h.db.CreateFile(c.Context(), params)
		if err != nil {
			slog.Error("Failed to create file record", "error", err, "filename", fileHeader.Filename)
			// Try to delete the saved file
			os.Remove(filePath)
			continue
		}

		uploadedFiles = append(uploadedFiles, fiber.Map{
			"id":       file.ID,
			"name":     file.Name,
			"size":     file.SizeBytes,
			"mimeType": file.MimeType,
		})
	}

	if len(uploadedFiles) == 0 {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status": "error",
			"error":  "Failed to upload any files",
		})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"status": "success",
		"files":  uploadedFiles,
	})
}

func (h *ApiHandler) DownloadFile(c *fiber.Ctx) error {
	// userID := c.Locals("user_id").(uuid.UUID)

	fileIDStr := c.Params("file_id")
	fileID, err := uuid.Parse(fileIDStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status": "error",
			"error":  "Invalid file ID",
		})
	}

	// todo check file access

	file, err := h.db.GetFileByID(c.Context(), fileID, database.GetFileByIDParams{})
	if err != nil {
		if err == database.ErrFileNotFound {
			slog.Error("File not found", "file_id", fileID)
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"status": "error",
				"error":  "File not found",
			})
		}
		slog.Error("Failed to retrieve file", "error", err, "file_id", fileID)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status": "error",
			"error":  "Failed to retrieve file",
		})
	}

	if _, err := os.Stat(file.S3Key); os.IsNotExist(err) {
		slog.Error("File does not exist on disk", "file_path", file.S3Key)
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"status": "error",
			"error":  "File not found",
		})
	}

	c.Set("Content-Disposition", `attachment; filename="`+file.Name+`"`)
	c.Set("Content-Type", file.MimeType)

	return c.SendFile(file.S3Key, false)
}

type ShareFileRequest struct {
	Email string `json:"email"`
}

func (h *ApiHandler) ShareFile(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	// Get file ID from URL parameter
	fileIDStr := c.Params("file_id")
	fileID, err := uuid.Parse(fileIDStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status": "error",
			"error":  "Invalid file ID",
		})
	}

	var req ShareFileRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status": "error",
			"error":  "Invalid request",
		})
	}

	// Check if the file exists
	file, err := h.db.GetFileByID(c.Context(), fileID, database.GetFileByIDParams{})
	if err != nil {
		if err == database.ErrFileNotFound {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"status": "error",
				"error":  "File not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status": "error",
			"error":  "Failed to retrieve file",
		})
	}

	var retrieveUserParams database.RetrieveUserParams
	retrieveUserParams.Email = req.Email

	targetUser, err := h.db.RetrieveUser(c.Context(), retrieveUserParams)
	if err != nil {
		if err == database.ErrUserNotFound {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"status": "error",
				"error":  "User not found",
			})
		}

		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status": "error",
			"error":  "Failed to retrieve user",
		})
	}

	// Create a shared file record
	var createSharedFileParams database.CreateSharedFileParams
	createSharedFileParams.FileID = file.ID
	createSharedFileParams.SharingUserID = userID
	createSharedFileParams.ReceivingUserID = targetUser.ID
	createSharedFileParams.GrantedAt = time.Now()

	if err := h.db.CreateSharedFile(c.Context(), createSharedFileParams); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status": "error",
			"error":  "Failed to share file",
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "File shared successfully",
	})
}
