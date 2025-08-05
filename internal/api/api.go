package api

import (
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

type CreateFolderRequest struct {
	Name     string     `json:"name"`
	ParentID *uuid.UUID `json:"parent_id"`
}

func (h *ApiHandler) CreateFolder(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)

	var req CreateFolderRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status": "error",
			"error":  "Invalid request body",
		})
	}

	// Validate folder name
	if req.Name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status": "error",
			"error":  "Folder name is required",
		})
	}

	if len(req.Name) > 100 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status": "error",
			"error":  "Folder name too long (max 100 characters)",
		})
	}

	// Create folder object
	folder := database.Folder{
		ID:      uuid.New(),
		Name:    req.Name,
		OwnerID: userID,
		ParentID: uuid.NullUUID{Valid: req.ParentID != nil, UUID: func() uuid.UUID {
			if req.ParentID != nil {
				return *req.ParentID
			}
			return uuid.UUID{}
		}()},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Save folder to database
	if err := h.db.CreateFolder(c.Context(), folder); err != nil {
		slog.Error("Failed to create folder", "error", err, "user_id", userID)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status": "error",
			"error":  "Failed to create folder",
		})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"status": "success",
		"folder": fiber.Map{
			"id":   folder.ID,
			"name": folder.Name,
		},
	})
}

func (h *ApiHandler) UploadFiles(c *fiber.Ctx) error {
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
		fileRecord := database.File{
			ID:        uuid.New(),
			OwnerID:   userID,
			FolderID:  folderID, // Use the provided folder ID
			Filename:  fileHeader.Filename,
			MimeType:  mimeType,
			S3Key:     filePath, // Store local path for now
			SizeBytes: uint64(fileHeader.Size),
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		if err := h.db.CreateFile(c.Context(), fileRecord); err != nil {
			slog.Error("Failed to create file record", "error", err, "filename", fileHeader.Filename)
			// Try to delete the saved file
			os.Remove(filePath)
			continue
		}

		uploadedFiles = append(uploadedFiles, fiber.Map{
			"id":       fileRecord.ID,
			"filename": fileRecord.Filename,
			"size":     fileRecord.SizeBytes,
			"mimeType": fileRecord.MimeType,
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
	userID := c.Locals("user_id").(uuid.UUID)
	fileIDStr := c.FormValue("file_id")
	if fileIDStr == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status": "error",
			"error":  "File ID is required",
		})
	}

	fileID, err := uuid.Parse(fileIDStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status": "error",
			"error":  "Invalid file ID",
		})
	}

	file, err := h.db.GetFileByID(c.Context(), userID, fileID)
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

	c.Set("Content-Disposition", `attachment; filename="`+file.Filename+`"`)
	c.Set("Content-Type", file.MimeType)

	return c.SendFile(file.S3Key, false)
}

func (h *ApiHandler) DeleteFile(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	fileIDStr := c.FormValue("file_id")
	if fileIDStr == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status": "error",
			"error":  "File ID is required",
		})
	}

	fileID, err := uuid.Parse(fileIDStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status": "error",
			"error":  "Invalid file ID",
		})
	}

	// Get file info before deleting to remove physical file
	file, err := h.db.GetFileByID(c.Context(), userID, fileID)
	if err != nil {
		if err == database.ErrFileNotFound {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"status": "error",
				"error":  "File not found",
			})
		}
		slog.Error("Failed to get file for deletion", "error", err, "file_id", fileID)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status": "error",
			"error":  "Failed to delete file",
		})
	}

	// Delete from database first
	if err := h.db.DeleteFile(c.Context(), userID, fileID); err != nil {
		slog.Error("Failed to delete file from database", "error", err, "file_id", fileID)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status": "error",
			"error":  "Failed to delete file",
		})
	}

	// Try to delete physical file (non-critical if it fails)
	if err := os.Remove(file.S3Key); err != nil {
		slog.Warn("Failed to delete physical file", "error", err, "file_path", file.S3Key)
		// Don't return error as database deletion succeeded
	}

	return c.JSON(fiber.Map{
		"status": "success",
	})
}

func (h *ApiHandler) DeleteFolder(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	folderIDStr := c.FormValue("folder_id")
	if folderIDStr == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status": "error",
			"error":  "Folder ID is required",
		})
	}

	folderID, err := uuid.Parse(folderIDStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status": "error",
			"error":  "Invalid folder ID",
		})
	}

	if err := h.db.DeleteFolder(c.Context(), userID, folderID); err != nil {
		slog.Error("Failed to delete folder", "error", err, "folder_id", folderID)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status": "error",
			"error":  "Failed to delete folder",
		})
	}

	return c.JSON(fiber.Map{
		"status": "success",
	})
}
