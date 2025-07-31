package service

import (
	"askfrank/internal/model"
	"askfrank/internal/repository"
	"context"
	"log/slog"
	"net"
	"time"

	"github.com/google/uuid"
)

type AuditService struct {
	repo repository.Repository
}

func NewAuditService(repo repository.Repository) *AuditService {
	return &AuditService{repo: repo}
}

// AuditContext contains request context for audit logging
type AuditContext struct {
	UserID    *uuid.UUID
	IPAddress string
	UserAgent string
	SessionID string
}

func (s *AuditService) LogUserAction(ctx context.Context, entityType string, entityID uuid.UUID, action model.AuditAction, auditCtx AuditContext, oldValues, newValues map[string]interface{}) {
	auditLog := model.AuditLog{
		ID:         uuid.New(),
		UserID:     auditCtx.UserID,
		EntityType: entityType,
		EntityID:   entityID,
		Action:     action,
		OldValues:  oldValues,
		NewValues:  newValues,
		IPAddress:  auditCtx.IPAddress,
		UserAgent:  auditCtx.UserAgent,
		SessionID:  auditCtx.SessionID,
		CreatedAt:  time.Now(),
	}

	// Async logging for performance
	go func() {
		if err := s.repo.CreateAuditLog(context.Background(), auditLog); err != nil {
			slog.Error("Failed to log audit", "error", err, "entity_type", entityType, "action", action)
		}
	}()
}

func (s *AuditService) LogDocumentAccess(ctx context.Context, userID, documentID uuid.UUID, auditCtx AuditContext) {
	s.LogUserAction(ctx, "document", documentID, model.AuditActionRead, auditCtx, nil, nil)
}

func (s *AuditService) LogAuthenticationEvent(ctx context.Context, userID uuid.UUID, action model.AuditAction, auditCtx AuditContext) {
	sessionEntityID := uuid.New() // Generate session entity ID
	s.LogUserAction(ctx, "session", sessionEntityID, action, auditCtx, nil, nil)
}

func (s *AuditService) LogFolderAction(ctx context.Context, folderID uuid.UUID, action model.AuditAction, auditCtx AuditContext, oldValues, newValues map[string]interface{}) {
	s.LogUserAction(ctx, "folder", folderID, action, auditCtx, oldValues, newValues)
}

func (s *AuditService) LogDocumentAction(ctx context.Context, documentID uuid.UUID, action model.AuditAction, auditCtx AuditContext, oldValues, newValues map[string]interface{}) {
	s.LogUserAction(ctx, "document", documentID, action, auditCtx, oldValues, newValues)
}

// ExtractAuditContext creates audit context from request information
func ExtractAuditContext(userID *uuid.UUID, ip, userAgent, sessionID string) AuditContext {
	// Parse IP address
	ipAddr := ip
	if parsedIP := net.ParseIP(ip); parsedIP != nil {
		ipAddr = parsedIP.String()
	}

	return AuditContext{
		UserID:    userID,
		IPAddress: ipAddr,
		UserAgent: userAgent,
		SessionID: sessionID,
	}
}
