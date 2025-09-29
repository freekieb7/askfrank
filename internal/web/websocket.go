package web

import (
	"hp/internal/rtc"
	"hp/internal/session"
	"log/slog"
	"net/http"

	"github.com/gorilla/websocket"
)

type MeetingHandler struct {
	logger          *slog.Logger
	signalingServer *rtc.SignalingServer
	sessionStore    *session.Store
	upgrader        websocket.Upgrader
}

func NewMeetingHandler(logger *slog.Logger, signalingServer *rtc.SignalingServer, sessionStore *session.Store) MeetingHandler {
	return MeetingHandler{
		logger:          logger,
		signalingServer: signalingServer,
		sessionStore:    sessionStore,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				// In production, you should check the origin properly
				return true
			},
		},
	}
}

func (h *MeetingHandler) HandleRTCConnection(w http.ResponseWriter, r *http.Request) error {
	// Get user session (session should be available in context through middleware)
	sessionData, err := h.sessionStore.Get(r.Context(), r)
	if err != nil {
		h.logger.Error("Invalid session in WebSocket request", "error", err)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return err
	}

	// Upgrade the HTTP connection to WebSocket
	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.logger.Error("Failed to upgrade WebSocket connection", "error", err)
		return err
	}
	defer conn.Close()

	// Extract user ID from session
	userID := sessionData.UserID.String()

	h.logger.Info("WebSocket connection established for RTC", "user_id", userID)

	// Handle the WebSocket connection through the signaling server
	h.signalingServer.HandleConnection(conn, userID)

	return nil
}

type ChatHandler struct {
	logger    *slog.Logger
	upgrader  websocket.Upgrader
	clients   map[*websocket.Conn]bool
	broadcast chan []byte
}

func NewChatHandler(logger *slog.Logger) *ChatHandler {
	return &ChatHandler{
		logger:    logger,
		upgrader:  websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }},
		clients:   make(map[*websocket.Conn]bool),
		broadcast: make(chan []byte),
	}
}

func (h *ChatHandler) HandleChatWebSocket(w http.ResponseWriter, r *http.Request) error {
	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return err
	}
	defer conn.Close()

	h.clients[conn] = true

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			delete(h.clients, conn)
			break
		}

		// Broadcast to all clients
		for client := range h.clients {
			if err := client.WriteMessage(websocket.TextMessage, message); err != nil {
				client.Close()
				delete(h.clients, client)
			}
		}
	}

	return nil
}
