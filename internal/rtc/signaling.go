package rtc

// type SignalingServer struct {
// 	logger      *slog.Logger
// 	rooms       map[string]*Room
// 	roomsMutex  sync.RWMutex
// 	connections map[*websocket.Conn]string // Map connections to user IDs
// 	connMutex   sync.RWMutex
// }

// type Room struct {
// 	ID           string
// 	Participants map[string]*websocket.Conn // Map user IDs to connections
// 	mutex        sync.RWMutex
// }

// type SignalMessage struct {
// 	Type    string          `json:"type"`
// 	From    string          `json:"from"`
// 	To      string          `json:"to,omitempty"`
// 	RoomID  string          `json:"roomId,omitempty"`
// 	Payload json.RawMessage `json:"payload,omitempty"`
// }

// func NewSignalingServer(logger *slog.Logger) *SignalingServer {
// 	return &SignalingServer{
// 		logger:      logger,
// 		rooms:       make(map[string]*Room),
// 		connections: make(map[*websocket.Conn]string),
// 	}
// }

// func (s *SignalingServer) HandleConnection(c *websocket.Conn) {
// 	// Extract user ID from context (set during authentication)
// 	userID := c.Locals("user_id").(uuid.UUID).String()

// 	// Register connection
// 	s.connMutex.Lock()
// 	s.connections[c] = userID
// 	s.connMutex.Unlock()

// 	s.logger.Info("WebSocket connection established", "user_id", userID)

// 	// Handle incoming messages
// 	for {
// 		messageType, msg, err := c.ReadMessage()
// 		if err != nil {
// 			s.handleDisconnect(c)
// 			break
// 		}

// 		if messageType == websocket.TextMessage {
// 			s.handleSignalingMessage(c, msg)
// 		}
// 	}
// }

// func (s *SignalingServer) handleSignalingMessage(c *websocket.Conn, msg []byte) {
// 	var signal SignalMessage
// 	if err := json.Unmarshal(msg, &signal); err != nil {
// 		s.logger.Error("Failed to parse signaling message", "error", err)
// 		return
// 	}

// 	s.connMutex.RLock()
// 	fromUserID := s.connections[c]
// 	s.connMutex.RUnlock()

// 	// Set the actual sender ID
// 	signal.From = fromUserID

// 	switch signal.Type {
// 	case "join":
// 		s.handleJoinRoom(c, signal.RoomID, fromUserID)
// 	case "leave":
// 		s.handleLeaveRoom(c, signal.RoomID, fromUserID)
// 	case "offer", "answer", "ice-candidate":
// 		s.relayMessage(signal)
// 	}
// }

// func (s *SignalingServer) handleJoinRoom(c *websocket.Conn, roomID, userID string) {
// 	s.roomsMutex.Lock()
// 	defer s.roomsMutex.Unlock()

// 	room, exists := s.rooms[roomID]
// 	if !exists {
// 		// Create a new room if it doesn't exist
// 		room = &Room{
// 			ID:           roomID,
// 			Participants: make(map[string]*websocket.Conn),
// 		}
// 		s.rooms[roomID] = room
// 	}

// 	// Add user to room
// 	room.mutex.Lock()
// 	room.Participants[userID] = c

// 	// Notify others in the room
// 	for participantID, conn := range room.Participants {
// 		if participantID != userID {
// 			notifyMsg := SignalMessage{
// 				Type:   "user-joined",
// 				From:   userID,
// 				RoomID: roomID,
// 			}

// 			msgBytes, _ := json.Marshal(notifyMsg)
// 			conn.WriteMessage(websocket.TextMessage, msgBytes)
// 		}
// 	}
// 	room.mutex.Unlock()

// 	// Send room info to the joining user
// 	roomInfoMsg := SignalMessage{
// 		Type:   "room-info",
// 		RoomID: roomID,
// 	}

// 	// Add current participants to payload
// 	var participantList []string
// 	room.mutex.RLock()
// 	for pid := range room.Participants {
// 		if pid != userID {
// 			participantList = append(participantList, pid)
// 		}
// 	}
// 	room.mutex.RUnlock()

// 	participantsJSON, _ := json.Marshal(participantList)
// 	roomInfoMsg.Payload = participantsJSON

// 	msgBytes, _ := json.Marshal(roomInfoMsg)
// 	c.WriteMessage(websocket.TextMessage, msgBytes)
// }

// func (s *SignalingServer) handleLeaveRoom(c *websocket.Conn, roomID, userID string) {
// 	s.roomsMutex.RLock()
// 	room, exists := s.rooms[roomID]
// 	s.roomsMutex.RUnlock()

// 	if !exists {
// 		return
// 	}

// 	// Remove user from room
// 	room.mutex.Lock()
// 	delete(room.Participants, userID)

// 	// Check if room is empty
// 	if len(room.Participants) == 0 {
// 		s.roomsMutex.Lock()
// 		delete(s.rooms, roomID)
// 		s.roomsMutex.Unlock()
// 	} else {
// 		// Notify others
// 		for _, conn := range room.Participants {
// 			notifyMsg := SignalMessage{
// 				Type:   "user-left",
// 				From:   userID,
// 				RoomID: roomID,
// 			}

// 			msgBytes, _ := json.Marshal(notifyMsg)
// 			conn.WriteMessage(websocket.TextMessage, msgBytes)
// 		}
// 	}
// 	room.mutex.Unlock()
// }

// func (s *SignalingServer) relayMessage(signal SignalMessage) {
// 	s.roomsMutex.RLock()
// 	room, exists := s.rooms[signal.RoomID]
// 	s.roomsMutex.RUnlock()

// 	if !exists {
// 		return
// 	}

// 	room.mutex.RLock()
// 	targetConn, exists := room.Participants[signal.To]
// 	room.mutex.RUnlock()

// 	if !exists {
// 		return
// 	}

// 	msgBytes, _ := json.Marshal(signal)
// 	targetConn.WriteMessage(websocket.TextMessage, msgBytes)
// }

// func (s *SignalingServer) handleDisconnect(c *websocket.Conn) {
// 	s.connMutex.RLock()
// 	userID, exists := s.connections[c]
// 	s.connMutex.RUnlock()

// 	if !exists {
// 		return
// 	}

// 	// Remove from connections map
// 	s.connMutex.Lock()
// 	delete(s.connections, c)
// 	s.connMutex.Unlock()

// 	// Remove from all rooms
// 	s.roomsMutex.RLock()
// 	for roomID, room := range s.rooms {
// 		room.mutex.RLock()
// 		_, inRoom := room.Participants[userID]
// 		room.mutex.RUnlock()

// 		if inRoom {
// 			s.handleLeaveRoom(c, roomID, userID)
// 		}
// 	}
// 	s.roomsMutex.RUnlock()

// 	s.logger.Info("WebSocket connection closed", "user_id", userID)
// }
