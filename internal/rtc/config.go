package rtc

type RTCConfig struct {
	StunServers []string
	TurnServers []TurnServer
}

type TurnServer struct {
	URL      string
	Username string
	Password string
}

func DefaultRTCConfig() RTCConfig {
	return RTCConfig{
		StunServers: []string{
			"stun:stun.l.google.com:19302",
			"stun:stun1.l.google.com:19302",
		},
		TurnServers: []TurnServer{
			// Free TURN servers for testing (replace with your own in production)
			{
				URL:      "turn:openrelay.metered.ca:80",
				Username: "openrelayproject",
				Password: "openrelayproject",
			},
			{
				URL:      "turn:openrelay.metered.ca:443",
				Username: "openrelayproject",
				Password: "openrelayproject",
			},
			{
				URL:      "turn:openrelay.metered.ca:443?transport=tcp",
				Username: "openrelayproject",
				Password: "openrelayproject",
			},
		},
	}
}

// GetICEServers returns the ICE servers configuration for WebRTC
func (c RTCConfig) GetICEServers() []map[string]interface{} {
	var iceServers []map[string]interface{}

	// Add STUN servers
	for _, stunURL := range c.StunServers {
		iceServers = append(iceServers, map[string]interface{}{
			"urls": stunURL,
		})
	}

	// Add TURN servers
	for _, turnServer := range c.TurnServers {
		iceServers = append(iceServers, map[string]interface{}{
			"urls":       turnServer.URL,
			"username":   turnServer.Username,
			"credential": turnServer.Password,
		})
	}

	return iceServers
}
