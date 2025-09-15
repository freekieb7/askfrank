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
			// Add your TURN servers here
			// Example:
			// {
			//     URL:      "turn:your-turn-server.com:3478",
			//     Username: "username",
			//     Password: "password",
			// },
		},
	}
}
