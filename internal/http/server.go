package http

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"
)

type Server struct {
	logger *slog.Logger
	Router Router
	server http.Server
}

func NewServer(logger *slog.Logger, router Router) Server {
	return Server{
		logger: logger,
		Router: router,
		server: http.Server{
			ReadTimeout:  10 * time.Second, // max time to read request (headers + body)
			WriteTimeout: 10 * time.Second, // max time to write response
			IdleTimeout:  60 * time.Second, // keep-alive connections
		},
	}
}

func (s *Server) ListenAndServe(addr string) error {
	// Register routes
	mux := http.NewServeMux()

	// Handle static files first (higher priority)
	for path, dir := range s.Router.StaticPaths {
		// Ensure path exists
		_, err := os.Stat(dir)
		if os.IsNotExist(err) {
			return fmt.Errorf("static file directory does not exist: %s", dir)
		}

		// Serve static files
		fileServer := http.FileServer(http.Dir(dir))
		mux.Handle(path, http.StripPrefix(path, fileServer))
	}

	// Register dynamic routes
	for path, routePerMethod := range s.Router.Routes {
		// Method aware request handler
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			route, exists := routePerMethod[Method(r.Method)]
			if !exists {
				http.Error(w, "Not Found", http.StatusNotFound)
				return
			}

			// Call the route handler
			if err := route.Handler(r.Context(), &Request{Request: r}, &Response{Writer: w}); err != nil {
				s.logger.Error("failed to handle request", "error", err, "path", path, "method", r.Method)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		})
	}

	s.server.Addr = addr
	s.server.Handler = mux

	return s.server.ListenAndServe()
}
