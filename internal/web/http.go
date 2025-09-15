package web

import (
	"fmt"
	"log/slog"
	"net/http"
)

type HandlerFunc func(w http.ResponseWriter, r *http.Request) error
type GroupFunc func(group *Router)
type MiddlewareFunc func(next HandlerFunc) HandlerFunc

type Route struct {
	Path    string
	Method  string
	Handler HandlerFunc
}

type Router struct {
	Path        string
	Routes      map[string]map[string]Route
	StaticPaths map[string]string
}

func NewRouter() Router {
	return Router{
		Path:        "",
		Routes:      make(map[string]map[string]Route),
		StaticPaths: make(map[string]string),
	}
}

func (r *Router) Any(path, method string, handler HandlerFunc, middlewares ...MiddlewareFunc) {
	path = r.Path + path

	if _, exists := r.Routes[path]; !exists {
		r.Routes[path] = make(map[string]Route)
	}

	// Add each handle as a separate route for the same path and method
	if _, exists := r.Routes[path][method]; exists {
		panic(fmt.Sprintf("route already exists: %s %s", method, path))
	}

	// Wrap handler with middlewares
	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}

	r.Routes[path][method] = Route{
		Path:    path,
		Method:  method,
		Handler: handler,
	}
}

func (r *Router) OPTIONS(path string, handler HandlerFunc, middlewares ...MiddlewareFunc) {
	r.Any(path, http.MethodOptions, handler, middlewares...)
}

func (r *Router) GET(path string, handler HandlerFunc, middlewares ...MiddlewareFunc) {
	r.Any(path, http.MethodGet, handler, middlewares...)
}

func (r *Router) POST(path string, handler HandlerFunc, middlewares ...MiddlewareFunc) {
	r.Any(path, http.MethodPost, handler, middlewares...)
}

func (r *Router) PATCH(path string, handler HandlerFunc, middlewares ...MiddlewareFunc) {
	r.Any(path, http.MethodPatch, handler, middlewares...)
}

func (r *Router) PUT(path string, handler HandlerFunc, middlewares ...MiddlewareFunc) {
	r.Any(path, http.MethodPut, handler, middlewares...)
}

func (r *Router) DELETE(path string, handler HandlerFunc, middlewares ...MiddlewareFunc) {
	r.Any(path, http.MethodDelete, handler, middlewares...)
}

func (r *Router) Static(path, dir string, middlewares ...MiddlewareFunc) {
	// Ensure path ends with / for proper prefix matching
	if path[len(path)-1] != '/' {
		path += "/"
	}

	// Store the static path mapping
	r.StaticPaths[path] = dir

	// Note: Actual file serving is handled in the Server.ListenAndServe method
	// using http.FileServer and http.StripPrefix for proper static file handling
}

func (r *Router) Group(path string, grouper GroupFunc, middlewares ...MiddlewareFunc) {
	subRouter := Router{
		Path:   path,
		Routes: make(map[string]map[string]Route),
	}

	// Adds routes to group
	grouper(&subRouter)

	// Add routes to parent router
	for path, routePerMethod := range subRouter.Routes {
		for method, route := range routePerMethod {
			r.Any(path, method, route.Handler, middlewares...)
		}
	}
}

type Server struct {
	logger *slog.Logger
	Router Router
}

func NewServer(logger *slog.Logger, router Router) Server {
	return Server{
		logger: logger,
		Router: router,
	}
}

func (s *Server) ListenAndServe(addr string) error {
	// Register routes
	mux := http.NewServeMux()

	// Handle static files first (higher priority)
	for path, dir := range s.Router.StaticPaths {
		fileServer := http.FileServer(http.Dir(dir))
		mux.Handle(path, http.StripPrefix(path, fileServer))
	}

	// Register dynamic routes
	for path, routePerMethod := range s.Router.Routes {
		// Method aware request handler
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			route, exists := routePerMethod[r.Method]
			if !exists {
				http.Error(w, "Not Found", http.StatusNotFound)
				return
			}

			// Call the route handler
			if err := route.Handler(w, r); err != nil {
				s.logger.Error("failed to handle request", "error", err, "path", path, "method", r.Method)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		})
	}

	s.logger.Info("server starting", "addr", addr)
	return http.ListenAndServe(addr, mux)
}
