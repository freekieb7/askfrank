package http

import (
	"context"
	"fmt"
)

type HandlerFunc func(ctx context.Context, req *Request, res *Response) error
type GroupFunc func(group *Router)
type MiddlewareFunc func(next HandlerFunc) HandlerFunc

type Route struct {
	Path    string
	Method  Method
	Handler HandlerFunc
}

type Router struct {
	Path        string
	Routes      map[string]map[Method]Route
	StaticPaths map[string]string
}

func NewRouter() Router {
	return Router{
		Path:        "",
		Routes:      make(map[string]map[Method]Route),
		StaticPaths: make(map[string]string),
	}
}

func (r *Router) Any(path string, method Method, handler HandlerFunc, middlewares ...MiddlewareFunc) {
	path = r.Path + path

	if _, exists := r.Routes[path]; !exists {
		r.Routes[path] = make(map[Method]Route)
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
	r.Any(path, MethodOptions, handler, middlewares...)
}

func (r *Router) GET(path string, handler HandlerFunc, middlewares ...MiddlewareFunc) {
	r.Any(path, MethodGet, handler, middlewares...)
}

func (r *Router) POST(path string, handler HandlerFunc, middlewares ...MiddlewareFunc) {
	r.Any(path, MethodPost, handler, middlewares...)
}

func (r *Router) PATCH(path string, handler HandlerFunc, middlewares ...MiddlewareFunc) {
	r.Any(path, MethodPatch, handler, middlewares...)
}

func (r *Router) PUT(path string, handler HandlerFunc, middlewares ...MiddlewareFunc) {
	r.Any(path, MethodPut, handler, middlewares...)
}

func (r *Router) DELETE(path string, handler HandlerFunc, middlewares ...MiddlewareFunc) {
	r.Any(path, MethodDelete, handler, middlewares...)
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
		Routes: make(map[string]map[Method]Route),
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
