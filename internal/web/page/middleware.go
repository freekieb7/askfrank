package page

import (
	"context"
	"hp/internal/config"
	"hp/internal/session"
	"hp/internal/util"
	"hp/internal/web"
	"log/slog"
	"net/http"
)

func SessionMiddleware(cfg *config.Config, logger *slog.Logger, sessionStore *session.Store) web.MiddlewareFunc {
	return func(next web.HandlerFunc) web.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) error {
			ctx := r.Context()

			cookie, err := r.Cookie(sessionStore.Config.CookieName)
			if err != nil || cookie.Value == "" {
				// No session cookie, create new session
				session, err := sessionStore.Create(r.Context(), w, r)
				if err != nil {
					logger.Error("middleware: failed to create session", "error", err)
					return JSONResponse(w, http.StatusInternalServerError, JSONResponseBody{
						Status:  APIResponseStatusError,
						Message: "Internal server error",
					})
				}

				// Add session data to context
				ctx = context.WithValue(ctx, config.SessionContextKey, session)

				return next(w, r.WithContext(ctx))
			}

			// Existing session, retrieve it
			session, err := sessionStore.Get(ctx, r)
			if err != nil {
				// Handle invalid/expired sessions by creating new one
				logger.Warn("middleware: invalid session, creating new one", "error", err)
				session, err := sessionStore.Create(r.Context(), w, r)
				if err != nil {
					logger.Error("middleware: failed to create session", "error", err)
					return JSONResponse(w, http.StatusInternalServerError, JSONResponseBody{
						Status:  APIResponseStatusError,
						Message: "Internal server error",
					})
				}
				ctx = context.WithValue(ctx, config.SessionContextKey, session)
				return next(w, r.WithContext(ctx))
			}

			// Add session data to context
			ctx = context.WithValue(ctx, config.SessionContextKey, session)

			return next(w, r.WithContext(ctx))
		}
	}
}

func AuthenticatedMiddleware(sessionStore *session.Store) web.MiddlewareFunc {
	return func(next web.HandlerFunc) web.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) error {
			ctx := r.Context()

			sessValue := ctx.Value(config.SessionContextKey)
			if sessValue == nil {
				return Redirect(w, r, "/login", http.StatusSeeOther)
			}

			sess, ok := sessValue.(session.Session)
			if !ok {
				return Redirect(w, r, "/login", http.StatusSeeOther)
			}

			if !sess.UserID.IsSet {
				return Redirect(w, r, "/login", http.StatusSeeOther)
			}

			return next(w, r)
		}
	}
}

func CSRFMiddleware(logger *slog.Logger, sessionStore *session.Store) web.MiddlewareFunc {
	return func(next web.HandlerFunc) web.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) error {
			ctx := r.Context()

			switch r.Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
				sessValue := ctx.Value(config.SessionContextKey)
				if sessValue == nil {
					logger.Error("middleware: session not found in context")
					return JSONResponse(w, http.StatusInternalServerError, JSONResponseBody{
						Status:  APIResponseStatusError,
						Message: "Internal server error",
					})
				}

				sess, ok := sessValue.(session.Session)
				if !ok {
					logger.Error("middleware: invalid session type in context")
					return JSONResponse(w, http.StatusInternalServerError, JSONResponseBody{
						Status:  APIResponseStatusError,
						Message: "Internal server error",
					})
				}

				// Only generate new token if one doesn't exist
				if sess.Data.CsrfToken == "" {
					csrfToken, err := util.GenerateRandomString(32)
					if err != nil {
						logger.Error("middleware: failed to generate CSRF token", "error", err)
						return JSONResponse(w, http.StatusInternalServerError, JSONResponseBody{
							Status:  APIResponseStatusError,
							Message: "Internal server error",
						})
					}

					sess.Data.CsrfToken = csrfToken
					if err := sessionStore.Update(ctx, sess); err != nil {
						logger.Error("middleware: failed to save session with CSRF token", "error", err)
						return JSONResponse(w, http.StatusInternalServerError, JSONResponseBody{
							Status:  APIResponseStatusError,
							Message: "Internal server error",
						})
					}

					// Add updated session to context
					ctx = context.WithValue(ctx, config.SessionContextKey, sess)
					r = r.WithContext(ctx)
				}
			default:
				// State-changing methods - validate CSRF token
				sessValue := ctx.Value(config.SessionContextKey)
				if sessValue == nil {
					logger.Warn("CSRF validation failed: session not found in context")
					return JSONResponse(w, http.StatusForbidden, JSONResponseBody{
						Status:  APIResponseStatusError,
						Message: "Session validation failed",
					})
				}

				sess, ok := sessValue.(session.Session)
				if !ok {
					logger.Warn("CSRF validation failed: invalid session type in context")
					return JSONResponse(w, http.StatusForbidden, JSONResponseBody{
						Status:  APIResponseStatusError,
						Message: "Session validation failed",
					})
				}

				if sess.Data.CsrfToken == "" {
					logger.Warn("CSRF validation failed: no token in session")
					return JSONResponse(w, http.StatusForbidden, JSONResponseBody{
						Status:  APIResponseStatusError,
						Message: "Security token not found",
					})
				}

				// Get CSRF token from request (check both header and form)
				csrfToken := r.Header.Get("X-CSRF-Token")
				if csrfToken == "" {
					csrfToken = r.FormValue("csrf_token")
				}

				if csrfToken == "" {
					logger.Warn("CSRF validation failed: no token in request")
					return JSONResponse(w, http.StatusForbidden, JSONResponseBody{
						Status:  APIResponseStatusError,
						Message: "Security token required",
					})
				}

				// Use constant-time comparison to prevent timing attacks
				if !util.SecureCompare(sess.Data.CsrfToken, csrfToken) {
					logger.Warn("CSRF validation failed: token mismatch")
					return JSONResponse(w, http.StatusForbidden, JSONResponseBody{
						Status:  APIResponseStatusError,
						Message: "Invalid security token",
					})
				}
			}

			return next(w, r.WithContext(ctx))
		}
	}
}
