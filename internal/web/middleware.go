package web

import (
	"context"
	"log/slog"
	"slices"
	"time"

	"github.com/freekieb7/askfrank/internal/config"
	"github.com/freekieb7/askfrank/internal/database"
	"github.com/freekieb7/askfrank/internal/http"
	"github.com/freekieb7/askfrank/internal/oauth"
	"github.com/freekieb7/askfrank/internal/session"
	"github.com/freekieb7/askfrank/internal/util"
)

// ContentNegotiationMiddleware ensures that the client accepts JSON responses

func ContentNegotiationMiddleware() http.MiddlewareFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(ctx context.Context, req *http.Request, res *http.Response) error {
			acceptHeader := req.Header("Accept")
			if acceptHeader != "" && acceptHeader != "*/*" && acceptHeader != "application/json" {
				res.SetStatus(http.StatusNotAcceptable)
				return res.SendJSON(map[string]string{
					"error":   "Not Acceptable",
					"message": "Supported types: application/json",
				})
			}

			return next(ctx, req, res)
		}
	}
}

func AuthenticatedMiddleware(db *database.Database) http.MiddlewareFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(ctx context.Context, req *http.Request, res *http.Response) error {
			// Check if the user is authenticated via token (e.g., Bearer token)
			authHeader := req.Header("Authorization")
			if authHeader == "" {
				return ErrorResponse(res, http.StatusUnauthorized, "UNAUTHORIZED", "Missing Authorization header")
			}

			// For simplicity, we'll just check if it starts with "Bearer "
			if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
				return ErrorResponse(res, http.StatusUnauthorized, "UNAUTHORIZED", "Invalid Authorization header")
			}
			token := authHeader[7:]

			// Validate the token (this is a placeholder, implement your own logic)
			accessToken, err := db.GetOAuthAccessTokenByToken(ctx, token)
			if err != nil {
				return ErrorResponse(res, http.StatusUnauthorized, "UNAUTHORIZED", "Invalid token")
			}

			// Check if the token has expired
			if accessToken.ExpiresAt.Before(time.Now()) {
				return ErrorResponse(res, http.StatusUnauthorized, "UNAUTHORIZED", "Token has expired")
			}

			// Add user ID and scopes to context
			ctx = context.WithValue(ctx, config.AccessTokenContextKey, accessToken)

			return next(ctx, req, res)
		}
	}
}

func AuthorizedMiddleware(logger *slog.Logger, db *database.Database, requiredScopes []oauth.Scope) http.MiddlewareFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(ctx context.Context, req *http.Request, res *http.Response) error {
			accessToken := ctx.Value(config.AccessTokenContextKey).(database.OAuthAccessToken)

			scopes := make([]oauth.Scope, len(accessToken.Scopes))
			for idx, scope := range accessToken.Scopes {
				s, err := oauth.ScopeParse(scope)
				if err != nil {
					logger.Error("middleware: failed to parse scope", "error", err, "scope", scope)
					return ErrorResponse(res, http.StatusInternalServerError, "INTERNAL_SERVER_ERROR", "Internal server error")
				}
				scopes[idx] = s
			}

			// Check if the access token has the required scopes
			for _, requiredScope := range requiredScopes {
				if !slices.Contains(scopes, requiredScope) {
					return ErrorResponse(res, http.StatusForbidden, "FORBIDDEN", "Insufficient permissions")
				}
			}

			return next(ctx, req, res)
		}
	}
}

func SessionMiddleware(cfg *config.Config, logger *slog.Logger, sessionStore *session.Store) http.MiddlewareFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(ctx context.Context, req *http.Request, res *http.Response) error {
			cookie, err := req.Cookie(sessionStore.Config.CookieName)
			if err != nil || cookie.Value == "" {
				// No session cookie, create new session
				session, err := sessionStore.Create(ctx, req, res)
				if err != nil {
					logger.Error("middleware: failed to create session", "error", err)
					res.SetStatus(http.StatusInternalServerError)
					return res.SendJSON(JSONResponseBody{
						Status:  ResponseStatusError,
						Message: "Internal server error",
					})
				}

				// Add session data to context
				ctx = context.WithValue(ctx, config.SessionContextKey, session)

				return next(ctx, req, res)
			}

			// Existing session, retrieve it
			session, err := sessionStore.Get(ctx, req)
			if err != nil {
				// Handle invalid/expired sessions by creating new one
				logger.Warn("middleware: invalid session, creating new one", "error", err)
				session, err := sessionStore.Create(ctx, req, res)
				if err != nil {
					logger.Error("middleware: failed to create session", "error", err)
					res.SetStatus(http.StatusInternalServerError)
					return res.SendJSON(JSONResponseBody{
						Status:  ResponseStatusError,
						Message: "Internal server error",
					})
				}
				ctx = context.WithValue(ctx, config.SessionContextKey, session)
				return next(ctx, req, res)
			}

			// Add session data to context
			ctx = context.WithValue(ctx, config.SessionContextKey, session)

			return next(ctx, req, res)
		}
	}
}

func SignedInMiddleware(sessionStore *session.Store) http.MiddlewareFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(ctx context.Context, req *http.Request, res *http.Response) error {
			sessValue := ctx.Value(config.SessionContextKey)
			if sessValue == nil {
				return res.SendRedirect("/login", http.StatusSeeOther)
			}

			sess, ok := sessValue.(session.Session)
			if !ok {
				return res.SendRedirect("/login", http.StatusSeeOther)
			}

			if !sess.UserID.IsSet {
				return res.SendRedirect("/login", http.StatusSeeOther)
			}

			return next(ctx, req, res)
		}
	}
}

func CSRFMiddleware(logger *slog.Logger, sessionStore *session.Store) http.MiddlewareFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(ctx context.Context, req *http.Request, res *http.Response) error {
			switch req.Method() {
			case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
				sessValue := ctx.Value(config.SessionContextKey)
				if sessValue == nil {
					logger.Error("middleware: session not found in context")
					res.SetStatus(http.StatusInternalServerError)
					return res.SendJSON(JSONResponseBody{
						Status:  ResponseStatusError,
						Message: "Internal server error",
					})
				}

				sess, ok := sessValue.(session.Session)
				if !ok {
					logger.Error("middleware: invalid session type in context")
					res.SetStatus(http.StatusInternalServerError)
					return res.SendJSON(JSONResponseBody{
						Status:  ResponseStatusError,
						Message: "Internal server error",
					})
				}

				// Only generate new token if one doesn't exist
				if sess.Data.CsrfToken == "" {
					csrfToken, err := util.GenerateRandomString(32)
					if err != nil {
						logger.Error("middleware: failed to generate CSRF token", "error", err)
						res.SetStatus(http.StatusInternalServerError)
						return res.SendJSON(JSONResponseBody{
							Status:  ResponseStatusError,
							Message: "Internal server error",
						})
					}

					sess.Data.CsrfToken = csrfToken
					if err := sessionStore.Update(ctx, sess); err != nil {
						logger.Error("middleware: failed to save session with CSRF token", "error", err)
						res.SetStatus(http.StatusInternalServerError)
						return res.SendJSON(JSONResponseBody{
							Status:  ResponseStatusError,
							Message: "Internal server error",
						})
					}

					// Add updated session to context
					ctx = context.WithValue(ctx, config.SessionContextKey, sess)
				}
			default:
				// State-changing methods - validate CSRF token
				sessValue := ctx.Value(config.SessionContextKey)
				if sessValue == nil {
					logger.Warn("CSRF validation failed: session not found in context")
					res.SetStatus(http.StatusForbidden)
					return res.SendJSON(JSONResponseBody{
						Status:  ResponseStatusError,
						Message: "Session validation failed",
					})
				}

				sess, ok := sessValue.(session.Session)
				if !ok {
					logger.Warn("CSRF validation failed: invalid session type in context")
					res.SetStatus(http.StatusForbidden)
					return res.SendJSON(JSONResponseBody{
						Status:  ResponseStatusError,
						Message: "Session validation failed",
					})
				}

				if sess.Data.CsrfToken == "" {
					logger.Warn("CSRF validation failed: no token in session")
					res.SetStatus(http.StatusForbidden)
					return res.SendJSON(JSONResponseBody{
						Status:  ResponseStatusError,
						Message: "Security token not found",
					})
				}

				// Get CSRF token from request (check both header and form)
				csrfToken := req.Header("X-CSRF-Token")
				if csrfToken == "" {
					logger.Warn("CSRF validation failed: no token in request")
					res.SetStatus(http.StatusForbidden)
					return res.SendJSON(JSONResponseBody{
						Status:  ResponseStatusError,
						Message: "Security token required",
					})
				}

				// Use constant-time comparison to prevent timing attacks
				if !util.SecureCompare(sess.Data.CsrfToken, csrfToken) {
					logger.Warn("CSRF validation failed: token mismatch")
					res.SetStatus(http.StatusForbidden)
					return res.SendJSON(JSONResponseBody{
						Status:  ResponseStatusError,
						Message: "Invalid security token",
					})
				}
			}

			return next(ctx, req, res)
		}
	}
}
