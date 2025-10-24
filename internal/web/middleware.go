package web

import (
	"context"
	"fmt"
	"hp/internal/config"
	"hp/internal/i18n"
	"hp/internal/session"
	"hp/internal/util"
	"log/slog"
	"net/http"
)

func LocalizationMiddleware() MiddlewareFunc {
	// TODO preference language

	return func(next HandlerFunc) HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) error {
			// Set default language to Dutch
			ctx := context.WithValue(r.Context(), config.LanguageContextKey, i18n.NL)
			r = r.WithContext(ctx)
			return next(w, r)
		}
	}
}

func SessionMiddleware(logger *slog.Logger, sessionStore *session.Store) MiddlewareFunc {
	return func(next HandlerFunc) HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) error {
			// Get or create session using the store's GetOrCreate method
			session, err := sessionStore.GetOrCreate(r.Context(), w, r)
			if err != nil {
				logger.Error("failed to get or create session", "error", err)
				return fmt.Errorf("failed to get or create session: %w", err)
			}

			// Generate CSRF token if not present
			if session.Data.CsrfToken == "" {
				csrfToken, err := util.GenerateRandomString(32)
				if err != nil {
					logger.Error("failed to generate CSRF token", "error", err)
					return fmt.Errorf("failed to generate CSRF token: %w", err)
				}
				session.Data.CsrfToken = csrfToken

				// Save session with new CSRF token
				if err := sessionStore.Save(r.Context(), w, session); err != nil {
					logger.Error("failed to save session", "error", err)
					return fmt.Errorf("failed to save session: %w", err)
				}
			}

			// Add session data to context
			ctx := r.Context()
			ctx = context.WithValue(ctx, config.SessionContextKey, session.Token)
			ctx = context.WithValue(ctx, config.CSRFTokenContextKey, session.Data.CsrfToken)
			if session.UserID.IsSet {
				ctx = context.WithValue(ctx, config.UserIDContextKey, session.UserID.Val)
			}

			return next(w, r.WithContext(ctx))
		}
	}
}

func AuthenticatedSessionMiddleware(sessionStore *session.Store) MiddlewareFunc {
	return func(next HandlerFunc) HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) error {
			sess, err := sessionStore.Get(r.Context(), r)
			if err != nil {
				return fmt.Errorf("failed to get session: %w", err)
			}

			if !sess.UserID.IsSet {
				// Check if this is an AJAX request
				if isAjaxRequest(r) {
					return JSONResponse(w, http.StatusUnauthorized, JSONResponseBody{
						Status:  APIResponseStatusError,
						Message: "Authentication required",
					})
				}

				// For regular requests, redirect to login
				return Redirect(w, r, "/login", http.StatusSeeOther)
			}

			// Add user ID to context
			ctx := context.WithValue(r.Context(), config.UserIDContextKey, sess.UserID.Val)
			r = r.WithContext(ctx)

			return next(w, r)
		}
	}
}

// isAjaxRequest checks if the request is an AJAX request
func isAjaxRequest(r *http.Request) bool {
	// Check for common AJAX indicators
	return r.Header.Get("X-Requested-With") == "XMLHttpRequest" ||
		r.Header.Get("Accept") == "application/json" ||
		r.Header.Get("Content-Type") == "application/json"
}

func CSRFMiddleware(logger *slog.Logger, sessionStore *session.Store) MiddlewareFunc {
	return func(next HandlerFunc) HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) error {
			switch r.Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
				// Safe methods - ensure CSRF token exists in session
				sess, err := sessionStore.Get(r.Context(), r)
				if err != nil {
					return fmt.Errorf("failed to get session: %w", err)
				}

				// Generate new CSRF token if not present
				if sess.Data.CsrfToken == "" {
					csrfToken, err := util.GenerateRandomString(32)
					if err != nil {
						logger.Error("failed to generate CSRF token", "error", err)
						return fmt.Errorf("failed to generate CSRF token: %w", err)
					}

					sess.Data.CsrfToken = csrfToken
					if err := sessionStore.Save(r.Context(), w, sess); err != nil {
						logger.Error("failed to save session with CSRF token", "error", err)
						return fmt.Errorf("failed to save session: %w", err)
					}
				}

				// Add CSRF token to context
				ctx := context.WithValue(r.Context(), config.CSRFTokenContextKey, sess.Data.CsrfToken)
				r = r.WithContext(ctx)

			default:
				// State-changing methods - validate CSRF token
				sess, err := sessionStore.Get(r.Context(), r)
				if err != nil {
					logger.Warn("CSRF validation failed: could not get session", "error", err)
					return handleCSRFError(w, r, "Session validation failed")
				}

				if sess.Data.CsrfToken == "" {
					logger.Warn("CSRF validation failed: no token in session")
					return handleCSRFError(w, r, "Security token not found")
				}

				// Get CSRF token from request (try multiple sources)
				var csrfToken string
				if csrfToken = r.Header.Get("X-CSRF-Token"); csrfToken == "" {
					if csrfToken = r.Header.Get("X-Requested-With"); csrfToken == "" {
						if err := r.ParseForm(); err == nil {
							csrfToken = r.FormValue("_csrf")
						}
					}
				}

				if csrfToken == "" {
					logger.Warn("CSRF validation failed: no token in request")
					return handleCSRFError(w, r, "Security token required")
				}

				if sess.Data.CsrfToken != csrfToken {
					logger.Warn("CSRF token mismatch",
						"session_token_hash", hashToken(sess.Data.CsrfToken),
						"request_token_hash", hashToken(csrfToken),
						"user_agent", r.UserAgent(),
						"remote_addr", r.RemoteAddr)
					return handleCSRFError(w, r, "Invalid security token")
				}

				// Add CSRF token to context for valid requests
				ctx := context.WithValue(r.Context(), config.CSRFTokenContextKey, sess.Data.CsrfToken)
				r = r.WithContext(ctx)
			}

			return next(w, r)
		}
	}
}

// handleCSRFError returns appropriate error response based on request type
func handleCSRFError(w http.ResponseWriter, r *http.Request, message string) error {
	if isAjaxRequest(r) {
		return JSONResponse(w, http.StatusForbidden, JSONResponseBody{
			Status:  APIResponseStatusError,
			Message: message,
		})
	}

	// For non-AJAX requests, return a proper error page
	http.Error(w, message, http.StatusForbidden)
	return nil
}

// hashToken creates a simple hash of the token for logging (security - don't log full tokens)
func hashToken(token string) string {
	if len(token) < 8 {
		return "short_token"
	}
	return token[:4] + "****" + token[len(token)-4:]
}
