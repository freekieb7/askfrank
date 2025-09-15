package web

import (
	"context"
	"errors"
	"fmt"
	"hp/internal/config"
	"hp/internal/database"
	"hp/internal/i18n"
	"hp/internal/session"
	"hp/internal/util"
	"log/slog"
	"net/http"
	"time"
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

func SessionMiddleware(sessionStore *session.Store) MiddlewareFunc {
	return func(next HandlerFunc) HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) error {
			cookie, err := r.Cookie(sessionStore.Config.CookieName)
			if err != nil {
				if !errors.Is(err, http.ErrNoCookie) {
					return fmt.Errorf("failed to get session cookie: %w", err)
				}

				// Create a new cookie
				sessionToken, err := util.RandomString(32)
				if err != nil {
					return fmt.Errorf("failed to generate session token: %w", err)
				}

				cookie := http.Cookie{
					Name:        sessionStore.Config.CookieName,
					Value:       sessionToken,
					Expires:     time.Now().Add(sessionStore.Config.ExpiresIn),
					Secure:      sessionStore.Config.CookieSecure,
					HttpOnly:    sessionStore.Config.CookieHTTPOnly,
					Path:        sessionStore.Config.Path,
					Partitioned: sessionStore.Config.CookieSecure,
					SameSite:    sessionStore.Config.CookieSameSite,
					MaxAge:      sessionStore.Config.CookieMaxAge,
					Domain:      sessionStore.Config.Domain,
				}

				// Add cookie to both request and response
				http.SetCookie(w, &cookie)
				r.AddCookie(&cookie)

				// Add session ID to context
				ctx := r.Context()
				ctx = context.WithValue(ctx, config.SessionContextKey, cookie.Value)
				r = r.WithContext(ctx)

				return next(w, r)
			}

			// Add session ID to context
			ctx := r.Context()
			ctx = context.WithValue(ctx, config.SessionContextKey, cookie.Value)
			r = r.WithContext(ctx)

			return next(w, r)
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

			if !sess.UserID.Some {
				return Redirect(w, r, "/login", http.StatusSeeOther)
			}

			return next(w, r)
		}
	}
}

func AuthenticatedTokenMiddleware(db *database.Database) MiddlewareFunc {
	return func(next HandlerFunc) HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) error {
			ctx := r.Context()

			// Check if the user is authenticated via token (e.g., Bearer token)
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				return JSONResponse(w, http.StatusUnauthorized, ApiResponse{
					Status:  APIResponseStatusError,
					Message: "Missing Authorization header",
				})
			}

			// For simplicity, we'll just check if it starts with "Bearer "
			if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
				return JSONResponse(w, http.StatusUnauthorized, ApiResponse{
					Status:  APIResponseStatusError,
					Message: "Invalid Authorization header",
				})
			}
			token := authHeader[7:]

			// Validate the token (this is a placeholder, implement your own logic)
			accessToken, err := db.GetOAuthAccessTokenByToken(ctx, token)
			if err != nil {
				return JSONResponse(w, http.StatusUnauthorized, ApiResponse{
					Status:  APIResponseStatusError,
					Message: "Invalid token",
				})
			}

			// Check if the token has expired
			if accessToken.ExpiresAt.Before(time.Now()) {
				return JSONResponse(w, http.StatusUnauthorized, ApiResponse{
					Status:  APIResponseStatusError,
					Message: "Token has expired",
				})
			}

			// Assuming the token is valid and corresponds to a user ID
			ctx = context.WithValue(ctx, config.UserIDContextKey, accessToken.UserID)
			r = r.WithContext(ctx)

			return next(w, r)
		}
	}
}

func CSRFMiddleware(logger *slog.Logger, sessionStore *session.Store) MiddlewareFunc {
	return func(next HandlerFunc) HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) error {
			switch r.Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
				// Generate new CSRF token for each safe request
				csrfToken, err := util.RandomString(32)
				if err != nil {
					return fmt.Errorf("failed to generate CSRF token: %w", err)
				}

				sess, err := sessionStore.Get(r.Context(), r)
				if err != nil {
					return fmt.Errorf("failed to get session: %w", err)
				}

				// Store the new CSRF token in the session
				sess.Data["csrf_token"] = csrfToken
				if err := sessionStore.Save(r.Context(), w, sess); err != nil {
					return fmt.Errorf("failed to save session: %w", err)
				}

				// Add CSRF token to context
				ctx := context.WithValue(r.Context(), config.CSRFTokenContextKey, csrfToken)
				r = r.WithContext(ctx)

			default:
				// Validate CSRF token for state-changing methods
				sess, err := sessionStore.Get(r.Context(), r)
				if err != nil {
					return fmt.Errorf("failed to get session: %w", err)
				}

				sessCSRFToken, ok := sess.Data["csrf_token"].(string)
				if !ok || sessCSRFToken == "" {
					return fmt.Errorf("CSRF token not found in session")
				}

				csrfToken := r.Header.Get("X-CSRF-Token")
				if csrfToken == "" {
					return fmt.Errorf("missing CSRF token")
				}

				if sessCSRFToken != csrfToken {
					logger.Warn("CSRF token mismatch", "session_token", sessCSRFToken, "request_token", csrfToken)
					return JSONResponse(w, http.StatusForbidden, ApiResponse{
						Status:  APIResponseStatusError,
						Message: "Invalid request please try again",
					})
				}

				// Generate new token after successful validation
				newCSRFToken, err := util.RandomString(32)
				if err != nil {
					return fmt.Errorf("failed to generate new CSRF token: %w", err)
				}

				sess.Data["csrf_token"] = newCSRFToken
				if err := sessionStore.Save(r.Context(), w, sess); err != nil {
					return fmt.Errorf("failed to save session: %w", err)
				}

				// Add new token to context for response
				ctx := context.WithValue(r.Context(), config.CSRFTokenContextKey, newCSRFToken)
				r = r.WithContext(ctx)
			}

			return next(w, r)
		}
	}
}
