package api

import (
	"context"
	"encoding/json"
	"hp/internal/config"
	"hp/internal/database"
	"hp/internal/oauth"
	"hp/internal/web"
	"log/slog"
	"net/http"
	"slices"
	"time"
)

// ContentNegotiationMiddleware ensures that the client accepts JSON responses

func ContentNegotiationMiddleware() web.MiddlewareFunc {
	return func(next web.HandlerFunc) web.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) error {
			acceptHeader := r.Header.Get("Accept")
			if acceptHeader != "" && acceptHeader != "*/*" && acceptHeader != "application/json" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotAcceptable)
				return json.NewEncoder(w).Encode(map[string]string{
					"error":   "Not Acceptable",
					"message": "Supported types: application/json",
				})
			}

			return next(w, r)
		}
	}
}

func AuthenticatedMiddleware(db *database.Database) web.MiddlewareFunc {
	return func(next web.HandlerFunc) web.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) error {
			ctx := r.Context()

			// Check if the user is authenticated via token (e.g., Bearer token)
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				return ErrorResponse(w, http.StatusUnauthorized, "UNAUTHORIZED", "Missing Authorization header")
			}

			// For simplicity, we'll just check if it starts with "Bearer "
			if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
				return ErrorResponse(w, http.StatusUnauthorized, "UNAUTHORIZED", "Invalid Authorization header")
			}
			token := authHeader[7:]

			// Validate the token (this is a placeholder, implement your own logic)
			accessToken, err := db.GetOAuthAccessTokenByToken(ctx, token)
			if err != nil {
				return ErrorResponse(w, http.StatusUnauthorized, "UNAUTHORIZED", "Invalid token")
			}

			// Check if the token has expired
			if accessToken.ExpiresAt.Before(time.Now()) {
				return ErrorResponse(w, http.StatusUnauthorized, "UNAUTHORIZED", "Token has expired")
			}

			// Add user ID and scopes to context
			ctx = context.WithValue(ctx, config.AccessTokenContextKey, accessToken)
			r = r.WithContext(ctx)

			return next(w, r)
		}
	}
}

func AuthorizedMiddleware(logger *slog.Logger, db *database.Database, requiredScopes []oauth.Scope) web.MiddlewareFunc {
	return func(next web.HandlerFunc) web.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) error {
			ctx := r.Context()

			accessToken := ctx.Value(config.AccessTokenContextKey).(database.OAuthAccessToken)

			scopes := make([]oauth.Scope, len(accessToken.Scopes))
			for idx, scope := range accessToken.Scopes {
				s, err := oauth.ScopeParse(scope)
				if err != nil {
					logger.Error("middleware: failed to parse scope", "error", err, "scope", scope)
					return ErrorResponse(w, http.StatusInternalServerError, "INTERNAL_SERVER_ERROR", "Internal server error")
				}
				scopes[idx] = s
			}

			// Check if the access token has the required scopes
			for _, requiredScope := range requiredScopes {
				if !slices.Contains(scopes, requiredScope) {
					return ErrorResponse(w, http.StatusForbidden, "FORBIDDEN", "Insufficient permissions")
				}
			}

			return next(w, r)
		}
	}
}
