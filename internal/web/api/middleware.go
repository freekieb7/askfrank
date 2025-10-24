package api

import (
	"context"
	"hp/internal/config"
	"hp/internal/database"
	"hp/internal/web"
	"net/http"
	"time"
)

func AuthenticatedTokenMiddleware(db *database.Database) web.MiddlewareFunc {
	return func(next web.HandlerFunc) web.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) error {
			ctx := r.Context()

			// Check if the user is authenticated via token (e.g., Bearer token)
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				return ErrorResponse(w, http.StatusUnauthorized, http.StatusUnauthorized, "Missing Authorization header")
			}

			// For simplicity, we'll just check if it starts with "Bearer "
			if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
				return ErrorResponse(w, http.StatusUnauthorized, http.StatusUnauthorized, "Invalid Authorization header")
			}
			token := authHeader[7:]

			// Validate the token (this is a placeholder, implement your own logic)
			accessToken, err := db.GetOAuthAccessTokenByToken(ctx, token)
			if err != nil {
				return ErrorResponse(w, http.StatusUnauthorized, http.StatusUnauthorized, "Invalid token")
			}

			// Check if the token has expired
			if accessToken.ExpiresAt.Before(time.Now()) {
				return ErrorResponse(w, http.StatusUnauthorized, http.StatusUnauthorized, "Token has expired")
			}

			// Assuming the token is valid and corresponds to a user ID
			ctx = context.WithValue(ctx, config.UserIDContextKey, accessToken.UserID)
			r = r.WithContext(ctx)

			return next(w, r)
		}
	}
}
