package middleware

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"github.com/thiagomontozo/netscope/backend/internal/domain"
	"log/slog"
	"net/http"
	"time"
)

type contextKey string

const (
	requestIDKey      contextKey = "request-id"
	organizationIDKey contextKey = "organization-id"
	userIDKey         contextKey = "user-id"
)

func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := make([]byte, 12)
		_, _ = rand.Read(value)
		id := hex.EncodeToString(value)
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey, id)))
	})
}
func RequestIDFrom(ctx context.Context) string {
	value, _ := ctx.Value(requestIDKey).(string)
	return value
}

type SessionStore interface {
	ValidateSession(context.Context, string) (domain.ID, domain.ID, error)
}

func SessionIdentity(store SessionStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("netscope_session")
			if err != nil {
				WriteError(w, r, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED", "a valid session is required")
				return
			}
			hash := sha256.Sum256([]byte(cookie.Value))
			org, user, err := store.ValidateSession(r.Context(), hex.EncodeToString(hash[:]))
			if err != nil {
				WriteError(w, r, http.StatusUnauthorized, "SESSION_INVALID", "the session is expired, revoked or disabled")
				return
			}
			ctx := context.WithValue(r.Context(), organizationIDKey, org)
			ctx = context.WithValue(ctx, userIDKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
func OrganizationID(ctx context.Context) domain.ID {
	value, _ := ctx.Value(organizationIDKey).(domain.ID)
	return value
}
func UserID(ctx context.Context) domain.ID {
	value, _ := ctx.Value(userIDKey).(domain.ID)
	return value
}
func AgentIdentity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			WriteError(w, r, http.StatusUnauthorized, "AGENT_IDENTITY_REQUIRED", "a verified agent client certificate is required")
			return
		}
		next.ServeHTTP(w, r)
	})
}
func AccessLog(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			started := time.Now()
			next.ServeHTTP(w, r)
			logger.InfoContext(r.Context(), "http request", "requestId", RequestIDFrom(r.Context()), "method", r.Method, "path", r.URL.Path, "durationMs", time.Since(started).Milliseconds())
		})
	}
}
