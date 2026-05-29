package identity_provider

import (
	"context"
	"net/http"
	"strings"

	"github.com/gddisney/logger"
	"github.com/gddisney/secure_policy"
)

type contextKey string
// Unexported key prevents cross-package collision and type dropping
const subjectContextKey contextKey = "subject_id"

// WithSubject safely injects the identity string into the context
func WithSubject(ctx context.Context, subject string) context.Context {
	return context.WithValue(ctx, subjectContextKey, subject)
}

// GetSubject safely extracts the identity string from the context
func GetSubject(ctx context.Context) string {
	if sub, ok := ctx.Value(subjectContextKey).(string); ok {
		return sub
	}
	return ""
}

func EnforcePolicy(pe *secure_policy.PolicyEngine, sm *secure_policy.SessionManager, sysLog *logger.LogDispatcher, action, resource string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("session_id")
			if err != nil || cookie.Value == "" {
				if sysLog != nil { sysLog.Error("Authentication rejected: Missing session cookie") }
				http.Error(w, "Authentication Required", http.StatusUnauthorized)
				return
			}

			rawToken := cookie.Value
			if strings.HasPrefix(rawToken, "user_session_") {
				rawToken = strings.TrimPrefix(rawToken, "user_session_")
			}

			subjectID, err := sm.ValidateCookieToken(rawToken)
			if err != nil {
				http.SetCookie(w, &http.Cookie{Name: "session_id", Value: "", Path: "/", MaxAge: -1})
				http.Error(w, "Session Invalid or Revoked", http.StatusUnauthorized)
				return
			}

			cleanSubject := strings.TrimSpace(subjectID)

			if !pe.Evaluate([]byte(cleanSubject), action, resource, map[string]string{}) {
				if sysLog != nil { sysLog.Audit(cleanSubject, "ACCESS_DENIED", "Policy violation: Attempted '"+action+"' on '"+resource+"'") }
				http.Error(w, "Forbidden by Zero-Trust Policy", http.StatusForbidden)
				return
			}

			if sysLog != nil { sysLog.Info("Access granted to " + cleanSubject + " for " + r.URL.Path) }

			// Use the idiomatic accessor to bind context securely
			ctx := WithSubject(r.Context(), cleanSubject)
			next(w, r.WithContext(ctx))
		}
	}
}
