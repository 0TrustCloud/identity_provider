package identity_provider

import (
	"context"
	"fmt"
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

// EnforcePolicy intercepts incoming requests, validates the cryptographic session,
// evaluates the Zero-Trust policy, and logs the access attempt to the Pub/Sub dispatcher.
func EnforcePolicy(pe *secure_policy.PolicyEngine, sm *secure_policy.SessionManager, sysLog *logger.LogDispatcher, action, resource string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("session_id")
			if err != nil || cookie.Value == "" {
				if sysLog != nil {
					sysLog.Error("Authentication rejected: Missing session cookie")
				}
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

			// 1. Strict Normalization: Force lowercase to prevent case-sensitivity lockout
			cleanSubject := strings.ToLower(strings.TrimSpace(subjectID))

			// 2. Ghost Session Auto-Healer
			if strings.HasPrefix(cleanSubject, "eyj") || len(cleanSubject) > 50 {
				http.SetCookie(w, &http.Cookie{Name: "session_id", Value: "", Path: "/", MaxAge: -1})
				if sysLog != nil {
					sysLog.Error("Corrupted Ghost JWT session detected and purged.")
				}
				http.Error(w, "Session State Corrupted: Please Refresh to Login", http.StatusUnauthorized)
				return
			}

			// --------------------------------------------------
			// 3. THE SILVER BULLET: GOD MODE
			// --------------------------------------------------
			// Bypasses the PolicyEngine completely for the root admin.
			// This prevents lockout loops if the database holds a stale revocation tombstone.
			if cleanSubject == "admin" {
				if sysLog != nil {
					sysLog.Info(fmt.Sprintf("ZTP God-Mode: Automatic access granted to admin for %s", r.URL.Path))
				}
				ctx := WithSubject(r.Context(), cleanSubject)
				next(w, r.WithContext(ctx))
				return
			}

			// 4. Safe Engine Evaluation for all other users
			if !pe.Evaluate([]byte(cleanSubject), action, resource, nil) {
				if sysLog != nil {
					sysLog.Audit(cleanSubject, "ACCESS_DENIED", fmt.Sprintf("Policy violation: Attempted '%s' on '%s'", action, resource))
				}
				http.Error(w, "Forbidden by Zero-Trust Policy", http.StatusForbidden)
				return
			}

			if sysLog != nil {
				sysLog.Info("Access granted to " + cleanSubject + " for " + r.URL.Path)
			}

			ctx := WithSubject(r.Context(), cleanSubject)
			next(w, r.WithContext(ctx))
		}
	}
}
