package identity_provider

import (
	"context"
	"net/http"

	"github.com/gddisney/logger"
	"github.com/gddisney/secure_policy"
)
type contextKey string
const SubjectContextKey contextKey = "subject_id"

// EnforcePolicy intercepts incoming requests, validates the cryptographic session,
// evaluates the Zero-Trust policy, and logs the access attempt to the Pub/Sub dispatcher.
func EnforcePolicy(pe *secure_policy.PolicyEngine, sm *secure_policy.SessionManager, sysLog *logger.LogDispatcher, action, resource string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("session_id")
			if err != nil || cookie.Value == "" {
				if sysLog != nil { sysLog.Error("Authentication rejected: Missing or empty session cookie on path " + r.URL.Path) }
				http.Error(w, "Authentication Required", http.StatusUnauthorized)
				return
			}

			subjectID, err := sm.ValidateCookieToken(cookie.Value)
			if err != nil {
				if sysLog != nil { sysLog.Error("Session invalid or revoked for token on path: " + r.URL.Path) }
				http.SetCookie(w, &http.Cookie{
					Name: "session_id", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
				})
				http.Error(w, "Session Invalid or Revoked", http.StatusUnauthorized)
				return
			}

			if !pe.Evaluate([]byte(subjectID), action, resource, map[string]string{}) {
				if sysLog != nil { 
					sysLog.Audit(subjectID, "ACCESS_DENIED", "Policy violation: Attempted '"+action+"' on '"+resource+"'") 
				}
				http.Error(w, "Forbidden by Zero-Trust Policy", http.StatusForbidden)
				return
			}

			// Successful access is logged as an Info event
			if sysLog != nil { 
				sysLog.Info("Access granted to " + subjectID + " for " + r.URL.Path) 
			}

			ctx := context.WithValue(r.Context(), SubjectContextKey, subjectID)
			next(w, r.WithContext(ctx))
		}
	}
}
