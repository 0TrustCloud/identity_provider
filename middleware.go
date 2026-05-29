package identity_provider

import (
	"context"
	"net/http"
	"strings"

	"github.com/gddisney/logger"
	"github.com/gddisney/secure_policy"
)

type contextKey string

// SubjectContextKey is the universal context key used to pass the verified, 
// human-readable username down to downstream route handlers and templates.
const SubjectContextKey contextKey = "subject_id"

// EnforcePolicy intercepts incoming requests, validates the cryptographic session,
// evaluates the Zero-Trust policy, and logs the access attempt to the Pub/Sub dispatcher.
func EnforcePolicy(pe *secure_policy.PolicyEngine, sm *secure_policy.SessionManager, sysLog *logger.LogDispatcher, action, resource string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("session_id")
			if err != nil || cookie.Value == "" {
				if sysLog != nil { 
					sysLog.Error("Authentication rejected: Missing or empty session cookie on path " + r.URL.Path) 
				}
				http.Error(w, "Authentication Required", http.StatusUnauthorized)
				return
			}

			// FIX: Clean up any structural framework prefix contamination immediately 
			// before passing the token string to the cryptographic validation engine.
			rawToken := cookie.Value
			if strings.HasPrefix(rawToken, "user_session_") {
				rawToken = strings.TrimPrefix(rawToken, "user_session_")
			}

			subjectID, err := sm.ValidateCookieToken(rawToken)
			if err != nil {
				if sysLog != nil { 
					sysLog.Error("Session invalid or revoked for token on path: " + r.URL.Path) 
				}
				// Clear out the corrupted/expired client session token state
				http.SetCookie(w, &http.Cookie{
					Name:     "session_id",
					Value:    "",
					Path:     "/",
					MaxAge:   -1,
					HttpOnly: true,
					Secure:   true,
					SameSite: http.SameSiteStrictMode,
				})
				http.Error(w, "Session Invalid or Revoked", http.StatusUnauthorized)
				return
			}

			// FIX: Ensure we have a strictly sanitized, un-prefixed user string (e.g., "admin")
			// rather than allowing raw token strings to bleed into policy engine evaluations.
			cleanSubject := strings.TrimSpace(subjectID)

			if !pe.Evaluate([]byte(cleanSubject), action, resource, map[string]string{}) {
				if sysLog != nil { 
					sysLog.Audit(cleanSubject, "ACCESS_DENIED", "Policy violation: Attempted '"+action+"' on '"+resource+"'") 
				}
				http.Error(w, "Forbidden by Zero-Trust Policy", http.StatusForbidden)
				return
			}

			// Successful access is logged as an Info event using the verified subject string
			if sysLog != nil { 
				sysLog.Info("Access granted to " + cleanSubject + " for " + r.URL.Path) 
			}

			// Explicitly bind the authenticated human user string to the request context
			ctx := context.WithValue(r.Context(), SubjectContextKey, cleanSubject)
			next(w, r.WithContext(ctx))
		}
	}
}
