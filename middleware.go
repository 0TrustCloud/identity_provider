package identity_provider

import (
	"context"
	"net/http"

	"github.com/gddisney/secure_policy"
)

type contextKey string
const SubjectContextKey contextKey = "subject_id"

// EnforcePolicy intercepts incoming requests, validates the cryptographic session,
// and evaluates the action against the Zero-Trust Policy Engine.
func EnforcePolicy(pe *secure_policy.PolicyEngine, sm *secure_policy.SessionManager, action, resource string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("session_id")
			if err != nil || cookie.Value == "" {
				http.Error(w, "Authentication Required", http.StatusUnauthorized)
				return
			}

			// Validate the JWT signature, expiration, and check DB blacklists (device & session)
			subjectID, err := sm.ValidateCookieToken(cookie.Value)
			if err != nil {
				// Destroy the invalid cookie
				http.SetCookie(w, &http.Cookie{
					Name: "session_id", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
				})
				http.Error(w, "Session Invalid or Revoked", http.StatusUnauthorized)
				return
			}

			// Evaluate ABAC/PBAC rules using the cryptographically verified subjectID
			if !pe.Evaluate([]byte(subjectID), action, resource, map[string]string{}) {
				http.Error(w, "Forbidden by Zero-Trust Policy", http.StatusForbidden)
				return
			}

			// Inject the verified subject ID into the request context for downstream handlers
			ctx := context.WithValue(r.Context(), SubjectContextKey, subjectID)
			next(w, r.WithContext(ctx))
		}
	}
}
