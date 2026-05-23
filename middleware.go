package identity_provider

import (
	"net/http"
	"strings"

	"github.com/gddisney/secure_policy"
)

// EnforcePolicy intercepts incoming requests and evaluates the action against the PolicyEngine
func EnforcePolicy(pe *secure_policy.PolicyEngine, action, resource string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("session_id")
			if err != nil || cookie.Value == "" {
				http.Error(w, "Authentication Required", http.StatusUnauthorized)
				return
			}

			// Extract the subject from the session
			subject := strings.TrimPrefix(cookie.Value, "user_session_")

			// Evaluate ABAC/PBAC rules. If this is a machine identity, the context
			// would be populated with the mTLS or Noise static public key attributes.
			if !pe.Evaluate([]byte(subject), action, resource, map[string]string{}) {
				http.Error(w, "Forbidden by Zero-Trust Policy", http.StatusForbidden)
				return
			}

			next(w, r)
		}
	}
}
