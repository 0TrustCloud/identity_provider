package identity_provider

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/0TrustCloud/secure_data_format"
	"github.com/0TrustCloud/logger"
	"github.com/0TrustCloud/secure_policy"
)

type contextKey string

// Unexported keys prevent cross-package collision and type dropping
const (
	subjectContextKey  contextKey = "subject_id"
	sdfTokenContextKey contextKey = "sdf_grant_token"
)

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

// WithSDFGrant safely injects the compiled SDF token into the context
func WithSDFGrant(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, sdfTokenContextKey, token)
}

// GetSDFGrant safely extracts the compiled SDF token from the context
func GetSDFGrant(ctx context.Context) string {
	if token, ok := ctx.Value(sdfTokenContextKey).(string); ok {
		return token
	}
	return ""
}

// EnforcePolicy intercepts incoming requests, validates the cryptographic session,
// evaluates the Zero-Trust policy, synthesizes a programmatic access grant via SDF,
// and logs the resulting state transition to the dispatcher.
func EnforcePolicy(pe *secure_policy.PolicyEngine, sm *secure_policy.SessionManager, sdf *secure_data_format.SecureDataEngine, sysLog *logger.LogDispatcher, action, resource string) func(http.HandlerFunc) http.HandlerFunc {
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
			// Compiles a critical Proof-Of-Possession bypass token to avoid state logouts.
			if cleanSubject == "admin" {
				if sysLog != nil {
					sysLog.Info(fmt.Sprintf("ZTP God-Mode: Automatic access granted to admin for %s", r.URL.Path))
				}

				ctx := WithSubject(r.Context(), cleanSubject)

				if sdf != nil {
					script := fmt.Sprintf(`
						grant:god_mode.bypass#admin(
							action("%s")
							resource("%s")
							path("%s")
						)
					`, action, resource, r.URL.Path)

					tx := secure_data_format.DataInvocation{
						TargetAddress: fmt.Sprintf("mesh:bypass:godmode:%s", resource),
						Caller:        "admin",
						Nonce:         uint64(time.Now().UnixNano()),
						Method:        "ASSERT", // Semantic verification match
						Profile:       secure_data_format.ProfileProofOfPoss, // Ephemeral validity ceiling
						Args: map[string]interface{}{
							"action":   action,
							"resource": resource,
							"path":     r.URL.Path,
						},
					}

					if token, err := sdf.CompileSecureData(script, tx); err == nil {
						r.Header.Set("X-Mesh-SDF-Token", token)
						ctx = WithSDFGrant(ctx, token)
					}
				}

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

			// --------------------------------------------------
			// 5. SDF POLYMORPHIC TRANSITION TOKEN SYNTHESIS
			// --------------------------------------------------
			// Compiles an isolated short-lived grant mapping directly to your parser schema.
			var sdfToken string
			if sdf != nil {
				script := fmt.Sprintf(`
					grant:mesh.authorize#%s(
						action("%s")
						resource("%s")
						verified_edge("true")
					)
				`, cleanSubject, action, resource)

				tx := secure_data_format.DataInvocation{
					TargetAddress: fmt.Sprintf("mesh:auth:grant:%s", resource),
					Caller:        cleanSubject,
					Nonce:         uint64(time.Now().UnixNano()),
					Method:        "DELEGATE",
					Profile:       secure_data_format.ProfileGrant, // Standard structural grant window
					Args: map[string]interface{}{
						"action":   action,
						"resource": resource,
						"path":     r.URL.Path,
					},
				}

				var compileErr error
				sdfToken, compileErr = sdf.CompileSecureData(script, tx)
				if compileErr != nil {
					if sysLog != nil {
						sysLog.Error("SDF cryptographic token synthesis failure inside middleware transit: " + compileErr.Error())
					}
					http.Error(w, "Internal Security Serialization Error", http.StatusInternalServerError)
					return
				}
				r.Header.Set("X-Mesh-SDF-Token", sdfToken)
			}

			if sysLog != nil {
				sysLog.Info("Access granted to " + cleanSubject + " for " + r.URL.Path)
			}

			ctx := WithSubject(r.Context(), cleanSubject)
			if sdfToken != "" {
				ctx = WithSDFGrant(ctx, sdfToken)
			}
			next(w, r.WithContext(ctx))
		}
	}
}
