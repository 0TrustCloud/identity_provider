package identity_provider

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/gddisney/guikit"
	"github.com/gddisney/logger"
	"github.com/gddisney/secure_network"
	"github.com/gddisney/secure_policy"
)

// Global safeguard to ensure routes are only ever mounted once onto the ServeMux.
var mountOnce sync.Once

// RegisterRoutes binds all identity, admin, and audit endpoints to the mesh router.
// It now requires the logger.RPCLogger to satisfy the updated middleware requirements.
func RegisterRoutes(r *secure_network.Router, admin *AdminController, audit *AuditController, pe *secure_policy.PolicyEngine, sm *secure_policy.SessionManager, sysLog *logger.RPCLogger) {

	mountOnce.Do(func() {

		// 1. Audit Ingestion (HTTP)
		// Signature: EnforcePolicy(pe, sm, sysLog, action, resource)
		r.Mux.HandleFunc("/ingest", EnforcePolicy(pe, sm, sysLog, "write", "audit_logs")(func(w http.ResponseWriter, req *http.Request) {
			if req.Method != http.MethodPost {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}

			payload, err := io.ReadAll(req.Body)
			if err != nil {
				http.Error(w, "Bad request", http.StatusBadRequest)
				return
			}
			defer req.Body.Close()

			var logData LogPayload
			if err := json.Unmarshal(payload, &logData); err == nil {
				audit.RecordLog(logData.Level, logData.Service, logData.Message)
			}

			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Log ingested successfully"))
		}))

		// 2. Audit Ingestion (RPC over the Mesh Tunnel)
		if rpcEngineModule, ok := r.Modules["mesh_rpc"]; ok {
			rpcEngine := rpcEngineModule.(*secure_network.RPCManager)
			rpcEngine.Register("ingest_log", func(ctx secure_network.RPCContext, args []byte) (interface{}, error) {
				if !pe.Evaluate(ctx.CallerID, "write", "audit_logs", nil) {
					return nil, fmt.Errorf("unauthorized to ingest logs over RPC")
				}

				var logData LogPayload
				if err := json.Unmarshal(args, &logData); err != nil {
					return nil, err
				}

				audit.RecordLog(logData.Level, logData.Service, logData.Message)
				return map[string]string{"status": "success"}, nil
			})
		}

		// 3. System Audit Console (UI)
		r.Mux.HandleFunc("/admin/logs", EnforcePolicy(pe, sm, sysLog, "read", "audit_logs")(func(w http.ResponseWriter, req *http.Request) {
			c := &guikit.Context{W: w, R: req, Data: make(map[string]interface{})}

			audit.logsMu.RLock()
			recent := make([]LogDisplay, len(audit.recentLogs))
			copy(recent, audit.recentLogs)
			audit.logsMu.RUnlock()

			c.Data["Results"] = recent

			if r.GUIKit != nil {
				r.GUIKit.Render(c, "views/admin_logs")
			} else {
				http.Error(w, "GUI Engine offline", http.StatusInternalServerError)
			}
		}))

		// 4. Application Registration (Admin API)
		r.Mux.HandleFunc("/admin/apps/register", EnforcePolicy(pe, sm, sysLog, "write", "app_registry")(func(w http.ResponseWriter, req *http.Request) {
			if req.Method != http.MethodPost {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}

			// Extract actor from context (injected by EnforcePolicy)
			actor, _ := req.Context().Value(SubjectContextKey).(string)
			if actor == "" { actor = "system" }

			var newApp Application
			if err := json.NewDecoder(req.Body).Decode(&newApp); err != nil {
				http.Error(w, "Invalid application payload", http.StatusBadRequest)
				return
			}

			// Pass both app AND actor
			if err := admin.RegisterApp(newApp, actor); err != nil {
				http.Error(w, "Failed to register application", http.StatusInternalServerError)
				return
			}

			w.WriteHeader(http.StatusCreated)
			w.Write([]byte("Application registered successfully"))
		}))

		// 5. Secure Session Logout
		r.Mux.HandleFunc("/logout", func(w http.ResponseWriter, req *http.Request) {
			cookie, err := req.Cookie("session_id")
			if err == nil && cookie.Value != "" {
				sm.RevokeTokenString(cookie.Value)
			}

			http.SetCookie(w, &http.Cookie{
				Name:     "session_id",
				Value:    "",
				Path:     "/",
				MaxAge:   -1,
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteStrictMode,
			})

			http.Redirect(w, req, "/", http.StatusSeeOther)
		})
	})
}
