package identity_provider

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/gddisney/guikit"
	"github.com/gddisney/secure_network"
	"github.com/gddisney/secure_policy"
)

// RegisterRoutes binds all identity, admin, and audit endpoints to the mesh router.
// The main UI portal route is handled in the boilerplate to prevent import cycles.
func RegisterRoutes(r *secure_network.Router, admin *AdminController, audit *AuditController, pe *secure_policy.PolicyEngine, sm *secure_policy.SessionManager) {

	// 1. Audit Ingestion (HTTP)
	// Protected by the PolicyEngine. Only identities with 'write' access to 'audit_logs' can post here.
	r.Mux.HandleFunc("/ingest", EnforcePolicy(pe, sm, "write", "audit_logs")(func(w http.ResponseWriter, req *http.Request) {
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
	// Registers the function on the LocalBus and enforces policy against the hardware CallerID.
	if rpcEngineModule, ok := r.Modules["mesh_rpc"]; ok {
		rpcEngine := rpcEngineModule.(*secure_network.RPCManager)
		rpcEngine.Register("ingest_log", func(ctx secure_network.RPCContext, args []byte) (interface{}, error) {
			
			// Verify the hardware identity (CallerID) has write access to audit logs
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
	// Protected by the PolicyEngine. Only users explicitly granted 'read' to 'audit_logs' can view this.
	r.Mux.HandleFunc("/admin/logs", EnforcePolicy(pe, sm, "read", "audit_logs")(func(w http.ResponseWriter, req *http.Request) {
		c := &guikit.Context{W: w, R: req, Data: make(map[string]interface{})}
		
		audit.logsMu.RLock()
		recent := make([]LogDisplay, len(audit.recentLogs))
		copy(recent, audit.recentLogs)
		audit.logsMu.RUnlock()

		c.Data["Results"] = recent
		
		// Ensure GUIKit exists before attempting to render
		if r.GUIKit != nil {
			r.GUIKit.Render(c, "views/admin_logs")
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("GUI Engine offline"))
		}
	}))

	// 4. Application Registration (Admin API)
	// Protected by the PolicyEngine. Only administrators can add new integrations to the catalog.
	r.Mux.HandleFunc("/admin/apps/register", EnforcePolicy(pe, sm, "write", "app_registry")(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var newApp Application
		if err := json.NewDecoder(req.Body).Decode(&newApp); err != nil {
			http.Error(w, "Invalid application payload", http.StatusBadRequest)
			return
		}

		if err := admin.RegisterApp(newApp); err != nil {
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
			// Actively blacklist the JWT in the database to prevent replay attacks
			sm.RevokeTokenString(cookie.Value)
		}

		// Destroy the session cookie expected by middleware.go
		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   true, // Ensure this matches your TLS setup
			SameSite: http.SameSiteStrictMode,
		})

		// Prevent the browser from caching the authenticated state
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")

		// Redirect to the login page or public root
		http.Redirect(w, req, "/", http.StatusSeeOther)
	})
}
