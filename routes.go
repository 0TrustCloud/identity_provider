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

// RegisterRoutes binds admin and audit endpoints to the mesh router.
// Note: The main UI portal route has been moved to the boilerplate to prevent import cycles.
func RegisterRoutes(r *secure_network.Router, admin *AdminController, audit *AuditController, pe *secure_policy.PolicyEngine) {

	// 1. Audit Ingestion (HTTP)
	r.Mux.HandleFunc("/ingest", EnforcePolicy(pe, "write", "audit_logs")(func(w http.ResponseWriter, req *http.Request) {
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
	r.Mux.HandleFunc("/admin/logs", EnforcePolicy(pe, "read", "audit_logs")(func(w http.ResponseWriter, req *http.Request) {
		c := &guikit.Context{W: w, R: req, Data: make(map[string]interface{})}
		
		audit.logsMu.RLock()
		recent := make([]LogDisplay, len(audit.recentLogs))
		copy(recent, audit.recentLogs)
		audit.logsMu.RUnlock()

		c.Data["Results"] = recent
		
		if r.GUIKit != nil {
			r.GUIKit.Render(c, "views/admin_logs")
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("GUI Engine offline"))
		}
	}))

	// 4. Application Registration (Admin API)
	r.Mux.HandleFunc("/admin/apps/register", EnforcePolicy(pe, "write", "app_registry")(func(w http.ResponseWriter, req *http.Request) {
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

	// 5. Session Logout
	r.Mux.HandleFunc("/logout", func(w http.ResponseWriter, req *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   true,
		})

		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")

		http.Redirect(w, req, "/", http.StatusSeeOther)
	})
}
