package identity_provider

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/gddisney/guikit"
	"github.com/gddisney/secure_bootstrap"
	"github.com/gddisney/secure_network"
	"github.com/gddisney/secure_policy"
)

// RegisterRoutes binds all identity, admin, and audit endpoints to the mesh router.
func RegisterRoutes(r *secure_network.Router, admin *AdminController, audit *AuditController, pe *secure_policy.PolicyEngine) {

	// 1. The Main Identity Portal (App Catalog Dashboard)
	// Protected by secure_bootstrap.RequireAuth to ensure a valid session exists.
	r.Mux.HandleFunc("/", secure_bootstrap.RequireAuth(r, func(c *guikit.Context) {
		// In a full implementation, this queries AppRegistryPageID to show authorized apps
		c.Data["Title"] = "Identity Portal"
		r.GUIKit.Render(c, "views/portal")
	}))

	// 2. Audit Ingestion (HTTP)
	// Protected by the PolicyEngine. Only identities with 'write' access to 'audit_logs' can post here.
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

	// 3. Audit Ingestion (RPC over the Mesh Tunnel)
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

	// 4. System Audit Console (UI)
	// Protected by the PolicyEngine. Only users explicitly granted 'read' to 'audit_logs' can view this.
	r.Mux.HandleFunc("/admin/logs", EnforcePolicy(pe, "read", "audit_logs")(func(w http.ResponseWriter, req *http.Request) {
		c := &guikit.Context{W: w, R: req, Data: make(map[string]interface{})}
		
		audit.logsMu.RLock()
		recent := make([]LogDisplay, len(audit.recentLogs))
		copy(recent, audit.recentLogs)
		audit.logsMu.RUnlock()

		c.Data["Results"] = recent
		r.GUIKit.Render(c, "views/admin_logs")
	}))

	// 5. Application Registration (Admin API)
	// Protected by the PolicyEngine. Only administrators can add new integrations to the catalog.
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
}
