package identity_provider

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"

	"github.com/gddisney/guikit"
	"github.com/gddisney/logger"
	"github.com/gddisney/secure_network"
	"github.com/gddisney/secure_policy"
	"gopkg.in/yaml.v3"
)

// RouteConfig maps YAML entries to router endpoints
type RouteConfig struct {
	Pattern  string `yaml:"pattern"`
	Method   string `yaml:"method"`
	Action   string `yaml:"action"`
	Resource string `yaml:"resource"`
	Handler  string `yaml:"handler"`
}

type Config struct {
	Routes []RouteConfig `yaml:"routes"`
}

// IngestPayload defines the expected JSON structure for external logs
type IngestPayload struct {
	Actor   string `json:"actor"`
	Level   string `json:"level"`
	Service string `json:"service"`
	Message string `json:"message"`
}

var mountOnce sync.Once

// RegisterRoutes binds identity, admin, and audit endpoints dynamically.
func RegisterRoutes(r *secure_network.Router, admin *AdminController, audit *AuditController, pe *secure_policy.PolicyEngine, sm *secure_policy.SessionManager, Logger *logger.LogDispatcher, configPath string) {
	mountOnce.Do(func() {
		// 1. Load Dynamic Config
		cfgData, err := os.ReadFile(configPath)
		if err != nil {
			if Logger != nil { Logger.Error("Failed to load routes.yaml: " + err.Error()) }
			return
		}
		var cfg Config
		if err := yaml.Unmarshal(cfgData, &cfg); err != nil {
			if Logger != nil { Logger.Error("Failed to parse routes.yaml: " + err.Error()) }
			return
		}

		// 2. Define Handler Registry
		registry := map[string]http.HandlerFunc{
			
			// HTTP Log Ingest: Routes external logs through the central Pub/Sub dispatcher
			"ingest_handler": func(w http.ResponseWriter, req *http.Request) {
				payload, _ := io.ReadAll(req.Body)
				var logData IngestPayload
				if err := json.Unmarshal(payload, &logData); err == nil {
					if Logger != nil {
						if logData.Level == "AUDIT" {
							Logger.Audit(logData.Actor, "EXTERNAL_INGEST", logData.Message)
						} else if logData.Level == "ERROR" {
							Logger.Error(fmt.Sprintf("[%s] %s", logData.Service, logData.Message))
						} else {
							Logger.Info(fmt.Sprintf("[%s] %s", logData.Service, logData.Message))
						}
					}
				}
				w.WriteHeader(http.StatusOK)
			},
			
			// Admin Logs UI: Serves the real-time ring buffer from the AuditController
			"admin_logs_handler": func(w http.ResponseWriter, req *http.Request) {
				c := &guikit.Context{W: w, R: req, Data: make(map[string]interface{})}
				audit.logsMu.RLock()
				recent := make([]LogDisplay, len(audit.recentLogs))
				copy(recent, audit.recentLogs)
				audit.logsMu.RUnlock()
				
				c.Data["Results"] = recent
				r.GUIKit.Render(c, "views/admin_logs")
			},
			
			// App Registration: Deploys a new SCIM integration
			"register_app_handler": func(w http.ResponseWriter, req *http.Request) {
				actor, _ := req.Context().Value(SubjectContextKey).(string)
				var newApp Application
				if err := json.NewDecoder(req.Body).Decode(&newApp); err != nil {
					http.Error(w, "Invalid payload format", http.StatusBadRequest)
					return
				}
				if err := admin.RegisterApp(newApp, actor); err != nil {
					http.Error(w, "Failed to register application", http.StatusInternalServerError)
					return
				}
				w.WriteHeader(http.StatusCreated)
			},
			
			// Logout: Revokes the hardware-bound session token
			"logout_handler": func(w http.ResponseWriter, req *http.Request) {
				cookie, err := req.Cookie("session_id")
				if err == nil && cookie.Value != "" {
					sm.RevokeTokenString(cookie.Value)
					if Logger != nil {
						Logger.Info("Session revoked for token: " + cookie.Value[:10] + "...")
					}
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
			},
		}

		// 3. Register HTTP routes dynamically
		for _, route := range cfg.Routes {
			handler, ok := registry[route.Handler]
			if !ok {
				if Logger != nil { Logger.Error("Handler not found in registry: " + route.Handler) }
				continue
			}

			// Apply EnforcePolicy middleware only if action/resource are defined in YAML
			var finalHandler http.HandlerFunc
			if route.Action != "NONE" {
				finalHandler = EnforcePolicy(pe, sm, Logger, route.Action, route.Resource)(func(w http.ResponseWriter, req *http.Request) {
					if route.Method != "" && req.Method != route.Method {
						http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
						return
					}
					handler(w, req)
				})
			} else {
				finalHandler = handler
			}
			r.Mux.HandleFunc(route.Pattern, finalHandler)
		}

		// 4. RPC registration for Mesh-native log ingest
		if rpcEngineModule, ok := r.Modules["mesh_rpc"]; ok {
			rpcEngine := rpcEngineModule.(*secure_network.RPCManager)
			rpcEngine.Register("ingest_log", func(ctx secure_network.RPCContext, args []byte) (interface{}, error) {
				
				// Enforce Zero-Trust write policy over RPC
				if !pe.Evaluate(ctx.CallerID, "write", "audit_logs", nil) {
					if Logger != nil {
						Logger.Audit(fmt.Sprintf("%x", ctx.CallerID[:8]), "RPC_DENIED", "Unauthorized attempt to ingest log over mesh")
					}
					return nil, fmt.Errorf("unauthorized")
				}
				
				var logData IngestPayload
				json.Unmarshal(args, &logData)
				
				// Route through the central dispatcher
				if Logger != nil {
					callerHex := fmt.Sprintf("%x", ctx.CallerID[:8])
					if logData.Level == "AUDIT" {
						Logger.Audit(callerHex, "RPC_INGEST", logData.Message)
					} else if logData.Level == "ERROR" {
						Logger.Error(fmt.Sprintf("[%s] RPC Error from %s: %s", logData.Service, callerHex, logData.Message))
					} else {
						Logger.Info(fmt.Sprintf("[%s] RPC Log from %s: %s", logData.Service, callerHex, logData.Message))
					}
				}
				
				return map[string]string{"status": "success"}, nil
			})
		}
	})
}
