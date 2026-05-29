package identity_provider

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/gddisney/guikit"
	"github.com/gddisney/logger"
	"github.com/gddisney/secure_network"
	"github.com/gddisney/secure_policy"
	"gopkg.in/yaml.v3"
)

// RouteConfig maps YAML entries to router endpoints [cite: 1]
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

// IngestPayload defines the expected JSON structure for external logs [cite: 1]
type IngestPayload struct {
	Actor   string `json:"actor"`
	Level   string `json:"level"`
	Service string `json:"service"`
	Message string `json:"message"`
}

var mountOnce sync.Once

// RegisterRoutes binds identity, admin, and audit endpoints dynamically. [cite: 1]
func RegisterRoutes(r *secure_network.Router, admin *AdminController, audit *AuditController, pe *secure_policy.PolicyEngine, sm *secure_policy.SessionManager, Logger *logger.LogDispatcher, configPath string) {
	mountOnce.Do(func() {
		// 1. Load Dynamic Config [cite: 1]
		cfgData, err := os.ReadFile(configPath)
		if err != nil {
			if Logger != nil {
				Logger.Error("Failed to load routes.yaml: " + err.Error())
			}
			return
		}
		var cfg Config
		if err := yaml.Unmarshal(cfgData, &cfg); err != nil {
			if Logger != nil {
				Logger.Error("Failed to parse routes.yaml: " + err.Error())
			}
			return
		}

		// 2. Define Handler Registry [cite: 1]
		registry := map[string]http.HandlerFunc{

			// HTTP Log Ingest: Routes external logs through the central Pub/Sub dispatcher [cite: 1]
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

			// Admin Logs UI: Serves the real-time ring buffer from the AuditController [cite: 1]
			"admin_logs_handler": func(w http.ResponseWriter, req *http.Request) {
				c := &guikit.Context{W: w, R: req, Data: make(map[string]interface{})}
				audit.logsMu.RLock()
				recent := make([]LogDisplay, len(audit.recentLogs))
				copy(recent, audit.recentLogs)
				audit.logsMu.RUnlock()

				c.Data["Results"] = recent
				r.GUIKit.Render(c, "views/admin_logs")
			},

			// App Registration: Deploys a new SCIM integration via raw JSON endpoint [cite: 1]
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

			// WIZARD API: Form handler destination for Application Registration [cite: 2]
			"wizard_register_app_handler": func(w http.ResponseWriter, req *http.Request) {
				_ = req.ParseForm()
				
				// FIX: Safely parse token prefix errors out of context keys [cite: 2]
				actor, _ := req.Context().Value(SubjectContextKey).(string)
				if actor == "" || strings.HasPrefix(actor, "eyJ") {
					if cookie, err := req.Cookie("session_id"); err == nil {
						cleanTkn := strings.TrimPrefix(cookie.Value, "user_session_")
						if parsedSub, err := sm.ValidateCookieToken(cleanTkn); err == nil {
							actor = parsedSub
						}
					}
				}
				if actor == "" {
					actor = "admin"
				}

				app := Application{
					ID:             req.FormValue("app_id"),
					Name:           req.FormValue("name"),
					TargetURL:      req.FormValue("target_url"),
					AuthProtocol:   req.FormValue("auth_protocol"),
					RequiredPolicy: "enforce",
					SCIMEndpoint:   req.FormValue("scim_endpoint"),
					SCIMToken:      req.FormValue("scim_token"),
				}

				if app.ID == "" || app.Name == "" {
					http.Error(w, "Bad Request: Missing application parameter attributes", http.StatusBadRequest)
					return
				}

				if err := admin.RegisterApp(app, actor); err != nil {
					http.Error(w, "Database write failure: "+err.Error(), http.StatusInternalServerError)
					return
				}

				http.Redirect(w, req, "/admin/identity", http.StatusFound)
			},

			// WIZARD API: Core Account & SCIM Provisioning Form Handler [cite: 2]
			"wizard_provision_user_handler": func(w http.ResponseWriter, req *http.Request) {
				_ = req.ParseForm()
				
				// FIX: Clean subject tracking extraction pass [cite: 2]
				actor, _ := req.Context().Value(SubjectContextKey).(string)
				if actor == "" || strings.HasPrefix(actor, "eyJ") {
					if cookie, err := req.Cookie("session_id"); err == nil {
						cleanTkn := strings.TrimPrefix(cookie.Value, "user_session_")
						if parsedSub, err := sm.ValidateCookieToken(cleanTkn); err == nil {
							actor = parsedSub
						}
					}
				}
				if actor == "" {
					actor = "admin"
				}

				identity := Identity{
					Subject:       req.FormValue("subject"),
					Type:          IdentityHuman,
					HardwareBound: true,
					Attributes: map[string]string{
						"email":       req.FormValue("email"),
						"given_name":  req.FormValue("given_name"),
						"family_name": req.FormValue("family_name"),
					},
				}

				appID := req.FormValue("app_id")
				if identity.Subject == "" || appID == "" {
					http.Error(w, "Bad Request: Missing assignment criteria parameters", http.StatusBadRequest)
					return
				}

				if err := admin.AssignUserToApp(identity, appID, actor); err != nil {
					http.Error(w, "Provisioning orchestration failed: "+err.Error(), http.StatusInternalServerError)
					return
				}

				http.Redirect(w, req, "/admin/scim/create", http.StatusFound)
			},

			// WIZARD API: Form Handler endpoint for the Policy Generator [cite: 2]
			"wizard_commit_policy_handler": func(w http.ResponseWriter, req *http.Request) {
				_ = req.ParseForm()
				
				actor, _ := req.Context().Value(SubjectContextKey).(string)
				if actor == "" || strings.HasPrefix(actor, "eyJ") {
					if cookie, err := req.Cookie("session_id"); err == nil {
						cleanTkn := strings.TrimPrefix(cookie.Value, "user_session_")
						if parsedSub, err := sm.ValidateCookieToken(cleanTkn); err == nil {
							actor = parsedSub
						}
					}
				}
				if actor == "" {
					actor = "admin"
				}

				targetSubject := req.FormValue("policy_subject")
				actionScope := req.FormValue("policy_action")
				resourceDomain := req.FormValue("policy_resource")

				if targetSubject == "" || actionScope == "" || resourceDomain == "" {
					http.Error(w, "Bad Request: Missing required policy definition options", http.StatusBadRequest)
					return
				}

				err := pe.GrantPermission([]byte(targetSubject), actionScope)
				if err != nil {
					http.Error(w, "Policy engine update failure: "+err.Error(), http.StatusInternalServerError)
					return
				}

				if Logger != nil {
					Logger.Log("AUDIT", "POLICY_WIZARD", fmt.Sprintf("Operator '%s' granted action '%s' on resource '%s' to subject '%s'", actor, actionScope, resourceDomain, targetSubject))
				}

				http.Redirect(w, req, "/admin/scim/create", http.StatusFound)
			},

			// Logout: Revokes the hardware-bound session token [cite: 1]
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

		// 3. Register HTTP routes dynamically [cite: 1]
		for _, route := range cfg.Routes {
			handler, ok := registry[route.Handler]
			if !ok {
				if Logger != nil {
					Logger.Error("Handler not found in registry: " + route.Handler)
				}
				continue
			}

			// Apply EnforcePolicy middleware only if action/resource are defined in YAML [cite: 1]
			var finalHandler http.HandlerFunc
			if route.Action != "NONE" && route.Action != "" {
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
	})
}
