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

type IngestPayload struct {
	Actor   string `json:"actor"`
	Level   string `json:"level"`
	Service string `json:"service"`
	Message string `json:"message"`
}

var mountOnce sync.Once

func RegisterRoutes(r *secure_network.Router, admin *AdminController, audit *AuditController, pe *secure_policy.PolicyEngine, sm *secure_policy.SessionManager, Logger *logger.LogDispatcher, configPath string) {
	mountOnce.Do(func() {
		cfgData, err := os.ReadFile(configPath)
		if err != nil { return }
		var cfg Config
		if err := yaml.Unmarshal(cfgData, &cfg); err != nil { return }

		registry := map[string]http.HandlerFunc{
			"ingest_handler": func(w http.ResponseWriter, req *http.Request) {
				payload, _ := io.ReadAll(req.Body)
				var logData IngestPayload
				if err := json.Unmarshal(payload, &logData); err == nil && Logger != nil {
					if logData.Level == "AUDIT" { Logger.Audit(logData.Actor, "EXTERNAL_INGEST", logData.Message)
					} else if logData.Level == "ERROR" { Logger.Error(fmt.Sprintf("[%s] %s", logData.Service, logData.Message))
					} else { Logger.Info(fmt.Sprintf("[%s] %s", logData.Service, logData.Message)) }
				}
				w.WriteHeader(http.StatusOK)
			},

			"admin_logs_handler": func(w http.ResponseWriter, req *http.Request) {
				c := &guikit.Context{W: w, R: req, Data: make(map[string]interface{})}
				audit.logsMu.RLock()
				recent := make([]LogDisplay, len(audit.recentLogs))
				copy(recent, audit.recentLogs)
				audit.logsMu.RUnlock()

				c.Data["Results"] = recent
				r.GUIKit.Render(c, "views/admin_logs")
			},

			"wizard_register_app_handler": func(w http.ResponseWriter, req *http.Request) {
				_ = req.ParseForm()
				actor := GetSubject(req.Context())
				if actor == "" { actor = "admin" }

				app := Application{
					ID: req.FormValue("app_id"), Name: req.FormValue("name"), TargetURL: req.FormValue("target_url"),
					AuthProtocol: req.FormValue("auth_protocol"), RequiredPolicy: "enforce", SCIMEndpoint: req.FormValue("scim_endpoint"), SCIMToken: req.FormValue("scim_token"),
				}
				if app.ID != "" && app.Name != "" { _ = admin.RegisterApp(app, actor) }
				http.Redirect(w, req, "/admin/identity", http.StatusFound)
			},

			"wizard_provision_user_handler": func(w http.ResponseWriter, req *http.Request) {
				_ = req.ParseForm()
				actor := GetSubject(req.Context())
				if actor == "" { actor = "admin" }

				identity := Identity{
					Subject: req.FormValue("subject"), Type: IdentityHuman, HardwareBound: true,
					Attributes: map[string]string{ "email": req.FormValue("email"), "given_name": req.FormValue("given_name"), "family_name": req.FormValue("family_name") },
				}

				appID := req.FormValue("app_id")
				if identity.Subject != "" && appID != "" { _ = admin.AssignUserToApp(identity, appID, actor) }
				http.Redirect(w, req, "/admin/scim/create", http.StatusFound)
			},

			"wizard_commit_policy_handler": func(w http.ResponseWriter, req *http.Request) {
				_ = req.ParseForm()
				actor := GetSubject(req.Context())
				if actor == "" { actor = "admin" }

				targetSubject := req.FormValue("policy_subject")
				actionScope := req.FormValue("policy_action")
				resourceDomain := req.FormValue("policy_resource")

				if targetSubject != "" && actionScope != "" && resourceDomain != "" {
					_ = pe.AddPolicy([]byte(targetSubject), actionScope, resourceDomain, "ALLOW", nil)
					if Logger != nil { Logger.Log("AUDIT", "POLICY_WIZARD", fmt.Sprintf("Operator '%s' granted action '%s' on resource '%s' to subject '%s'", actor, actionScope, resourceDomain, targetSubject)) }
				}
				http.Redirect(w, req, "/admin/scim/create", http.StatusFound)
			},

			"logout_handler": func(w http.ResponseWriter, req *http.Request) {
				cookie, err := req.Cookie("session_id")
				if err == nil && cookie.Value != "" { sm.RevokeTokenString(cookie.Value) }
				http.SetCookie(w, &http.Cookie{Name: "session_id", Value: "", Path: "/", MaxAge: -1})
				http.Redirect(w, req, "/", http.StatusSeeOther)
			},
		}

		for _, rCfg := range cfg.Routes {
			// Pin the loop variable to prevent closure overwrites
			route := rCfg 
			handler, ok := registry[route.Handler]
			if !ok { continue }

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
