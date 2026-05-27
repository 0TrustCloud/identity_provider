package identity_provider

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gddisney/logger"
	"github.com/gddisney/secure_network"
	"github.com/gddisney/ultimate_db"
)
// SCIMUser represents the standard SCIM 2.0 user schema
type SCIMUser struct {
	Schemas  []string `json:"schemas"`
	UserName string   `json:"userName"`
	Name     struct {
		GivenName  string `json:"givenName"`
		FamilyName string `json:"familyName"`
	} `json:"name"`
	Active bool `json:"active"`
}

// SCIMDaemon handles asynchronous lifecycle management and external provisioning
type SCIMDaemon struct {
	DB       *ultimate_db.DB
	LocalBus chan secure_network.SystemEvent
	Client   *http.Client
	Logger   *logger.LogDispatcher // Upgraded to the new LogDispatcher
}

// NewSCIMDaemon initializes the SCIM background worker
func NewSCIMDaemon(db *ultimate_db.DB, bus chan secure_network.SystemEvent, sysLog *logger.LogDispatcher) *SCIMDaemon {
	return &SCIMDaemon{
		DB:       db,
		LocalBus: bus,
		Client:   &http.Client{Timeout: 10 * time.Second},
		Logger:   sysLog,
	}
}

// Start begins listening to the LocalBus for SCIM provisioning events
func (s *SCIMDaemon) Start() {
	if s.Logger != nil { 
		s.Logger.Info("SCIM background daemon initialized and listening.") 
	}
	for event := range s.LocalBus {
		if event.Topic == "scim_provision" {
			go s.handleProvision(event.Payload)
		}
	}
}

// handleProvision executes the outbound HTTP request to the target application's SCIM endpoint
func (s *SCIMDaemon) handleProvision(payload []byte) {
	var data struct {
		AppID    string   `json:"app_id"`
		Identity Identity `json:"identity"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		if s.Logger != nil { s.Logger.Error("Malformed SCIM provision event payload") }
		return
	}

	txn := s.DB.BeginTxn()
	appData, err := s.DB.Read(AppRegistryPageID, txn, []byte(data.AppID))
	s.DB.CommitTxn(txn)

	if err != nil || appData == nil {
		return
	}

	var app Application
	json.Unmarshal(appData, &app)

	if app.SCIMEndpoint == "" {
		return // SSO only, no SCIM configured for this application
	}

	scimUser := SCIMUser{
		Schemas:  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		UserName: data.Identity.Attributes["email"],
		Active:   true,
	}
	scimUser.Name.GivenName = data.Identity.Attributes["given_name"]
	scimUser.Name.FamilyName = data.Identity.Attributes["family_name"]

	reqBody, _ := json.Marshal(scimUser)
	req, _ := http.NewRequest("POST", app.SCIMEndpoint+"/Users", bytes.NewBuffer(reqBody))
	req.Header.Set("Authorization", "Bearer "+app.SCIMToken)
	req.Header.Set("Content-Type", "application/scim+json")

	resp, err := s.Client.Do(req)
	if err != nil {
		if s.Logger != nil { 
			s.Logger.Error("SCIM Network failure provisioning " + data.Identity.Subject + " to " + app.Name) 
		}
		return
	}
	defer resp.Body.Close()

	if s.Logger != nil {
		s.Logger.Audit("system_scim_daemon", "REMOTE_PROVISION", "Provisioned "+data.Identity.Subject+" in "+app.Name)
	}
}
