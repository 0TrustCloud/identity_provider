package identity_provider

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/gddisney/secure_network"
	"github.com/gddisney/ultimate_db"
)

type SCIMUser struct {
	Schemas  []string `json:"schemas"`
	UserName string   `json:"userName"`
	Name     struct {
		GivenName  string `json:"givenName"`
		FamilyName string `json:"familyName"`
	} `json:"name"`
	Active bool `json:"active"`
}

type SCIMDaemon struct {
	DB       *ultimate_db.DB
	LocalBus chan secure_network.SystemEvent
	Client   *http.Client
}

func NewSCIMDaemon(db *ultimate_db.DB, bus chan secure_network.SystemEvent) *SCIMDaemon {
	return &SCIMDaemon{
		DB:       db,
		LocalBus: bus,
		Client:   &http.Client{Timeout: 10 * time.Second},
	}
}

func (s *SCIMDaemon) Start() {
	log.Println("[SCIM] Daemon online, listening for lifecycle events...")
	for event := range s.LocalBus {
		if event.Topic == "scim_provision" {
			go s.handleProvision(event.Payload)
		}
	}
}

func (s *SCIMDaemon) handleProvision(payload []byte) {
	var data struct {
		AppID    string   `json:"app_id"`
		Identity Identity `json:"identity"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		log.Printf("[SCIM] Malformed provision event: %v", err)
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
		return // Application uses SSO only, no SCIM configured
	}

	// Map internal identity to standard SCIM 2.0 User Resource
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
		log.Printf("[SCIM] Provisioning network failure for %s: %v", data.Identity.Subject, err)
		return
	}
	defer resp.Body.Close()

	log.Printf("[SCIM] Provisioned %s in %s. Remote Status: %d", data.Identity.Subject, app.Name, resp.StatusCode)
}
