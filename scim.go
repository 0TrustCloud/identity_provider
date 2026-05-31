package identity_provider

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/0TrustCloud/secure_data_format"
	"github.com/0TrustCloud/logger"
	"github.com/0TrustCloud/secure_network"
	"github.com/0TrustCloud/ultimate_db"
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

// SCIMDaemon handles asynchronous lifecycle management and external provisioning,
// now expanded with SDF for verifiable downstream state compilation.
type SCIMDaemon struct {
	DB       *ultimate_db.DB
	LocalBus chan secure_network.SystemEvent
	Client   *http.Client
	Logger   *logger.LogDispatcher
	SDFEngine *secure_data_format.SecureDataEngine // Integrated SDF compilation engine
}

// NewSCIMDaemon initializes the SCIM background worker with the attached SDF engine
func NewSCIMDaemon(db *ultimate_db.DB, bus chan secure_network.SystemEvent, sysLog *logger.LogDispatcher, sdf *secure_data_format.SecureDataEngine) *SCIMDaemon {
	return &SCIMDaemon{
		DB:        db,
		LocalBus:  bus,
		Client:    &http.Client{Timeout: 10 * time.Second},
		Logger:    sysLog,
		SDFEngine: sdf,
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
// and compiles a verifiable audit log token upon successful external state modification.
func (s *SCIMDaemon) handleProvision(payload []byte) {
	var data struct {
		AppID    string   `json:"app_id"`
		Identity Identity `json:"identity"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		if s.Logger != nil { 
			s.Logger.Error("Malformed SCIM provision event payload") 
		}
		return
	}

	txn := s.DB.BeginTxn()
	appData, err := s.DB.Read(AppRegistryPageID, txn, []byte(data.AppID))
	s.DB.CommitTxn(txn)

	if err != nil || appData == nil {
		return
	}

	var app Application
	_ = json.Unmarshal(appData, &app)

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

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		if s.Logger != nil {
			s.Logger.Error(fmt.Sprintf("Downstream SCIM endpoint returned unexpected status code: %d", resp.StatusCode))
		}
		return
	}

	// --------------------------------------------------
	// SDF ASYNCHRONOUS TRANSACTION COMPILATION
	// --------------------------------------------------
	// Constructs a programmatic log execution script mapping strictly to the engine parser
	var tokenStr string
	if s.SDFEngine != nil {
		script := fmt.Sprintf(`
			log:scim.provision#%s(
				subject("%s")
				username("%s")
				status("PROVISIONED")
				endpoint("%s")
			)
		`, app.ID, data.Identity.Subject, scimUser.UserName, app.SCIMEndpoint)

		tx := secure_data_format.DataInvocation{
			TargetAddress: fmt.Sprintf("mesh:scim:receipt:%s:%s", app.ID, data.Identity.Subject),
			Caller:        "system_scim_daemon",
			Nonce:         uint64(time.Now().UnixNano()),
			Method:        "EMIT", // Formally targets the logging verification profile
			Profile:       secure_data_format.ProfileStructuredLog, // Long-term archival window ceiling
			Args: map[string]interface{}{
				"app_id":      app.ID,
				"app_name":    app.Name,
				"subject":     data.Identity.Subject,
				"status_code": resp.StatusCode,
			},
		}

		var compileErr error
		tokenStr, compileErr = s.SDFEngine.CompileSecureData(script, tx)
		if compileErr != nil && s.Logger != nil {
			s.Logger.Error("SCIM daemon failed to compile structural provenance token: " + compileErr.Error())
		}
	}

	if s.Logger != nil {
		var tokenLogMsg string
		if len(tokenStr) > 15 {
			tokenLogMsg = " [Receipt Hash: " + tokenStr[len(tokenStr)-15:] + "]"
		}
		s.Logger.Audit("system_scim_daemon", "REMOTE_PROVISION", "Provisioned "+data.Identity.Subject+" in "+app.Name+tokenLogMsg)
	}
}
