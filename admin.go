package identity_provider

import (
	"encoding/json"

	"github.com/gddisney/logger"
	"github.com/gddisney/secure_network"
	"github.com/gddisney/secure_policy"
	"github.com/gddisney/ultimate_db"
)

const AppRegistryPageID = ultimate_db.PageID(4)
type RPCLogger = LogDispatcher
type AdminController struct {
	DB           *ultimate_db.DB
	PolicyEngine *secure_policy.PolicyEngine
	LocalBus     chan secure_network.SystemEvent
	Logger       *logger.LogDispatcher // Upgraded to the new Pub/Sub Dispatcher
}

// RegisterApp persists a new application tile to the registry
func (a *AdminController) RegisterApp(app Application, actor string) error {
	data, err := json.Marshal(app)
	if err != nil {
		if a.Logger != nil { 
			a.Logger.Error("Failed to marshal application payload: " + err.Error()) 
		}
		return err
	}
	
	txn := a.DB.BeginTxn()
	err = a.DB.Write(AppRegistryPageID, txn, []byte(app.ID), data, 0)
	a.DB.CommitTxn(txn)

	if err == nil && a.Logger != nil {
		a.Logger.Audit(actor, "DEPLOY_SERVICE", "Successfully registered new application: "+app.ID)
	}

	return err
}

// AssignUserToApp grants access and triggers the SCIM provisioning flow
func (a *AdminController) AssignUserToApp(identity Identity, appID string, actor string) error {
	err := a.PolicyEngine.AddPolicy([]byte(identity.Subject), "access", appID, "ALLOW", nil)
	if err != nil {
		if a.Logger != nil { 
			a.Logger.Error("Policy engine failed to assign user: " + err.Error()) 
		}
		return err
	}

	eventPayload, _ := json.Marshal(map[string]interface{}{
		"app_id":   appID,
		"identity": identity,
	})

	a.LocalBus <- secure_network.SystemEvent{
		Topic:   "scim_provision",
		Payload: eventPayload,
	}

	if a.Logger != nil {
		a.Logger.Audit(actor, "GRANT_ACCESS", "Assigned user "+identity.Subject+" to integration "+appID)
	}

	return nil
}
