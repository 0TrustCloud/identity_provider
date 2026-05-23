package identity_provider

import (
	"encoding/json"

	"github.com/gddisney/secure_network"
	"github.com/gddisney/secure_policy"
	"github.com/gddisney/ultimate_db"
)

const AppRegistryPageID = ultimate_db.PageID(4)

type AdminController struct {
	DB           *ultimate_db.DB
	PolicyEngine *secure_policy.PolicyEngine
	LocalBus     chan secure_network.SystemEvent
}

// RegisterApp persists a new application tile to the registry
func (a *AdminController) RegisterApp(app Application) error {
	data, err := json.Marshal(app)
	if err != nil {
		return err
	}
	
	txn := a.DB.BeginTxn()
	defer a.DB.CommitTxn(txn)
	return a.DB.Write(AppRegistryPageID, txn, []byte(app.ID), data, 0)
}

// AssignUserToApp grants access and triggers the SCIM provisioning flow
func (a *AdminController) AssignUserToApp(identity Identity, appID string) error {
	// 1. Enforce intent in the local Policy Engine
	err := a.PolicyEngine.AddPolicy([]byte(identity.Subject), "access", appID, "ALLOW", nil)
	if err != nil {
		return err
	}

	// 2. Emit an event to the secure_network LocalBus for the SCIM Daemon
	eventPayload, _ := json.Marshal(map[string]interface{}{
		"app_id":   appID,
		"identity": identity,
	})

	a.LocalBus <- secure_network.SystemEvent{
		Topic:   "scim_provision",
		Payload: eventPayload,
	}

	return nil
}
